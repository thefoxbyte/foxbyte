// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/httpx"
)

// Console queries reuse connections. Each one used to log in afresh, a SCRAM
// exchange and a few round trips of settings before the query itself, and the
// console topped out at about 90 queries a second.
//
// Who a session is must not leak from one request to the next, so:
//
//   - A pool belongs to one branch, one address and one login: the role and
//     its password. A connection made for one user's role is only ever handed
//     to that same role again; nobody is ever given a session of another's.
//   - What a request sets on its session (bb.actor, the guardrail overrides,
//     and anything its own SQL SET, including SET ROLE) is taken off before the
//     connection goes back: DISCARD ALL returns the session to how it was at
//     login, and pgx forgets its prepared statements to match. A connection
//     whose reset fails, or that is left in a transaction, is closed instead.
//   - Idle connections close after 30 seconds, and a branch's pools close when
//     it is suspended or deleted here, so a pool does not keep a branch awake.
//
// FOX_CONSOLE_POOL_SIZE is the most connections a pool holds (4); 0 or "off"
// turns pooling off, so every query logs in afresh as before.

// DefaultConsoleStatementTimeout is how long one console query may run on the
// server (FOX_CONSOLE_STATEMENT_TIMEOUT). Without it, a query the console had
// stopped waiting for went on running in the database.
const DefaultConsoleStatementTimeout = time.Minute

func consoleStatementTimeout() time.Duration {
	return httpx.EnvDuration("CONSOLE_STATEMENT_TIMEOUT", DefaultConsoleStatementTimeout)
}

func consolePoolSize() int {
	switch strings.ToLower(strings.TrimSpace(brand.Getenv("CONSOLE_POOL_SIZE"))) {
	case "0", "off", "false", "no":
		return 0
	}
	return httpx.EnvInt("CONSOLE_POOL_SIZE", 4)
}

const (
	poolIdleConn   = 30 * time.Second
	poolHealth     = 10 * time.Second
	poolLifetime   = 10 * time.Minute
	poolForgetIdle = 5 * time.Minute // an empty pool unused this long is closed
)

// poolKey is one login on one branch at one address. The password is kept as
// a hash: a changed password is a new login, and so a new pool.
type poolKey struct {
	branch, addr, user string
	password           [32]byte
}

type consolePool struct {
	pool *pgxpool.Pool
	used time.Time
}

var consolePools = struct {
	sync.Mutex
	m map[poolKey]*consolePool
}{m: map[poolKey]*consolePool{}}

func keyFor(branchName string, cfg *pgx.ConnConfig) poolKey {
	return poolKey{branch: branchName, addr: fmt.Sprintf("%s:%d", cfg.Host, cfg.Port), user: cfg.User,
		password: sha256.Sum256([]byte(cfg.Password))}
}

// poolFor is the pool for this login on this branch, made on first use. The
// pool's own config is a copy of cfg, so its every connection logs in as cfg
// does and as nothing else.
func poolFor(branchName string, cfg *pgx.ConnConfig, size int) (*pgxpool.Pool, error) {
	k := keyFor(branchName, cfg)
	consolePools.Lock()
	defer consolePools.Unlock()
	now := time.Now()
	for ok, p := range consolePools.m {
		if ok != k && p.pool.Stat().TotalConns() == 0 && now.Sub(p.used) > poolForgetIdle {
			delete(consolePools.m, ok)
			go p.pool.Close()
		}
	}
	if p, ok := consolePools.m[k]; ok {
		p.used = now
		return p.pool, nil
	}
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, err
	}
	pc.ConnConfig = cfg.Copy()
	pc.MaxConns = int32(size)
	pc.MinConns = 0
	pc.MaxConnIdleTime = poolIdleConn
	pc.HealthCheckPeriod = poolHealth
	pc.MaxConnLifetime = poolLifetime
	pc.AfterRelease = resetSession
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		return nil, err
	}
	consolePools.m[k] = &consolePool{pool: pool, used: now}
	return pool, nil
}

// resetSession returns a released connection to how it was at login, or
// reports false so the pool closes it. pgxpool has already closed one left
// mid-transaction or busy, so this sees only idle sessions.
func resetSession(conn *pgx.Conn) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// DISCARD ALL: RESET ALL (every setting, the role among them, back to its
	// login value), DEALLOCATE ALL, CLOSE ALL, UNLISTEN *, the advisory locks
	// released, temporary tables dropped.
	if _, err := conn.Exec(ctx, "DISCARD ALL"); err != nil {
		return false
	}
	// And pgx's own record of the statements it prepared, which DISCARD ALL
	// has just removed from the server.
	if err := conn.DeallocateAll(ctx); err != nil {
		return false
	}
	return true
}

// closeConsolePools closes every pool for a branch: before it is suspended or
// deleted, so no pooled session holds it open or keeps it from sleeping.
// Closing waits for connections in use, so it runs on its own.
func closeConsolePools(branchName string) {
	consolePools.Lock()
	defer consolePools.Unlock()
	for k, p := range consolePools.m {
		if k.branch == branchName {
			delete(consolePools.m, k)
			go p.pool.Close()
		}
	}
}

// dropConsolePool forgets one login's pool, after its address stopped
// answering.
func dropConsolePool(branchName string, cfg *pgx.ConnConfig) {
	k := keyFor(branchName, cfg)
	consolePools.Lock()
	defer consolePools.Unlock()
	if p, ok := consolePools.m[k]; ok {
		delete(consolePools.m, k)
		go p.pool.Close()
	}
}

// acquireSession is openSession for a console query: a session from the pool
// for this login, prepared with this run's settings, and a release that
// returns it (reset) to the pool. With pooling off it is openSession.
func acquireSession(ctx context.Context, addr string, as queryAs) (*pgx.Conn, func(), error) {
	size := consolePoolSize()
	if size == 0 {
		conn, err := openSession(ctx, addr, as)
		if err != nil {
			return nil, nil, err
		}
		return conn, func() { conn.Close(context.Background()) }, nil
	}
	pc, err := acquirePooled(ctx, addr, as, size)
	if err != nil && as.Branch != "" && isDialFailure(err) {
		// The address may be stale (connectSession says why): route again
		// and try once more.
		branch.ForgetBackends()
		if again, rerr := sessionRoute(as.Branch); rerr == nil && again != addr {
			pc, err = acquirePooled(ctx, again, as, size)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	if err := prepareSession(ctx, pc.Conn(), as); err != nil {
		// Half prepared: never back into the pool.
		pc.Conn().Close(context.Background())
		pc.Release()
		return nil, nil, err
	}
	return pc.Conn(), pc.Release, nil
}

func acquirePooled(ctx context.Context, addr string, as queryAs, size int) (*pgxpool.Conn, error) {
	cfg, err := sessionConfig(addr, as)
	if err != nil {
		return nil, err
	}
	// The server stops a query nobody is waiting for any more. A setting at
	// login, so DISCARD ALL returns a session to it.
	cfg.RuntimeParams["statement_timeout"] = fmt.Sprint(consoleStatementTimeout().Milliseconds())
	pool, err := poolFor(as.Branch, cfg, size)
	if err != nil {
		return nil, err
	}
	pc, err := pool.Acquire(ctx)
	if err != nil {
		if isDialFailure(err) {
			dropConsolePool(as.Branch, cfg)
		}
		return nil, err
	}
	return pc, nil
}
