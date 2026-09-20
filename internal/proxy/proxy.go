// SPDX-License-Identifier: AGPL-3.0-or-later

// Package proxy is the foxbyte serverless front door: a single PostgreSQL
// wire-protocol endpoint that routes each connection to the right branch based
// on the database name in the client's startup message, then pipes the rest of
// the session through transparently.
package proxy

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/foxbyte/foxbyte/internal/brand"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/foxbyte/foxbyte/internal/auth"
	"github.com/foxbyte/foxbyte/internal/branch"
	"github.com/foxbyte/foxbyte/internal/tlsutil"
)

// authStore verifies API keys presented as the connection password. When nil
// (FOX_GATEWAY_NOAUTH), the Gateway accepts any client and still mediates
// the backend login — convenient for trusted/local use.
var authStore *auth.Store

// tlsConfig, when non-nil, lets the Gateway answer SSLRequest with 'S' and wrap
// the client connection in TLS — so clients with sslmode=require connect and the
// API key never crosses the wire in cleartext. Loaded once in Serve.
var tlsConfig *tls.Config

// gatewayNoAuth reports whether the gateway's API-key check is disabled. The
// FOX_GATEWAY_NOAUTH escape hatch is only honored in builds made with
// `-tags insecure`; release builds compile it out (insecureAllowed == false), so
// a full auth bypass can never be flipped on in production by an env var.
func gatewayNoAuth() bool {
	if !insecureAllowed {
		return false
	}
	v := brand.Getenv("GATEWAY_NOAUTH")
	return v == "1" || v == "true"
}

// lastActivity tracks when the proxy last routed a connection to each branch, so
// the reaper can suspend branches that have been idle.
var (
	mu           sync.Mutex
	lastActivity = map[string]time.Time{}
)

func touch(name string) {
	mu.Lock()
	lastActivity[name] = time.Now()
	mu.Unlock()
}

// realDatabase is the actual Postgres database inside every branch. The client's
// requested "database" is the branch NAME (routing key), which we rewrite to
// this before forwarding to the backend.
const realDatabase = "foxbyte"

// scopeAllows reports whether a key may open target: an unscoped key opens any
// branch, a scoped one only the branch it names.
func scopeAllows(scope, target string) bool { return scope == "" || scope == target }

// realUser is the Postgres role the Gateway logs clients in as — a non-superuser
// role, so client sessions obey RLS/GRANTs and cannot bypass the append-only
// ledger. The API key gates the client; this role bounds what they can do.
const realUser = "db_client"

const (
	codeStartup30 = 196608   // protocol 3.0 StartupMessage
	codeSSL       = 80877103 // SSLRequest
	codeGSS       = 80877104 // GSSENCRequest
	codeCancel    = 80877102 // CancelRequest
)

// errHandledCancel signals that readStartup already handled a CancelRequest, so
// handle() should just return without logging or opening a session.
var errHandledCancel = errors.New("cancel request handled")

// cancelTargets maps a backend's key (pid:secret, as the client learned it from
// the backend's BackendKeyData) to the backend address, so a CancelRequest — which
// arrives on a fresh connection carrying only that key — can be forwarded to the
// right branch. Registered when a session starts, removed when it ends.
var (
	cancelMu      sync.Mutex
	cancelTargets = map[string]string{}
)

func cancelKey(pid, secret uint32) string {
	return fmt.Sprintf("%d:%d", pid, secret)
}

func registerCancel(key, addr string) {
	cancelMu.Lock()
	cancelTargets[key] = addr
	cancelMu.Unlock()
}

func deregisterCancel(key string) {
	cancelMu.Lock()
	delete(cancelTargets, key)
	cancelMu.Unlock()
}

// forwardCancel relays a client's CancelRequest to the backend that owns the key.
// body is the CancelRequest packet body: code(4), pid(4), secret(4).
func forwardCancel(body []byte) {
	if len(body) < 12 {
		return
	}
	key := cancelKey(binary.BigEndian.Uint32(body[4:8]), binary.BigEndian.Uint32(body[8:12]))
	cancelMu.Lock()
	addr := cancelTargets[key]
	cancelMu.Unlock()
	if addr == "" {
		return // unknown/expired key
	}
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return
	}
	defer c.Close()
	// A CancelRequest is length(4)=16, code, pid, secret — the same pid/secret.
	pkt := make([]byte, 16)
	binary.BigEndian.PutUint32(pkt[0:], 16)
	binary.BigEndian.PutUint32(pkt[4:], codeCancel)
	copy(pkt[8:], body[4:12])
	_, _ = c.Write(pkt)
}

// relayStartupCaptureKey forwards backend->client messages after authentication
// (ParameterStatus, BackendKeyData, ReadyForQuery), capturing the BackendKeyData
// so a later CancelRequest can be routed, and returns the captured key (or "")
// once ReadyForQuery is seen. After it returns, the session is a raw pipe.
func relayStartupCaptureKey(client, backend net.Conn, addr string) (string, error) {
	var key string
	for {
		typ, body, err := readMsg(backend)
		if err != nil {
			return key, err
		}
		if err := writeMsg(client, typ, body); err != nil {
			return key, err
		}
		switch typ {
		case 'K': // BackendKeyData: pid(4), secret(4)
			if len(body) >= 8 {
				key = cancelKey(binary.BigEndian.Uint32(body[0:4]), binary.BigEndian.Uint32(body[4:8]))
				registerCancel(key, addr)
			}
		case 'Z': // ReadyForQuery — startup complete
			return key, nil
		case 'E': // ErrorResponse during startup
			return key, fmt.Errorf("backend error during startup")
		}
	}
}

// Serve listens on addr (e.g. ":6432") and proxies Postgres connections,
// auto-resuming suspended branches on connect and auto-suspending branches idle
// for longer than idle (0 disables suspension).
func Serve(addr string, idle time.Duration) error {
	if gatewayNoAuth() {
		log.Printf("gateway authentication DISABLED (FOX_GATEWAY_NOAUTH) — trusted/local mode")
	} else {
		store, err := auth.OpenFromEnv()
		if err != nil {
			return fmt.Errorf("open auth store: %w", err)
		}
		authStore = store
		log.Printf("gateway authentication ENABLED — connect with an API key (key_…) as the password")
	}
	if cfg, err := tlsutil.ServerConfig(); err != nil {
		log.Printf("TLS disabled (could not load certificate): %v — clients must use sslmode=disable", err)
	} else {
		tlsConfig = cfg
		log.Printf("TLS enabled — clients can connect with sslmode=require")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if idle > 0 {
		go reaper(idle)
		log.Printf("auto-suspend enabled: idle branches stop after %s", idle)
	}
	log.Printf("wire-protocol proxy listening on %s — connect with dbname=<branch> (e.g. dbname=main)", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(c)
	}
}

func handle(client net.Conn) {
	defer client.Close()

	// readStartup may upgrade the connection to TLS, so it returns the conn to
	// use for the rest of the session (Go passes net.Conn by value).
	client, params, err := readStartup(client)
	if err != nil {
		if !errors.Is(err, errHandledCancel) {
			log.Printf("startup: %v", err)
		}
		return
	}

	// Gateway authentication: the client's password must be a valid API key.
	// The authenticated identity becomes the ledger "actor" for this session.
	var actor, keyScope string
	if authStore != nil {
		key, err := requestClientPassword(client)
		if err != nil {
			log.Printf("gateway auth: %v", err)
			return
		}
		u, scope, ok := authStore.VerifyKey(key)
		if !ok {
			sendError(client, "28P01", "invalid API key — use a key_ key as the password")
			return
		}
		actor, keyScope = u.Email, scope
	}

	target := params["database"]
	if target == "" {
		target = "main"
	}
	// A branch-scoped key (an agent's) opens its own branch and nothing else.
	// Checked before the branch is touched, so such a key cannot even wake
	// another branch, and the actor recorded is the agent, not the key's owner.
	if keyScope != "" {
		if !scopeAllows(keyScope, target) {
			sendError(client, "42501", fmt.Sprintf("this key only opens branch %q", keyScope))
			return
		}
		actor = keyScope
	}
	touch(target)
	if st := branch.ContainerState(target); st != "running" && st != "absent" {
		log.Printf("auto-resume: waking %s (was %s)", target, st)
	}
	addr, err := branch.EnsureRunning(target) // resumes the branch if suspended
	if err != nil {
		log.Printf("route dbname=%q: %v", target, err)
		sendError(client, "3D000", err.Error()) // invalid_catalog_name
		return
	}
	backend, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("dial backend %s: %v", addr, err)
		sendError(client, "08006", fmt.Sprintf("could not reach branch %q", target))
		return
	}
	defer backend.Close()

	// Log in to the backend as the real role/database; the branch name and client
	// user were only routing/identity inputs. The Gateway performs the backend
	// handshake so the client never needs the real DB password.
	params["database"] = realDatabase
	// Log the client in as a per-user role named for their identity, so the
	// ledger's session_user (which a client cannot change) is the authoritative
	// actor — attribution becomes non-forgeable. Fall back to the shared role if
	// the per-user role can't be provisioned.
	loginUser := realUser
	backendPass := backendPassword()
	switch {
	case keyScope != "":
		// The branch's own agent role. Its password is derived from the install
		// secret (branch.AgentRolePassword), so session_user is the agent and the
		// attribution cannot be forged. Deliberately not EnsureUserRole: that
		// would reset this role's password and break the DSN already issued.
		loginUser = keyScope
		backendPass = branch.AgentRolePassword(keyScope)
	case actor != "":
		if err := branch.EnsureUserRole(target, actor); err != nil {
			log.Printf("per-user role %q on %s: %v (using %s)", actor, target, err, realUser)
		} else {
			loginUser = actor
		}
	}
	params["user"] = loginUser
	// Attribution for the Blackbox: inject connection context that the
	// branch's DDL event triggers read via current_setting('foxbyte.*'). For a
	// per-user login this is a fallback/display value; session_user is authoritative.
	params["options"] = ledgerOptions(params["options"], actor, target, keyScope == "")
	if err := backendAuth(backend, params, backendPass); err != nil {
		log.Printf("backend auth %s: %v", addr, err)
		sendError(client, "08006", fmt.Sprintf("branch %q authentication failed", target))
		return
	}
	// Authentication (client + backend) complete — tell the client it's in.
	if err := writeAuthOk(client); err != nil {
		return
	}
	log.Printf("routed: dbname=%s -> %s", target, addr)

	// Relay the startup tail (ParameterStatus, BackendKeyData, ReadyForQuery),
	// capturing the backend key so a later CancelRequest from this client can be
	// routed to this branch. After ReadyForQuery it's a raw pipe.
	key, err := relayStartupCaptureKey(client, backend, addr)
	if err != nil {
		return
	}
	if key != "" {
		defer deregisterCancel(key)
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(backend, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, backend); done <- struct{}{} }()
	<-done
}

// readStartup reads the startup phase and returns the startup parameters (user,
// database, ...). When TLS is configured it accepts an SSLRequest, upgrades the
// connection, and returns the wrapped conn — the caller must use the returned
// conn for the rest of the session. GSS is always declined.
func readStartup(client net.Conn) (net.Conn, map[string]string, error) {
	for {
		header := make([]byte, 4)
		if _, err := io.ReadFull(client, header); err != nil {
			return client, nil, err
		}
		msgLen := int(binary.BigEndian.Uint32(header))
		if msgLen < 8 || msgLen > 1<<20 {
			return client, nil, fmt.Errorf("bad startup length %d", msgLen)
		}
		body := make([]byte, msgLen-4)
		if _, err := io.ReadFull(client, body); err != nil {
			return client, nil, err
		}
		switch binary.BigEndian.Uint32(body[:4]) {
		case codeSSL:
			if tlsConfig == nil {
				if _, err := client.Write([]byte{'N'}); err != nil { // we don't offer it
					return client, nil, err
				}
				continue
			}
			// Offer TLS: reply 'S', then wrap and hand the loop the encrypted
			// conn to read the real StartupMessage over.
			if _, err := client.Write([]byte{'S'}); err != nil {
				return client, nil, err
			}
			tconn := tls.Server(client, tlsConfig)
			if err := tconn.Handshake(); err != nil {
				return client, nil, fmt.Errorf("tls handshake: %w", err)
			}
			client = tconn
			continue
		case codeGSS:
			if _, err := client.Write([]byte{'N'}); err != nil { // GSS never offered
				return client, nil, err
			}
			continue
		case codeCancel:
			// A cancel is a fresh, session-less connection carrying only a backend
			// key. Forward it to that backend and we're done (restores Ctrl-C).
			forwardCancel(body)
			return client, nil, errHandledCancel
		case codeStartup30:
			return client, parseParams(body[4:]), nil
		default:
			return client, nil, fmt.Errorf("unsupported startup code %d", binary.BigEndian.Uint32(body[:4]))
		}
	}
}

// sendError writes a Postgres ErrorResponse (a FATAL with the given SQLSTATE
// code and message) so the client shows a clear error instead of "server closed
// the connection unexpectedly".
func sendError(conn net.Conn, code, message string) {
	var fields []byte
	add := func(typ byte, val string) {
		fields = append(fields, typ)
		fields = append(fields, val...)
		fields = append(fields, 0)
	}
	add('S', "FATAL")
	add('C', code)
	add('M', message)
	fields = append(fields, 0) // terminator

	out := make([]byte, 5+len(fields))
	out[0] = 'E'
	binary.BigEndian.PutUint32(out[1:], uint32(4+len(fields)))
	copy(out[5:], fields)
	_, _ = conn.Write(out)
}

func parseParams(b []byte) map[string]string {
	var parts []string
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			parts = append(parts, string(b[start:i]))
			start = i + 1
		}
	}
	params := map[string]string{}
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] == "" {
			break
		}
		params[parts[i]] = parts[i+1]
	}
	return params
}

func buildStartup(params map[string]string) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, codeStartup30)
	for k, v := range params {
		body = append(body, k...)
		body = append(body, 0)
		body = append(body, v...)
		body = append(body, 0)
	}
	body = append(body, 0) // final terminator
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(4+len(body)))
	copy(out[4:], body)
	return out
}

// Probes the reaper uses to decide whether an idle branch is really unused.
// Package-level so tests can stand in for Docker and Postgres.
var (
	probeConnections = branch.ActiveConnections
	probeReplication = branch.ReplicationStatus
)

// canSuspend reports whether a branch that has been idle past the window can be
// stopped. It refuses a branch that still has client connections, and a branch
// with a continuous import: replication has no client connections of its own
// (the subscription's apply worker is a background worker), so an importing
// branch looks idle, and suspending it silently stops the import until
// something wakes the branch again. A probe that fails leaves the branch
// running -- an unreachable branch is not proof that it is unused.
func canSuspend(name string) bool {
	active, err := probeConnections(name)
	if err != nil || active > 0 {
		return false
	}
	r, err := probeReplication(name)
	if err != nil || r.Replicating {
		return false
	}
	return true
}

// reaper periodically suspends branches idle (no proxy activity, no active
// connections and no continuous import) for longer than idle.
func reaper(idle time.Duration) {
	interval := idle / 3
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	for {
		time.Sleep(interval)
		names, err := branch.SuspendableBranches()
		if err != nil {
			continue
		}
		for _, n := range names {
			mu.Lock()
			last, seen := lastActivity[n]
			if !seen {
				lastActivity[n] = time.Now() // first sight: start the idle clock
				mu.Unlock()
				continue
			}
			idleFor := time.Since(last)
			mu.Unlock()
			if idleFor < idle {
				continue
			}
			if !canSuspend(n) {
				continue
			}
			log.Printf("auto-suspend: %s idle %s, 0 connections -> stopping", n, idleFor.Round(time.Second))
			if err := branch.Suspend(n); err != nil {
				log.Printf("suspend %s: %v", n, err)
			}
		}
	}
}
