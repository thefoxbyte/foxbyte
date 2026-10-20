// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// The other side of `node expose`: this install becomes the standby for a
// primary on another machine.
//
// Phase 1 of docs/FOX_HA_Plan.md, and the last of its items. What it reuses is
// the point — the standby container, its storage, the promotion, the failover
// refusals, slot synchronisation, zero-data-loss mode and the drill all work
// on a standby whose primary is across a network exactly as they do on one
// whose primary is the container next to it. The only differences are where
// the base backup comes from and that the walreceiver has a certificate to
// verify.
//
// What this install's own `main` is for afterwards: nothing. A node that hosts
// a standby of another install is a standby node, and its own main sits idle.
// That is honest rather than elegant, and it is what makes this additive: no
// existing path changes meaning, and `ha failover` on this machine promotes the
// standby and reroutes exactly as it always has.

// joinedCAName is where the primary's CA lives on this machine, and
// joinedCAMount where it appears inside the containers that need it.
//
// The same path in both the base backup and the standby, and that is not a
// tidiness choice: pg_basebackup -R copies the parameters it connected with
// into primary_conninfo, sslrootcert among them, as the path it saw. The
// walreceiver then reads that path from inside the standby container. Give the
// backup a different path from the standby and the standby cannot verify
// anything — measured.
const (
	joinedCAName  = "ca-primary.crt"
	joinedCAMount = "/fox-tls/ca.crt"
)

func joinedCAPath() string { return filepath.Join(nodeCADir(), joinedCAName) }

// Joined is what this install knows about the primary it follows.
type Joined struct {
	Address string    `json:"address"`
	Port    int       `json:"port"`
	Role    string    `json:"role"`
	At      time.Time `json:"at"`
}

func joinedPath() string { return brand.StatePath("node-joined.json") }

// CurrentJoin reports the primary this install is a standby of, or false when
// it is a primary in its own right — which is every install until somebody
// runs `node join`.
func CurrentJoin() (Joined, bool) {
	b, err := os.ReadFile(joinedPath())
	if err != nil {
		return Joined{}, false
	}
	var j Joined
	if err := json.Unmarshal(b, &j); err != nil || j.Address == "" {
		return Joined{}, false
	}
	return j, true
}

// IsStandbyNode reports whether this install follows a primary elsewhere. Read
// by startStandbyContainer and by the guards on `ha enable`, so it must be
// cheap and must not need a database.
func IsStandbyNode() bool { _, ok := CurrentJoin(); return ok }

// joinedMount is the CA, read-only, for a container that has to verify the
// primary. Empty on an install that follows nobody, so a local standby's
// arguments are exactly what they were.
func joinedMount() []string {
	if !IsStandbyNode() {
		return nil
	}
	return []string{"-v", joinedCAPath() + ":" + joinedCAMount + ":ro"}
}

// remoteBaseBackupArgs copies a primary on another machine.
//
// Separate from baseBackupArgs rather than another flag on it: that one takes
// a container name on this host's docker network and this one takes an address,
// a port, a TLS mode and a certificate — and the local form has a test
// asserting it is byte-for-byte what it has always been, which is worth
// keeping readable.
//
// sslmode=verify-full, not require. `require` encrypts and verifies nothing,
// which would leave this standby sending a credential that copies the database
// to whoever answered on that address.
func remoteBaseBackupArgs(j Joined, dataDir string) []string {
	conninfo := fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=verify-full sslrootcert=%s",
		j.Address, j.Port, j.Role, pgDatabase, joinedCAMount)
	return []string{
		"pg_basebackup", "-d", conninfo, "-D", dataDir,
		"-R", "-X", "stream", "-c", "fast",
	}
}

// NodeJoin makes this install the standby of the primary a token describes.
//
// Not destructive of this install's own data: the standby has storage of its
// own (the same storage `ha enable` uses), so main is untouched. Re-running it
// rebuilds the standby from the primary, which is how a standby that has fallen
// too far behind is repaired.
func NodeJoin(token string) error {
	p, err := ParseJoinToken(token)
	if err != nil {
		return err
	}
	if PrimaryContainer() == container("standby") {
		return fmt.Errorf("this install is serving 'main' from its promoted standby since `%s ha failover`.\n"+
			"Run `%s ha failback` first", brand.CLI, brand.CLI)
	}
	// A standby of this install's own main, and a standby of somebody else's,
	// are the same container and the same storage. Doing both is not a
	// configuration, it is a collision.
	if !IsStandbyNode() && ContainerState("standby") != "absent" {
		return fmt.Errorf("this install already has a standby of its own main.\n"+
			"Run `%s ha disable` first if this machine should follow %s instead",
			brand.CLI, p.Address)
	}

	// The CA before anything else: without it the backup cannot verify the
	// primary, and verifying is the whole reason the token carries it.
	if err := os.MkdirAll(nodeCADir(), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(joinedCAPath(), []byte(p.CACert), 0o644); err != nil {
		return fmt.Errorf("writing the primary's CA certificate: %w", err)
	}

	j := Joined{Address: p.Address, Port: p.Port, Role: p.Role, At: time.Now().UTC()}

	fmt.Printf("1/4 copying %s:%d over TLS…\n", j.Address, j.Port)
	store := activeStorage()
	removeContainer(container("standby"))
	if err := store.resetStandby(); err != nil {
		return err
	}
	if err := run("chown", "-R", pgUID+":"+pgUID, store.standbyPath()); err != nil {
		return err
	}
	// The replication role's password comes from the token: this install's own
	// secret derives a different one, and the primary knows nothing about it.
	env := joinedReplicaEnvFile(p.Password)
	args := append([]string{"run", "--rm", "--user", pgUID, "--network", network,
		"--env-file", env,
		"-v", store.standbyPath() + ":/data",
		"-v", joinedCAPath() + ":" + joinedCAMount + ":ro",
		pgImage()},
		remoteBaseBackupArgs(j, "/data/pgdata")...)
	if err := run("docker", args...); err != nil {
		return fmt.Errorf("copying the primary: %w\n\n"+
			"Check that `%s node expose` has been run there, that this machine's address is the\n"+
			"--peer it names, and that %s:%d is reachable from here", err, brand.CLI, j.Address, j.Port)
	}

	// Recorded only once the copy exists, so a failed join leaves an install
	// that is still its own primary rather than one claiming to follow
	// somebody it never reached.
	fmt.Println("2/4 recording the primary…")
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(joinedPath(), append(b, '\n'), 0o600); err != nil {
		return err
	}

	fmt.Println("3/4 starting the standby…")
	if err := startStandbyContainer(store); err != nil {
		return err
	}
	if err := waitReady("standby"); err != nil {
		return err
	}

	fmt.Println("4/4 waiting for it to stream…")
	if err := pollUntil("the standby to start streaming from "+j.Address, 2*time.Minute, func() bool {
		return StandbyStreamingFromRemote()
	}); err != nil {
		return fmt.Errorf("%w\n\nThe copy succeeded, so the credentials and TLS are right; the standby is not\n"+
			"replaying yet. `%s ha status` and `%s logs` say more", err, brand.CLI, brand.CLI)
	}

	fmt.Printf("\nThis machine is now a standby of %s:%d.\n", j.Address, j.Port)
	fmt.Printf("  Streaming over TLS as %s, verifying that primary's certificate.\n", j.Role)
	fmt.Printf("  `%s ha status` shows how far behind it is; `%s ha failover` promotes it.\n",
		brand.CLI, brand.CLI)
	fmt.Printf("  This install's own 'main' is idle while it follows another primary.\n")
	return nil
}

// StandbyStreamingFromRemote reports whether the local standby is receiving
// WAL from the primary it follows.
//
// Asked of the standby rather than of the primary, which is the only side
// reachable from here: pg_stat_replication lives on the sender, and this
// machine is the receiver. pg_stat_wal_receiver is the mirror of it.
func StandbyStreamingFromRemote() bool {
	out, err := capture("docker", "exec", "--env-file", pgEnvFile(), container("standby"),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc",
		"SELECT count(*) FROM pg_stat_wal_receiver WHERE status = 'streaming'")
	return err == nil && strings.TrimSpace(out) == "1"
}

// RemotePrimaryAnswering reports whether the primary this install follows is
// still serving on the address it was joined at.
//
// A TCP connection and nothing more, deliberately. The question being asked is
// "would promoting here produce a second primary", and anything that answers on
// that port is reason enough to believe it would. A richer probe — connect,
// ask pg_is_in_recovery — would be more precise and would need credentials and
// a working TLS handshake to say "no", which means it would answer "the primary
// is gone" for a certificate problem. The conservative error is to refuse a
// promotion that might have been safe; the expensive one is to allow a
// promotion that was not.
func RemotePrimaryAnswering(j Joined, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(j.Address, strconv.Itoa(j.Port)), timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// fenceRemotePrimary refuses a promotion that would make two primaries.
//
// This closes a hole that `node join` opened. On one machine HAFailover stops
// the old primary before promoting the standby, and "stop the old primary" is
// the whole of fencing when both are containers here. Across machines it
// stopped the wrong thing: PrimaryContainer() is this host's own pg-main, which
// on a joined node is an idle database nobody uses, while the real primary went
// on serving writes somewhere else.
//
// Measured, with the primary left healthy: after `ha failover` both machines
// accepted writes and the promoted one reported pg_is_in_recovery() false. Two
// primaries, diverging, with nothing to say so.
//
// What this does and does not fix. It refuses to promote while the primary
// answers, which covers the case that produced that measurement — an operator
// promoting a standby whose primary is fine. It cannot cover a network
// partition: if this machine cannot reach the primary but clients still can,
// promoting here produces exactly the split-brain above and no amount of local
// probing can tell the two situations apart. That needs a third opinion, which
// is what phase 3's failover manager is for. Said here rather than implied,
// because a guard that looks like a solution is worse than one that names its
// limit.
func fenceRemotePrimary(force bool) error {
	j, ok := CurrentJoin()
	if !ok {
		return nil // a standby of this machine's own main: stopping it is enough
	}
	answering := RemotePrimaryAnswering(j, 5*time.Second)
	if !answering {
		return nil
	}
	if force {
		fmt.Printf("\nWARNING: %s:%d is still answering, and --force was given.\n"+
			"If it is still serving clients, both machines are about to accept writes and the\n"+
			"two copies will diverge with no way to merge them. This is only safe if that\n"+
			"machine has been stopped, isolated or fenced by something other than this\n"+
			"command.\n\n", j.Address, j.Port)
		return nil
	}
	return fmt.Errorf("%s", fenceRefusal(j))
}

// NodeLeave stops following the primary. The standby's storage goes with it,
// because a copy of somebody else's database that nothing keeps up to date is
// not a backup, it is a stale liability.
func NodeLeave() error {
	j, ok := CurrentJoin()
	if !ok {
		fmt.Println("This install follows no other primary.")
		return nil
	}
	if PrimaryContainer() == container("standby") {
		return fmt.Errorf("this machine is serving 'main' from the standby it was following %s with.\n"+
			"Leaving now would delete the only copy of those writes. Run `%s ha failback` first",
			j.Address, brand.CLI)
	}
	removeContainer(container("standby"))
	activeStorage().destroyStandby()
	if err := os.Remove(joinedPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(joinedCAPath())
	fmt.Printf("No longer following %s:%d. The standby and its copy are gone.\n", j.Address, j.Port)
	return nil
}

// DescribeJoin is the one-line summary `ha status` and `fox check` use.
func DescribeJoin() string {
	j, ok := CurrentJoin()
	if !ok {
		return ""
	}
	return fmt.Sprintf("a standby of %s:%d, over TLS as %s", j.Address, j.Port, j.Role)
}

// fenceRefusal is what the refusal says, separated so a test can read it: this
// message is the whole value of the guard, because somebody reads it during an
// incident and it has to name both the way forward and its own limit.
func fenceRefusal(j Joined) string {
	return fmt.Sprintf("the primary at %s:%d is still answering, so promoting this standby would\n"+
		"make a second primary and the two copies would diverge.\n\n"+
		"This command cannot stop a database on another machine. Stop that one first, then\n"+
		"run this again \u2014 or pass --force if it is already isolated by something else.\n\n"+
		"This check cannot tell a dead primary from one this machine merely cannot reach: if\n"+
		"the network is partitioned and clients can still reach %s, forcing a promotion here\n"+
		"produces two primaries anyway. That needs a third opinion, which is what a failover\n"+
		"manager is for (phase 3 of docs/FOX_HA_Plan.md).",
		j.Address, j.Port, j.Address)
}
