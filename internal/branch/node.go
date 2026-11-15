// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Letting a standby on another machine reach this primary.
//
// Phase 1 of docs/FOX_HA_Plan.md. Everything the engine does today keeps
// Postgres off the network: startContainer publishes no host port, and the
// comment there says why — a direct connection would bypass the gateway, its
// API key, TLS and ledger attribution. A standby on another machine needs the
// opposite, so this is the one command that reverses it, and it reverses it
// narrowly:
//
//   - only when asked, and never by default;
//   - only on the address given, not on every interface;
//   - only over TLS, with a certificate the standby verifies (nodecerts.go);
//   - only for db_replica, which can copy the database and read none of it
//     (replicationrole.go);
//   - only from the peer address named, as a /32;
//   - and no other role from any other network: while main is published its
//     pg_hba.conf is replaced by one that ends in an explicit reject, so the
//     stock "every role, every address" rule is not on the published port
//     (exposedHBA in replicationrole.go).
//
// The first five were measured across two machines before this was written.
// The one that matters most is the fourth: the superuser is refused
// even over TLS from the permitted address, because the rule names a role.

// nodePGCertDir holds the certificate and key the primary serves.
//
// Deliberately NOT inside main's data directory, even though that is already
// bind-mounted and would have saved a mount. pg_basebackup copies PGDATA — so
// a key kept there would be handed to every standby that joins, which is the
// opposite of what a key is for. Mounted read-only instead.
func nodePGCertDir() string { return filepath.Join(nodeCADir(), "pg") }

// nodeCertMount is where that directory appears inside the container, and so
// the prefix of the paths Postgres is given.
const nodeCertMount = "/fox-tls"

// NodeExposure is what this install publishes for a standby elsewhere.
type NodeExposure struct {
	// Address is what a standby dials, and therefore what the certificate has
	// to name: a wrong one fails after the handshake completes, which is the
	// most confusing moment available.
	Address string `json:"address"`
	// Port on the host. 5432 unless something already has it.
	Port int `json:"port"`
	// Peer is the address admitted by the pg_hba rule, as a CIDR.
	Peer string `json:"peer"`
}

func nodeExposePath() string { return brand.StatePath("node-expose.json") }

// CurrentExposure reports what this install publishes, or false when it
// publishes nothing — which is every install until somebody runs the command.
func CurrentExposure() (NodeExposure, bool) {
	b, err := os.ReadFile(nodeExposePath())
	if err != nil {
		return NodeExposure{}, false
	}
	var e NodeExposure
	if err := json.Unmarshal(b, &e); err != nil || e.Address == "" {
		return NodeExposure{}, false
	}
	return e, true
}

// Exposed reports whether Postgres is published off this machine. Read by
// startContainer, which is why it must be cheap and must not need a database.
func Exposed() bool { _, ok := CurrentExposure(); return ok }

// normalisePeer turns what somebody types into the CIDR a pg_hba rule needs.
//
// A bare address becomes a single-host mask, because "the other node" is one
// machine and a rule admitting a subnet admits every machine on it. A CIDR is
// taken as given — an operator who means a range has said so.
//
// Pure, and tested: this is the width of the door.
func normalisePeer(peer string) (string, error) {
	p := strings.TrimSpace(peer)
	if p == "" {
		return "", fmt.Errorf("no peer address: say which machine the standby is on")
	}
	if strings.Contains(p, "/") {
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return "", fmt.Errorf("%q is not an address or a CIDR range: %w", peer, err)
		}
		// A zero-length prefix is every address there is, which is the rule
		// this command exists to avoid writing.
		if ones, _ := n.Mask.Size(); ones == 0 {
			return "", fmt.Errorf("%q admits every address; name the standby's machine", peer)
		}
		return p, nil
	}
	ip := net.ParseIP(p)
	if ip == nil {
		return "", fmt.Errorf("%q is not an IP address — pg_hba rules match addresses, not names", peer)
	}
	if ip.To4() != nil {
		return p + "/32", nil
	}
	return p + "/128", nil
}

// validateExposeAddress refuses an address that cannot work before anything is
// changed, rather than after a restart.
func validateExposeAddress(addr string) error {
	a := strings.TrimSpace(addr)
	if a == "" {
		return fmt.Errorf("no address: say what a standby should dial")
	}
	if ip := net.ParseIP(a); ip != nil {
		if ip.IsLoopback() {
			return fmt.Errorf("%q is this machine's loopback, which another machine cannot reach", addr)
		}
		if ip.IsUnspecified() {
			return fmt.Errorf("%q is every interface, so the certificate could not name one — "+
				"give the address a standby will dial", addr)
		}
		return nil
	}
	// A name is refused. The port is bound to this one address, and a name
	// cannot be bound: the only way to publish it would be on every interface,
	// which is the opposite of what was asked for.
	return fmt.Errorf("%q is not an IP address. Give the address of this machine that a standby "+
		"will dial: the port is published on that address alone, and a name cannot be bound", addr)
}

// exposeArgs is what a published primary adds to its command line: TLS, from
// files mounted read-only.
//
// On the command line rather than ALTER SYSTEM, like every other setting this
// engine chooses, and for one extra reason here: ALTER SYSTEM writes
// postgresql.auto.conf, pg_basebackup copies PGDATA, and a standby promoted
// later would inherit paths to a certificate it does not have. Phase 5 learned
// that lesson about synchronous_standby_names the hard way.
//
// Pure, so what a published primary runs with is readable in a test.
func exposeArgs(exposed bool) []string {
	if !exposed {
		return nil
	}
	return []string{
		"-c", "ssl=on",
		"-c", "ssl_cert_file=" + nodeCertMount + "/" + nodeServerCertName,
		"-c", "ssl_key_file=" + nodeCertMount + "/" + nodeServerKeyName,
	}
}

// exposeMount is the read-only bind mount carrying them, or "" when nothing is
// published.
func exposeMount(exposed bool) []string {
	if !exposed {
		return nil
	}
	return []string{"-v", nodePGCertDir() + ":" + nodeCertMount + ":ro"}
}

// exposePublish is the host port, bound to the one address rather than to
// every interface. `docker run -p 0.0.0.0:5432:5432` would put the database on
// every network this machine is attached to, which is not what was asked for.
//
// There is no fallback to every interface. An address that is not an IP is
// passed through as it is, so `docker run` refuses it and main fails to start
// with an error naming it, rather than starting on every network. NodeExpose
// refuses such an address before it is ever saved (exposeBindAddress); this
// only matters for a record written by an older release, which accepted names.
func exposePublish(e NodeExposure, exposed bool) []string {
	if !exposed {
		return nil
	}
	// A record from before addresses had to be IPs may hold a hostname. Passing
	// it on would make docker refuse to create main at all, so main starts
	// unpublished instead and the log says how to publish it again.
	addr, err := exposeBindAddress(e)
	if err != nil {
		log.Printf("main is not published for its standby: %v", err)
		return nil
	}
	return []string{"-p", fmt.Sprintf("%s:%d:5432", addr, e.Port)}
}

// exposeBindAddress is the check behind that: the published address must be
// one specific IP. Unparseable or unspecified is an error, never 0.0.0.0.
func exposeBindAddress(e NodeExposure) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(e.Address))
	if ip == nil {
		return "", fmt.Errorf("the published address %q is not an IP address, so it cannot be bound. "+
			"Run `%s node expose --address <this machine's IP> --peer <standby IP> --yes` again",
			e.Address, brand.CLI)
	}
	if ip.IsUnspecified() {
		return "", fmt.Errorf("the published address %q is every interface; name one", e.Address)
	}
	return ip.String(), nil
}

// NodeExpose publishes this primary for a standby on another machine.
//
// Restarts main: the published port and the certificate mount are both fixed
// when a container is made. The TLS settings themselves are sighup and would
// not have needed it — measured — but the port does, so the command says what
// it is about to do and the caller confirms first, the way `realtime setup`
// does.
func NodeExpose(addr, peer string, port int) error {
	if err := validateExposeAddress(addr); err != nil {
		return err
	}
	cidr, err := normalisePeer(peer)
	if err != nil {
		return err
	}
	if port == 0 {
		port = 5432
	}
	if PrimaryContainer() == container("standby") {
		return fmt.Errorf("'main' is being served by the promoted standby since `%s ha failover`.\n"+
			"Run `%s ha failback` first: a standby should join the primary, not the machine standing in for it",
			brand.CLI, brand.CLI)
	}

	// A previous run gave the key to the database user, so take the directory
	// back before writing into it. Without this, `node expose` works once and
	// then fails with "permission denied" creating a temporary file — which is
	// exactly what it did, because the first version chowned the directory
	// rather than the key.
	if err := reclaimCertDir(); err != nil {
		return err
	}
	// The certificate next, because it is the part that can fail for a reason
	// worth hearing before anything restarts.
	if _, _, err := issueServerCert(nodePGCertDir(), addr); err != nil {
		return err
	}
	if err := handKeyToPostgres(); err != nil {
		return err
	}

	e := NodeExposure{Address: strings.TrimSpace(addr), Port: port, Peer: cidr}
	if _, err := exposeBindAddress(e); err != nil {
		return err
	}

	// The access rules before the port. pg_hba.conf lives in the data
	// directory, which survives the restart, so writing it into the running
	// main now means the published port never carries the stock rules, not
	// even for the seconds between the restart and the next step. A primary
	// that is not running cannot be published anyway.
	if err := allowReplicationFor(PrimaryContainer(), cidr); err != nil {
		return fmt.Errorf("writing the access rules before publishing main (main must be running): %w", err)
	}

	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(nodeExposePath()), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(nodeExposePath(), append(b, '\n'), 0o600); err != nil {
		return err
	}

	// Restarting picks up the mount, the port and the TLS settings together.
	fmt.Printf("Restarting main to publish it on %s:%d…\n", addr, port)
	if err := startContainer("main", true); err != nil {
		// Leave no state claiming an exposure that did not happen. The rules
		// written above stay until the next `ha enable` or `node unexpose`
		// puts the old ones back: narrower than needed is the safe way round.
		_ = os.Remove(nodeExposePath())
		return fmt.Errorf("restarting main: %w", err)
	}
	if err := waitReady("main"); err != nil {
		return err
	}
	// The same rules again, now that main is back. Idempotent, and it confirms
	// the restarted server loaded them.
	if err := allowReplication(PrimaryContainer()); err != nil {
		return err
	}
	if err := ExposeSSL(); err != nil {
		return err
	}
	fmt.Printf("\n%s is reachable by a standby at %s:%d, over TLS, as %s and from %s only.\n",
		brand.Product, addr, port, ReplicationRole, cidr)
	fmt.Printf("Nothing else is published: clients still reach branches through the gateway.\n\n")
	tok, err := JoinToken()
	if err != nil {
		return err
	}
	fmt.Printf("On the other machine, run:\n\n  %s node join %s\n\n", brand.CLI, tok)
	fmt.Printf("That token carries this install's CA certificate and the %s password, and nothing\n"+
		"else — not the install secret, so it cannot derive any other role's password.\n", ReplicationRole)
	return nil
}

// ExposeSSL confirms Postgres is actually serving TLS, and says so rather than
// leaving a standby to discover it.
//
// A separate step because `ssl=on` is a setting the server can refuse at
// startup — an unreadable key leaves it running with TLS off, and then the
// hostssl rule matches nothing and a standby's only symptom is "no pg_hba.conf
// entry", which points at the wrong thing entirely.
func ExposeSSL() error {
	out, err := capture("docker", "exec", "--env-file", pgEnvFile(), PrimaryContainer(),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc", "SHOW ssl")
	if err != nil {
		return fmt.Errorf("asking main whether it is serving TLS: %w", err)
	}
	if strings.TrimSpace(out) != "on" {
		return fmt.Errorf("main came up without TLS (ssl=%q), so a standby could not connect and no\n"+
			"replication rule would match. Check `%s logs` for why it could not read the key",
			strings.TrimSpace(out), brand.CLI)
	}
	return nil
}

// reclaimCertDir makes the certificate directory writable by this user again.
//
// `fox expose` has to be re-runnable: an operator changes the address, or the
// peer, or simply runs it twice. And a directory inside the state directory
// that this user cannot write is worse than inconvenient — `fox uninstall`
// removes ~/.fox with rm -rf as this user, and a directory it cannot enter
// stops the whole uninstall. Both of those were real: the first version of
// this chowned the directory and broke each of them.
func reclaimCertDir() error {
	dir := nodePGCertDir()
	if _, err := os.Stat(dir); err != nil {
		return nil // nothing there yet
	}
	me := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	if err := run("chown", "-R", me, dir); err != nil {
		return fmt.Errorf("taking back %s so a new certificate can be written: %w", dir, err)
	}
	return nil
}

// handKeyToPostgres gives the server its key, and nothing else away.
//
// Postgres refuses a private key that is group- or world-readable, or that
// belongs to neither the database user nor root. The container runs as pgUID,
// so the key is given to it — the *key only*. The directory stays this user's,
// which is what keeps expose re-runnable and uninstall able to remove it: a
// file is deleted by permission on its directory, not by owning the file.
func handKeyToPostgres() error {
	dir := nodePGCertDir()
	// The container's postgres user has to be able to enter the directory to
	// read what is in it; the directory is inside the 0700 state directory, so
	// this does not widen anything a stranger can reach.
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	key := filepath.Join(dir, nodeServerKeyName)
	if err := run("chown", pgUID+":"+pgUID, key); err != nil {
		return fmt.Errorf("giving the private key to the database user: %w", err)
	}
	return run("chmod", "600", key)
}

// NodeUnexpose takes it back off the network.
func NodeUnexpose() error {
	if !Exposed() {
		// Still put the old rules back if a published-shape pg_hba.conf was
		// left behind, which an expose that failed at the restart does. Best
		// effort: with nothing published, narrower rules are not a hazard,
		// only a surprise.
		if err := allowReplicationFor(PrimaryContainer(), ""); err != nil {
			fmt.Printf("Note: could not check main's access rules (%v).\n", err)
		}
		fmt.Println("Nothing is published: this install was already off the network.")
		return nil
	}
	if err := os.Remove(nodeExposePath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Println("Restarting main without the published port…")
	if err := startContainer("main", true); err != nil {
		return fmt.Errorf("restarting main: %w", err)
	}
	if err := waitReady("main"); err != nil {
		return err
	}
	// The rules from before the exposure come back, and the peer rule goes. The
	// role and the samenet rule stay: a standby on this machine still uses
	// them. Done after the restart, so the port is gone before the stock rules
	// return.
	if err := allowReplicationFor(PrimaryContainer(), ""); err != nil {
		return err
	}
	fmt.Println("Postgres is off the network again. Clients reach branches through the gateway, as before.")
	return nil
}

// JoinToken is everything the other machine needs, and nothing more.
//
// The CA certificate so it can verify this primary, the address and port to
// dial, and db_replica's password. Deliberately NOT the install secret: every
// role password on an install is derived from that secret, so handing it over
// would let the other machine derive the superuser's. One role's password is
// the narrow thing to send, and it is the only credential a standby needs.
//
// The cost of that choice, written down rather than discovered: the other
// machine cannot derive this password if it is ever rotated, so a rotation
// means re-issuing the token. That is the right trade — a rotation is rare and
// a superuser credential on a second machine is forever.
//
// Base64 of JSON, because it has to survive being pasted into a terminal.
func JoinToken() (string, error) {
	e, ok := CurrentExposure()
	if !ok {
		return "", fmt.Errorf("nothing is published yet — run `%s node expose` first", brand.CLI)
	}
	ca, err := NodeCACertPEM()
	if err != nil {
		return "", err
	}
	t := joinPayload{
		Version:  1,
		Address:  e.Address,
		Port:     e.Port,
		Role:     ReplicationRole,
		Password: ReplicationRolePassword(),
		CACert:   ca,
		Database: pgDatabase,
	}
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// joinPayload is the token's contents. A version, so a token minted by a later
// release can be refused with a sentence rather than a parse error.
type joinPayload struct {
	Version  int    `json:"v"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Role     string `json:"role"`
	Password string `json:"password"`
	CACert   string `json:"ca"`
	Database string `json:"database"`
}

// ParseJoinToken reads one back, and refuses anything it cannot use.
func ParseJoinToken(tok string) (joinPayload, error) {
	var p joinPayload
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(tok))
	if err != nil {
		return p, fmt.Errorf("this does not look like a join token: %w", err)
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("this join token could not be read: %w", err)
	}
	if p.Version != 1 {
		return p, fmt.Errorf("this join token is version %d; this %s understands version 1 — "+
			"the two installs are different releases", p.Version, brand.CLI)
	}
	for what, v := range map[string]string{
		"address":        p.Address,
		"role":           p.Role,
		"password":       p.Password,
		"CA certificate": p.CACert,
		"database name":  p.Database,
	} {
		if strings.TrimSpace(v) == "" {
			return p, fmt.Errorf("this join token carries no %s", what)
		}
	}
	if p.Port <= 0 || p.Port > 65535 {
		return p, fmt.Errorf("this join token names port %d", p.Port)
	}
	return p, nil
}

// DescribeExposure is the one-line summary `fox status` and `fox check` use.
func DescribeExposure() string {
	e, ok := CurrentExposure()
	if !ok {
		return "not published: Postgres is reachable only on this machine"
	}
	return fmt.Sprintf("published at %s for a standby at %s, over TLS as %s",
		net.JoinHostPort(e.Address, strconv.Itoa(e.Port)), e.Peer, ReplicationRole)
}
