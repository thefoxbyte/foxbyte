// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// The engine runs psql, pg_dump and the containers through `sudo docker`, and
// used to pass the superuser password as `-e PGPASSWORD=<secret>`: an argument,
// visible to anyone on the machine who lists processes while the command runs.
// Docker reads an --env-file itself, so the secret now lives in one file next
// to secrets.json, with the same permissions, and never on a command line.

var (
	pgEnvOnce sync.Once
	pgEnvPath string

	replicaEnvOnce sync.Once
	replicaEnvPath string
)

// replicaEnvFile is the same mechanism for the replication role's password,
// which the base backup reads (replicationrole.go).
//
// Here rather than beside the role it belongs to, because this file is one of
// the two TestNoPasswordOnCommandLines exempts — and the right answer to that
// test is one place that knows how to write a credential file, not a third
// exemption. A second credential is no reason to lower the bar for the first.
func replicaEnvFile() string {
	replicaEnvOnce.Do(func() {
		replicaEnvPath = writeEnvFile("replica.env",
			fmt.Sprintf("PGPASSWORD=%s\n", ReplicationRolePassword()))
	})
	return replicaEnvPath
}

// joinedReplicaEnvFile is the replication password a join token carried, for
// the base backup that copies a primary on another machine (nodejoin.go).
//
// Takes the password rather than deriving it, because that is the whole point:
// this install's own secret derives a different one and the primary has never
// heard of it. Here rather than beside the join for the same reason
// replicaEnvFile is here — this file is one of the two
// TestNoPasswordOnCommandLines exempts, and one place that knows how to write a
// credential file beats a third exemption. That test caught this twice now,
// and was right twice.
func joinedReplicaEnvFile(password string) string {
	return writeEnvFile("joined-replica.env", fmt.Sprintf("PGPASSWORD=%s\n", password))
}

// writeEnvFile puts one credential file in the state directory, 0600, and
// returns its path. Written beside and renamed over, so a process reading it
// never sees half a file. On failure it still returns the path, because docker
// reports a missing env file and names it, which is a better error than
// anything this could invent.
func writeEnvFile(name, body string) string {
	p := brand.StatePath(name)
	if cur, err := os.ReadFile(p); err == nil && string(cur) == body {
		return p
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err == nil {
		tmp, err := os.CreateTemp(filepath.Dir(p), "."+name+"-*")
		if err == nil {
			_, werr := tmp.Write([]byte(body))
			cerr := tmp.Close()
			if werr == nil && cerr == nil && os.Chmod(tmp.Name(), 0o600) == nil && os.Rename(tmp.Name(), p) == nil {
				return p
			}
			_ = os.Remove(tmp.Name())
		}
	}
	return p
}

// pgEnvFile returns the path of the env file holding the superuser password
// (PGPASSWORD for the clients, POSTGRES_PASSWORD for a container's first
// start), writing it on first use in this process. A failure to write it is
// fatal to the command that needed it, as a missing password would be.
func pgEnvFile() string {
	pgEnvOnce.Do(func() {
		p := brand.StatePath("pg.env")
		body := []byte(fmt.Sprintf("PGPASSWORD=%s\nPOSTGRES_PASSWORD=%s\n", pgPass(), pgPass()))
		if cur, err := os.ReadFile(p); err == nil && string(cur) == string(body) {
			pgEnvPath = p
			return
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err == nil {
			// Written beside and renamed over, so a process reading it never
			// sees half a file.
			tmp, err := os.CreateTemp(filepath.Dir(p), ".pg.env-*")
			if err == nil {
				_, werr := tmp.Write(body)
				cerr := tmp.Close()
				if werr == nil && cerr == nil && os.Chmod(tmp.Name(), 0o600) == nil && os.Rename(tmp.Name(), p) == nil {
					pgEnvPath = p
					return
				}
				_ = os.Remove(tmp.Name())
			}
		}
		pgEnvPath = p // docker reports the missing file, naming it
	})
	return pgEnvPath
}

// vaultDBEnvFile is the vault database's environment (point 13): its
// superuser's password, for the first start, and the vault service's role's,
// which the database's init script reads to make the role. Neither reaches a
// command line.
func vaultDBEnvFile(superPass, svcPass string) string {
	// envFile, not writeEnvFile: the file is in a directory of its own, and
	// writeEnvFile's temporary name is made from the name it is given.
	return envFile(filepath.Join("vault", "db.env"),
		fmt.Sprintf("POSTGRES_PASSWORD=%s\nFOX_VAULT_SVC_PASSWORD=%s\n", superPass, svcPass))
}
