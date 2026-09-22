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
)

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
