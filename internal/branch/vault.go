// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// The vault (point 13, docs/FOX_P13_Vault_Design.md): one per install, two
// containers of its own. The vault database is a PostgreSQL on a Docker
// network created --internal, which only the vault service shares; the
// service holds the PKCS#11 session and serves the engine on a Unix socket in
// the state directory. This file is the plumbing: where things are, making
// and starting the containers, and passing calls through. The service, its
// kinds and its client are Enterprise (enterprise/vault), reached through the
// Vaulter hook.

const (
	// VaultNetwork is the vault's own network: internal, so nothing on it has a
	// route out, and only the vault database and the service are on it.
	VaultNetwork = "fox-vault"
	// VaultHSMNetwork is an ordinary network the service also joins when the
	// HSM is a network one, so it can reach that address. The database never
	// joins it.
	VaultHSMNetwork = "fox-vault-hsm"
	// VaultDBVolume holds the vault database's data.
	VaultDBVolume = "fox-vault-db"

	vaultDBContainer  = "fox-vault-db"
	vaultSvcContainer = "fox-vault"
	vaultLabel        = "dev.dbengine.vault=1"

	// VaultImageRevision is the vault image this fox needs, as the image's
	// dev.dbengine.image-revision label numbers it.
	VaultImageRevision = 1

	// vaultSoftLib is FoxByte's own software token, inside the image.
	vaultSoftLib = "/usr/lib/softhsm/libsofthsm2.so"
	// vaultDefaultSubnet is small and unusual, so it rarely meets a network
	// already on the machine; FOX_VAULT_SUBNET picks another at setup.
	vaultDefaultSubnet = "172.29.213.0/29"
)

// ErrVaultNotSetUp is an install with no vault yet.
var ErrVaultNotSetUp = fmt.Errorf("%w: the vault is not set up on this install: %s vault setup", ErrInvalidRequest, brand.CLI)

// VaultConfig is what setup decided, kept in the state directory so the
// engine makes the same containers on every start.
type VaultConfig struct {
	SetUpAt time.Time `json:"set_up_at"`
	Subnet  string    `json:"subnet"`
	DBAddr  string    `json:"db_addr"`
	SvcAddr string    `json:"service_addr"`
	// PGMajor is the vault database's PostgreSQL major, fixed at setup: the
	// install's own major can move with `fox pg upgrade`; the vault's data
	// stays on the major it was made with.
	PGMajor string `json:"pg_major"`
	Token   string `json:"token"`
	// HSM is the customer's HSM; nil means FoxByte's own software token.
	HSM *VaultHSM `json:"hsm,omitempty"`
}

// VaultHSM is a customer's HSM: its client library's directory on this
// machine, mounted into the service, and the library inside it.
type VaultHSM struct {
	Dir string `json:"dir"`
	Lib string `json:"lib"`
}

// VaultSetupOptions are `fox vault setup`'s choices. All empty: FoxByte's own
// software token, labelled not compliant for kinds that require an HSM.
type VaultSetupOptions struct {
	HSMDir  string   // the HSM client's directory on this machine
	HSMLib  string   // the PKCS#11 library, relative to HSMDir
	HSMEnv  []string // NAME=VALUE the HSM client needs
	Token   string   // the token's label
	PINFile string   // a file holding the token's user PIN
}

func vaultPath(elem ...string) string {
	return brand.StatePath(append([]string{"vault"}, elem...)...)
}

// VaultSocket is where the service listens for the engine.
func VaultSocket() string { return vaultPath("run", "vault.sock") }

func vaultConfigPath() string { return vaultPath("vault.json") }

// VaultSetUp reports whether this install has a vault.
func VaultSetUp() bool {
	_, err := os.Stat(vaultConfigPath())
	return err == nil
}

// LoadVaultConfig reads what setup decided.
func LoadVaultConfig() (*VaultConfig, error) {
	b, err := os.ReadFile(vaultConfigPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrVaultNotSetUp
	}
	if err != nil {
		return nil, err
	}
	var c VaultConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", vaultConfigPath(), err)
	}
	return &c, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// vaultAddrs are the network's gateway's neighbours: the database second, the
// service third, fixed so the database admits only the service's address.
func vaultAddrs(subnet string) (db, svc string, err error) {
	p, err := netip.ParsePrefix(subnet)
	if err != nil || !p.Addr().Is4() || p.Bits() > 29 {
		return "", "", fmt.Errorf("%w: the vault's subnet %q is not an IPv4 network of at least 8 addresses (for example %s)", ErrInvalidRequest, subnet, vaultDefaultSubnet)
	}
	a := p.Masked().Addr()
	a = a.Next().Next()
	return a.String(), a.Next().String(), nil
}

// vaultHBA lets the service's role in from the service's address only, and
// nobody else from anywhere: the machine itself reaches an internal network
// through its bridge (design, section 20), so the network alone is not enough.
func vaultHBA(svc string) string {
	return "# Written by " + brand.CLI + " (the vault): only the vault service may log in.\n" +
		"local all all trust\n" +
		"host vault vault_svc " + svc + "/32 scram-sha-256\n" +
		"host all all all reject\n"
}

// vaultDBInit makes the service's role and database on the first start. The
// password comes from the container's environment, never from this file.
const vaultDBInit = `#!/bin/sh
# Written by the vault's setup: the service's role and its database.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE vault_svc LOGIN PASSWORD '$FOX_VAULT_SVC_PASSWORD';
CREATE DATABASE vault OWNER vault_svc;
SQL
`

func writePlain(path, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(body), 0o644)
}

// VaultSetup makes the install's vault: its secrets, its token (FoxByte's own
// software one unless an HSM is named), the image, the networks and the two
// containers, and starts them. A failure takes back what it made, so setup can
// simply be run again.
func VaultSetup(o VaultSetupOptions) (*VaultConfig, error) {
	if err := requireFeature(edition.Vault); err != nil {
		return nil, err
	}
	if VaultSetUp() {
		return nil, fmt.Errorf("%w: the vault is set up already", ErrInvalidRequest)
	}
	c := &VaultConfig{SetUpAt: time.Now().UTC(), Subnet: vaultDefaultSubnet, Token: "fox-vault", PGMajor: PGMajor}
	if s := strings.TrimSpace(brand.Getenv("VAULT_SUBNET")); s != "" {
		c.Subnet = s
	}
	var err error
	if c.DBAddr, c.SvcAddr, err = vaultAddrs(c.Subnet); err != nil {
		return nil, err
	}
	pin := randomHex(16)
	if o.HSMDir != "" || o.HSMLib != "" || o.PINFile != "" {
		if c.HSM, pin, err = vaultHSMOptions(o); err != nil {
			return nil, err
		}
		c.Token = strings.TrimSpace(o.Token)
	} else if strings.TrimSpace(o.Token) != "" {
		c.Token = strings.TrimSpace(o.Token)
	}
	if c.Token == "" || len(c.Token) > 32 {
		return nil, fmt.Errorf("%w: a token's label is 1 to 32 characters", ErrInvalidRequest)
	}
	for _, e := range o.HSMEnv {
		if name, _, ok := strings.Cut(e, "="); !ok || name == "" || strings.ContainsAny(name, " \n") {
			return nil, fmt.Errorf("%w: --hsm-env takes NAME=VALUE, not %q", ErrInvalidRequest, e)
		}
	}

	ok := false
	defer func() {
		if !ok {
			vaultTakeBack()
		}
	}()
	for _, d := range []string{"", "secret", "run", "tokens", "db"} {
		if err := os.MkdirAll(vaultPath(d), 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(vaultPath(d), 0o700); err != nil {
			return nil, err
		}
	}
	svcPass := randomHex(16)
	secrets := map[string]string{
		"secret": randomHex(32),
		"pin":    pin,
		"dsn":    fmt.Sprintf("postgres://vault_svc:%s@%s:5432/vault?sslmode=disable", svcPass, c.DBAddr),
	}
	if c.HSM == nil {
		secrets["so-pin"] = randomHex(16)
	}
	for name, v := range secrets {
		if err := writeSecretFile(vaultPath("secret", name), []byte(v+"\n")); err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(vaultDBEnvFile(randomHex(16), svcPass)); err != nil {
		return nil, fmt.Errorf("the vault database's environment file: %w", err)
	}
	if len(o.HSMEnv) > 0 {
		if err := writeSecretFile(vaultPath("hsm.env"), []byte(strings.Join(o.HSMEnv, "\n")+"\n")); err != nil {
			return nil, err
		}
	}
	if err := writePlain(vaultPath("db", "pg_hba.conf"), vaultHBA(c.SvcAddr)); err != nil {
		return nil, err
	}
	if err := writePlain(vaultPath("db", "init.sh"), vaultDBInit); err != nil {
		return nil, err
	}
	img, err := ensureVaultImage()
	if err != nil {
		return nil, err
	}
	if err := ensureImageRef(PostgresImageFor(c.PGMajor)); err != nil {
		return nil, err
	}
	if err := ensureVaultNetworks(c); err != nil {
		return nil, err
	}
	if c.HSM == nil {
		fmt.Println("Making FoxByte's own software token (not UIDAI-compliant: trials and testing only)…")
		if err := run("docker", "run", "--rm", "--user", vaultUser(), "--network", "none",
			"-v", vaultPath("tokens")+":/var/lib/fox-vault/tokens",
			"-v", vaultPath("secret")+":/etc/fox-vault/secret:ro",
			img, "init-token", "--token", c.Token); err != nil {
			return nil, fmt.Errorf("making the software token: %w", err)
		}
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(vaultConfigPath(), b, 0o600); err != nil {
		return nil, err
	}
	if err := vaultUp(c, img); err != nil {
		return nil, err
	}
	ok = true
	return c, nil
}

func vaultHSMOptions(o VaultSetupOptions) (*VaultHSM, string, error) {
	dir := filepath.Clean(strings.TrimSpace(o.HSMDir))
	if !filepath.IsAbs(dir) {
		return nil, "", fmt.Errorf("%w: --hsm-dir is the HSM client's directory, as an absolute path", ErrInvalidRequest)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil, "", fmt.Errorf("%w: --hsm-dir %s is not a directory", ErrInvalidRequest, dir)
	}
	lib := filepath.Clean(strings.TrimSpace(o.HSMLib))
	if lib == "." || filepath.IsAbs(lib) || strings.HasPrefix(lib, "..") {
		return nil, "", fmt.Errorf("%w: --hsm-lib is the PKCS#11 library's path inside --hsm-dir", ErrInvalidRequest)
	}
	if fi, err := os.Stat(filepath.Join(dir, lib)); err != nil || fi.IsDir() {
		return nil, "", fmt.Errorf("%w: there is no library %s in %s", ErrInvalidRequest, lib, dir)
	}
	if strings.TrimSpace(o.Token) == "" {
		return nil, "", fmt.Errorf("%w: --token names the HSM's token (its label)", ErrInvalidRequest)
	}
	if strings.TrimSpace(o.PINFile) == "" {
		return nil, "", fmt.Errorf("%w: --pin-file names a file holding the token's user PIN", ErrInvalidRequest)
	}
	b, err := os.ReadFile(o.PINFile)
	if err != nil {
		return nil, "", fmt.Errorf("%w: the PIN file: %v", ErrInvalidRequest, err)
	}
	pin := strings.TrimSpace(string(b))
	if pin == "" {
		return nil, "", fmt.Errorf("%w: the PIN file is empty", ErrInvalidRequest)
	}
	return &VaultHSM{Dir: dir, Lib: lib}, pin, nil
}

// vaultTakeBack undoes a setup that failed: its containers, the database's
// volume (which may hold a role under a password now forgotten), the token
// and the secrets.
func vaultTakeBack() {
	removeContainer(vaultSvcContainer)
	removeContainer(vaultDBContainer)
	quiet("docker", "volume", "rm", "-f", VaultDBVolume)
	quiet("docker", "network", "rm", VaultNetwork, VaultHSMNetwork)
	_ = os.Remove(vaultConfigPath())
	if d := vaultPath(); strings.HasSuffix(d, string(filepath.Separator)+"vault") {
		_ = os.RemoveAll(d)
	}
}

// vaultUser runs the service as the engine's own user, so the socket it makes
// is the engine's, and nobody else on the machine can open it.
func vaultUser() string { return fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()) }

// VaultImage is the vault service's image (FOX_VAULT_IMAGE overrides).
func VaultImage() string {
	if o := strings.TrimSpace(brand.Getenv("VAULT_IMAGE")); o != "" {
		return o
	}
	return brand.ImageRepo + "/fox-vault:" + strconv.Itoa(VaultImageRevision)
}

// ensureVaultImage has the vault image on this machine: already here and
// recent enough, pulled, or built from the repository (FOX_VAULT_IMAGE_CONTEXT,
// else a checkout found near the working directory), as the database image
// is.
func ensureVaultImage() (string, error) {
	img := VaultImage()
	override := strings.TrimSpace(brand.Getenv("VAULT_IMAGE")) != ""
	if imageExists(img) && (override || imageRevision(img) >= VaultImageRevision) {
		return img, nil
	}
	fmt.Printf("Fetching image %s…\n", img)
	if run("docker", "pull", img) == nil && (override || imageRevision(img) >= VaultImageRevision) {
		return img, nil
	}
	if override {
		return "", fmt.Errorf("the vault image %s (FOX_VAULT_IMAGE) is not on this machine and could not be pulled", img)
	}
	repo := findVaultRepo(envOr("VAULT_IMAGE_CONTEXT", ""))
	if repo == "" {
		return "", fmt.Errorf("the vault image %s could not be pulled, and no source to build it from was found (set %s to a checkout)",
			img, brand.EnvName("VAULT_IMAGE_CONTEXT"))
	}
	ctx, err := os.MkdirTemp("", "fox-vault-image-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(ctx)
	if err := vaultImageContext(repo, ctx); err != nil {
		return "", err
	}
	fmt.Printf("Building the vault image %s from %s…\n", img, repo)
	if err := run("docker", "build", "-t", img, "-f", filepath.Join(ctx, "enterprise", "vault", "image", "Dockerfile"), ctx); err != nil {
		return "", fmt.Errorf("building the vault image: %w", err)
	}
	return img, nil
}

func findVaultRepo(explicit string) string {
	var cands []string
	if explicit != "" {
		cands = append(cands, explicit)
	}
	if wd, err := os.Getwd(); err == nil {
		for d := wd; ; d = filepath.Dir(d) {
			cands = append(cands, d)
			if filepath.Dir(d) == d {
				break
			}
		}
	}
	for _, c := range cands {
		if fi, err := os.Stat(filepath.Join(c, "enterprise", "vault", "image", "Dockerfile")); err == nil && !fi.IsDir() {
			if _, err := os.Stat(filepath.Join(c, "go.mod")); err == nil {
				return c
			}
		}
	}
	return ""
}

// vaultImageContext copies what the service is built from, as
// enterprise/vault/image/context.sh does: go.mod, go.sum, and the vault and
// Aadhaar-check packages without their tests.
func vaultImageContext(repo, out string) error {
	for _, f := range []string{"go.mod", "go.sum"} {
		if err := copyFile(filepath.Join(repo, f), filepath.Join(out, f)); err != nil {
			return err
		}
	}
	for _, d := range []string{"idcheck", "vault"} {
		src := filepath.Join(repo, "enterprise", d)
		err := filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(repo, p)
			if e.IsDir() {
				return os.MkdirAll(filepath.Join(out, rel), 0o755)
			}
			if strings.HasSuffix(p, "_test.go") || !e.Type().IsRegular() {
				return nil
			}
			return copyFile(p, filepath.Join(out, rel))
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode().Perm()|0o444)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func ensureVaultNetworks(c *VaultConfig) error {
	if vaultProbe("docker", "network", "inspect", VaultNetwork) != nil {
		if err := run("docker", "network", "create", "--internal", "--subnet", c.Subnet, "--label", managedLabel, VaultNetwork); err != nil {
			return fmt.Errorf("making the vault's network on %s (another network may use it: pick another with %s): %w",
				c.Subnet, brand.EnvName("VAULT_SUBNET"), err)
		}
	}
	if c.HSM != nil {
		if vaultProbe("docker", "network", "inspect", VaultHSMNetwork) != nil {
			if err := run("docker", "network", "create", "--label", managedLabel, VaultHSMNetwork); err != nil {
				return err
			}
		}
	}
	return nil
}

// vaultProbe runs a quick privileged command for its exit status only.
func vaultProbe(name string, args ...string) error {
	_, err := capture(name, args...)
	return err
}

func vaultRunning(name string) bool {
	out, _ := capture("docker", "ps", "--filter", "name=^"+name+"$", "--format", "{{.Names}}")
	return out == name
}

// VaultUp starts an install's vault if it has one: called by `fox start`
// after the rest of the stack. An install whose licence no longer includes
// the vault keeps it, stopped.
func VaultUp() error {
	c, err := LoadVaultConfig()
	if errors.Is(err, ErrVaultNotSetUp) {
		return nil
	}
	if err != nil {
		return err
	}
	if !edition.Has(edition.Vault) {
		fmt.Fprintf(os.Stderr, "note: this install has a vault, but this licence does not include %s, so it was not started\n", edition.Describe(edition.Vault))
		return nil
	}
	img, err := ensureVaultImage()
	if err != nil {
		return err
	}
	if err := ensureVaultNetworks(c); err != nil {
		return err
	}
	return vaultUp(c, img)
}

func vaultUp(c *VaultConfig, img string) error {
	if !vaultRunning(vaultDBContainer) {
		removeContainer(vaultDBContainer)
		args := []string{"run", "-d", "--name", vaultDBContainer, "--network", VaultNetwork, "--ip", c.DBAddr,
			"--label", managedLabel, "--label", vaultLabel,
			"--env-file", vaultPath("db.env"),
			"-v", VaultDBVolume + ":/var/lib/postgresql",
			"-v", vaultPath("db", "pg_hba.conf") + ":/etc/fox-vault-db/pg_hba.conf:ro",
			"-v", vaultPath("db", "init.sh") + ":/docker-entrypoint-initdb.d/10-fox-vault.sh:ro",
		}
		args = append(args, restartPolicy...)
		args = append(args, PostgresImageFor(c.PGMajor), "-c", "hba_file=/etc/fox-vault-db/pg_hba.conf", "-c", "listen_addresses=*")
		if err := run("docker", args...); err != nil {
			return fmt.Errorf("starting the vault database: %w", err)
		}
	}
	if !vaultRunning(vaultSvcContainer) {
		removeContainer(vaultSvcContainer)
		_ = os.Remove(VaultSocket())
		args := []string{"create", "--name", vaultSvcContainer, "--network", VaultNetwork, "--ip", c.SvcAddr,
			"--label", managedLabel, "--label", vaultLabel, "--user", vaultUser(),
			"-v", vaultPath("tokens") + ":/var/lib/fox-vault/tokens",
			"-v", vaultPath("secret") + ":/etc/fox-vault/secret:ro",
			"-v", vaultPath("run") + ":/run/fox-vault",
		}
		lib := vaultSoftLib
		if c.HSM != nil {
			args = append(args, "-v", c.HSM.Dir+":/opt/hsm")
			lib = filepath.ToSlash(filepath.Join("/opt/hsm", c.HSM.Lib))
			if _, err := os.Stat(vaultPath("hsm.env")); err == nil {
				args = append(args, "--env-file", vaultPath("hsm.env"))
			}
		}
		args = append(args, restartPolicy...)
		args = append(args, img, "serve", "--pkcs11-lib", lib, "--token", c.Token)
		// Captured, not streamed: each prints an id or a name nobody needs.
		if out, err := captureCombined("docker", args...); err != nil {
			return fmt.Errorf("making the vault service: %w: %s", err, strings.TrimSpace(out))
		}
		if c.HSM != nil {
			if out, err := captureCombined("docker", "network", "connect", VaultHSMNetwork, vaultSvcContainer); err != nil {
				return fmt.Errorf("joining the vault service to %s: %w: %s", VaultHSMNetwork, err, strings.TrimSpace(out))
			}
		}
		if out, err := captureCombined("docker", "start", vaultSvcContainer); err != nil {
			return fmt.Errorf("starting the vault service: %w: %s", err, strings.TrimSpace(out))
		}
	}
	// The service waits up to a minute for its database; this waits a little
	// longer for the socket.
	deadline := time.Now().Add(100 * time.Second)
	for {
		if fi, err := os.Stat(VaultSocket()); err == nil && fi.Mode()&fs.ModeSocket != 0 && vaultRunning(vaultSvcContainer) {
			if _, err := vaultStatusRaw(); err == nil {
				return nil
			}
		}
		if time.Now().After(deadline) {
			logs, _ := captureCombined("docker", "logs", "--tail", "5", vaultSvcContainer)
			return fmt.Errorf("the vault service did not answer on %s within 100s: %s", VaultSocket(), strings.TrimSpace(logs))
		}
		time.Sleep(time.Second)
	}
}

// --- calls -----------------------------------------------------------------

// VaultKind is a kind as the engine shows it.
type VaultKind struct {
	Name        string `json:"name"`
	Prefix      string `json:"prefix"`
	Check       string `json:"check"`
	Legacy      string `json:"legacy,omitempty"`
	Rules       string `json:"rules,omitempty"`
	HSMRequired bool   `json:"hsm_required"`
}

// Vaulter is the vault's Enterprise half: the client of the service and its
// kinds. enterprise/vault sets it.
type Vaulter struct {
	// Call makes one call, the request body as JSON, and returns the reply's
	// body, the access log's head after it ("" when the call wrote no entry)
	// and the HTTP status.
	Call func(socket, secret, actor, path string, body []byte) (reply []byte, head string, code int, err error)
	// Status is the service's status, as JSON.
	Status func(socket, secret string) ([]byte, error)
	// LogAt is the head as it was at entry seq; found false when the access
	// log does not hold that entry.
	LogAt func(socket, secret string, seq int64) (head string, found bool, err error)
	Kinds func() []VaultKind
}

var vaulter *Vaulter

// SetVaulter installs the vault's Enterprise half.
func SetVaulter(v *Vaulter) { vaulter = v }

func requireVault() error {
	if err := requireFeature(edition.Vault); err != nil {
		return err
	}
	if vaulter == nil {
		return notLicensed{edition.Vault}
	}
	if !VaultSetUp() {
		return ErrVaultNotSetUp
	}
	return nil
}

func vaultSecret() (string, error) {
	b, err := os.ReadFile(vaultPath("secret", "secret"))
	if err != nil {
		return "", fmt.Errorf("the vault's secret: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// VaultKinds lists the kinds this build knows.
func VaultKinds() ([]VaultKind, error) {
	if err := requireFeature(edition.Vault); err != nil {
		return nil, err
	}
	if vaulter == nil {
		return nil, notLicensed{edition.Vault}
	}
	return vaulter.Kinds(), nil
}

// vaultRequest is what the engine reads of a call, to log it.
type vaultRequest struct {
	Kind    string   `json:"kind"`
	Values  []string `json:"values"`
	Refs    []string `json:"refs"`
	Purpose string   `json:"purpose"`
}

type vaultReply struct {
	Results []string `json:"results"`
	Error   string   `json:"error"`
}

// VaultCall passes one call to the service, as actor, and records it in the
// install's security log with the access log's head after it (design,
// section 10): never a value, only the kind, how many, the results, the
// purpose and the head.
func VaultCall(st *auth.Store, actor, ip, path string, body []byte) ([]byte, int, error) {
	if err := requireVault(); err != nil {
		return nil, 0, err
	}
	switch path {
	case "tokenise", "find", "detokenise":
	default:
		return nil, 0, fmt.Errorf("%w: no vault call %q", ErrInvalidRequest, path)
	}
	var req vaultRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, 0, fmt.Errorf("%w: the body is not a vault request", ErrInvalidRequest)
	}
	secret, err := vaultSecret()
	if err != nil {
		return nil, 0, err
	}
	reply, head, code, err := vaulter.Call(VaultSocket(), secret, actor, path, body)
	if err != nil && code == 0 {
		return nil, 0, fmt.Errorf("the vault service: %w", err)
	}
	var r vaultReply
	_ = json.Unmarshal(reply, &r)
	n := len(req.Values) + len(req.Refs)
	detail := fmt.Sprintf("%s, %d %s: %s", path, n, vaultPlural(n, "value", "values"), vaultSummary(r))
	if path == "detokenise" {
		detail = fmt.Sprintf("detokenise, %d reference %s, purpose %q: %s", n, vaultPlural(n, "key", "keys"), strings.TrimSpace(req.Purpose), vaultSummary(r))
	}
	if head != "" {
		detail += "; head " + head
	}
	st.Audit(auth.EvVaultCall, actor, req.Kind, ip, detail)
	return reply, code, nil
}

func vaultPlural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func vaultSummary(r vaultReply) string {
	if r.Error != "" {
		return "refused: " + r.Error
	}
	count := map[string]int{}
	var order []string
	for _, x := range r.Results {
		if count[x] == 0 {
			order = append(order, x)
		}
		count[x]++
	}
	parts := make([]string, 0, len(order))
	for _, x := range order {
		parts = append(parts, fmt.Sprintf("%s %d", x, count[x]))
	}
	if len(parts) == 0 {
		return "no results"
	}
	return strings.Join(parts, ", ")
}

func vaultStatusRaw() ([]byte, error) {
	if vaulter == nil {
		return nil, notLicensed{edition.Vault}
	}
	secret, err := vaultSecret()
	if err != nil {
		return nil, err
	}
	return vaulter.Status(VaultSocket(), secret)
}

// VaultState is the vault as `fox vault status` and the console show it.
type VaultState struct {
	SetUp     bool            `json:"set_up"`
	Config    *VaultConfig    `json:"config,omitempty"`
	Database  bool            `json:"database_running"`
	Service   bool            `json:"service_running"`
	Image     string          `json:"image,omitempty"`
	Status    json.RawMessage `json:"status,omitempty"`
	StatusErr string          `json:"status_error,omitempty"`
	Anchor    VaultAnchor     `json:"anchor"`
}

// VaultAnchor compares the access log's head as the security log last saw it
// with the access log now: a chain shows an entry changed or removed from its
// middle, and this shows entries cut off its end (design, section 10).
type VaultAnchor struct {
	// Recorded is the head the security log last saw, "" when it saw none.
	Recorded string `json:"recorded,omitempty"`
	// Holds is false when the access log no longer holds that entry as it was.
	Holds bool   `json:"holds"`
	Note  string `json:"note"`
}

// VaultStatus reads the vault's state, and checks its access log against the
// head the security log keeps.
func VaultStatus(st *auth.Store) (*VaultState, error) {
	if err := requireFeature(edition.Vault); err != nil {
		return nil, err
	}
	s := &VaultState{SetUp: VaultSetUp()}
	if !s.SetUp {
		return s, nil
	}
	c, err := LoadVaultConfig()
	if err != nil {
		return nil, err
	}
	s.Config = c
	s.Image = VaultImage()
	s.Database = vaultRunning(vaultDBContainer)
	s.Service = vaultRunning(vaultSvcContainer)
	if vaulter == nil {
		return s, nil
	}
	raw, err := vaultStatusRaw()
	if err != nil {
		s.StatusErr = err.Error()
		s.Anchor.Note = "the vault service did not answer, so its log was not checked"
		return s, nil
	}
	s.Status = raw
	s.Anchor = vaultCheckAnchor(st)
	return s, nil
}

func vaultCheckAnchor(st *auth.Store) VaultAnchor {
	ev, err := st.LastSecurityEventOfKind(auth.EvVaultCall)
	if err != nil {
		return VaultAnchor{Note: "the security log could not be read: " + err.Error()}
	}
	// Only calls to this vault count: one set up again (after its state was
	// removed by hand) starts a log of its own.
	if setup, err := st.LastSecurityEventOfKind(auth.EvVaultSetup); err == nil && setup != nil && ev != nil && ev.ID < setup.ID {
		ev = nil
	}
	recorded := ""
	if ev != nil {
		if i := strings.LastIndex(ev.Detail, "; head "); i >= 0 {
			recorded = strings.TrimSpace(ev.Detail[i+len("; head "):])
		}
	}
	if recorded == "" {
		return VaultAnchor{Holds: true, Note: "no call to the vault is in the security log yet"}
	}
	a, b, ok := strings.Cut(recorded, ":")
	seq, err := strconv.ParseInt(a, 10, 64)
	if !ok || err != nil || len(b) != 64 {
		return VaultAnchor{Recorded: recorded, Note: "the head in the security log cannot be read"}
	}
	secret, err := vaultSecret()
	if err != nil {
		return VaultAnchor{Recorded: recorded, Note: err.Error()}
	}
	now, found, err := vaulter.LogAt(VaultSocket(), secret, seq)
	switch {
	case err != nil:
		return VaultAnchor{Recorded: recorded, Note: "the vault's log could not be read: " + err.Error()}
	case !found:
		return VaultAnchor{Recorded: recorded, Note: fmt.Sprintf("the security log saw entry %d, which the vault's access log no longer holds: entries were cut off its end", seq)}
	case now != recorded:
		return VaultAnchor{Recorded: recorded, Note: fmt.Sprintf("entry %d of the vault's access log is not what the security log saw", seq)}
	}
	return VaultAnchor{Recorded: recorded, Holds: true, Note: fmt.Sprintf("entry %d is as the security log saw it", seq)}
}
