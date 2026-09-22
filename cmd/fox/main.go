// SPDX-License-Identifier: AGPL-3.0-or-later

// Command fox is the control CLI for the FoxByte serverless-Postgres
// platform. It runs inside the Linux dev VM (ZFS + Docker) and manages the
// unified stack: object storage (MinIO), the primary Postgres ("main") with WAL
// archiving, point-in-time restore, and instant copy-on-write branches.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/agentapi"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/controlplane"
	"github.com/thefoxbyte/foxbyte/internal/daemon"
	"github.com/thefoxbyte/foxbyte/internal/host"
	"github.com/thefoxbyte/foxbyte/internal/mcp"
	"github.com/thefoxbyte/foxbyte/internal/proxy"
	"github.com/thefoxbyte/foxbyte/internal/version"
	"github.com/thefoxbyte/foxbyte/web"
)

// background services managed by `start`/`stop` (name -> subcommand + flags).
var services = map[string][]string{
	"controlplane": {"controlplane", "--addr", listenAddr("8080")},
	"gateway":      {"gateway", "--addr", listenAddr("6432"), "--idle", "2m"},
	"api":          {"serve", "--addr", listenAddr("8088")},
}

// listenAddr is where a service listens: on this machine only, unless
// FOX_LISTEN names another address (0.0.0.0 for every interface). On macOS and
// Windows the services run in a VM whose loopback ports are forwarded to the
// host's own loopback, so the default reaches them from the host and from
// nowhere else. On a Linux server, exposing them is a decision to make with
// FOX_LISTEN, behind TLS and a firewall — not something a fresh install does.
func listenAddr(port string) string {
	host := strings.TrimSpace(brand.Getenv("LISTEN"))
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

const usage = `FoxByte — serverless Postgres control CLI

Usage:
  fox <command> [args]

Setup:
  setup                One-time: create/start the local engine VM (macOS: Lima, Windows: WSL2) and bring the stack up
  vm [status|shell]    The engine VM (macOS: Lima, Windows: WSL2): its state and size, or a shell inside it
  uninstall [--keep-data] [--yes]
                       Remove FoxByte from this machine: containers, storage, state and the command
  update [--check]     Install the newest release: new engine, restarted servers, Blackbox upgrades — data untouched
                       (--yes skips the confirmation, --version vX.Y.Z picks a release)

Stack:
  start                Bring EVERYTHING up in the background: stack + gateway + APIs
  stop                 Stop background servers and all containers
  up                   Bring up the stack: network + MinIO + primary 'main' (archiving)
  down                 Stop MinIO and all Postgres containers (ZFS data preserved)
  status               Show servers, main readiness, stored backups, and branches
  logs [gateway|api]   Print a background server's log
  psql                 Open a psql shell on the primary 'main'

Durability / time-travel:
  backup create        Base backup of 'main' -> object storage
  backup list          List base backups in object storage
  restore --to <ts>    PITR into a disposable container on port 5433 (ts or 'latest')
  backup export [--out <file>] [--branch <name>]...
                       Portable copy of every non-agent branch (pg_dump + roles + Blackbox),
                       verified, on this machine; it survives a PostgreSQL major change
  backup restore <file> [--branch <name>] --as <new>
                       Restore one branch of an export into a new branch

PostgreSQL versions:
  pg status            Which PostgreSQL this install and each branch run
  pg upgrade [--dry-run] [--yes] [--export <file> | --i-have-a-backup]
                       Move this install to the PostgreSQL this fox ships: shows every
                       change first, takes an export, keeps the old databases
  pg upgrade --rollback | --finalize
                       Go back to the kept databases, or delete them

Branching:
  branch create <name> [--from <branch>]  Instant copy-on-write branch of main, or of another branch
  branch list           List branches and their containers
  branch delete <name>  Stop and destroy a branch
  branch owner <name> [email]  Show who owns a branch, or give it to an account
  branch reset <name>   Re-clone from parent, discarding everything done on it
  branch suspend <name> Stop a branch (data preserved); resumes on next connect
  branch resume <name>  Start a suspended branch
  branch diff <a> <b>   Schema changes made on each branch since they split (from Blackbox; --json)

Blackbox — the database's record of every schema change (RECORD layer; fox ledger … works too):
  blackbox [branch] [--limit N]   Show captured DDL changes — attributed & policy-checked
  blackbox verify [branch]        Verify the tamper-evident hash chain is intact
  blackbox upgrade [branch|--all] Apply the current Blackbox definition to existing branches
  blackbox checkpoint [branch]    Anchor new entries outside the database (Merkle checkpoint)
  blackbox integrity [branch]     Check the record against its anchors (detects rewritten history)
  blackbox export [branch]        Write every entry as JSON lines (for fox-verify / audits)
  blackbox entries [branch]       Newest entries with their ids (--limit N)
  blackbox sessions [branch]      Agent sessions: agent, task, parent session, entries (--limit N)
  blackbox diff <a> <b>           Changes on each branch since they split, and objects both changed (--json)
  blackbox branch-before <id>     New branch of main as it was just before entry <id> (--as name)
  blackbox revert --to <ts>       Point-in-time restore of main into a disposable container on :5433 (same as fox restore)

Blackbox policy gate — checks every schema change before it runs (docs/policy-errors.md):
  policy [list] [--branch b]      Show the rules: action (warn|block) and whether enabled
  policy check "<SQL>"            Preview the rules a statement would trigger (exit 1 if one blocks)
  policy block|warn <rule>        Refuse matching changes (BBX01) or only warn about them (BBX02)
  policy enable|disable <rule>    Turn a rule on or off
  policy add <rule> --command "ALTER TABLE" [--pattern <regex>] [--block] --reason "…" [--hint "…"]
  policy remove <rule>            Remove a rule you added (built-in rules can only be disabled)
  policy evaluations [--limit N]  Recent warnings, blocks and overrides

Impact analysis — what a change would affect, before you run it:
  impact "<SQL>" [--branch b]     Dependents (views, foreign keys, indexes, …), other branches, policy, score
  impact --object <name> [--column c]   The same for a table, view or index directly (--json for JSON)

Migration:
  import --from <src> [--as <name>]  Migrate a DB into a new instance. <src> is a
                       connection string — postgres://, mysql://, mariadb://, mongodb:// —
                       or a .sql / .csv / .json file (picked from anywhere)
  import --from <pg-dsn> --continuous [--as <name>]
                       Continuous logical replication from a Postgres source
                       (initial copy + streaming) for zero-downtime cutover
  import-cutover <name>  Stop replication for a --continuous instance, keeping its data
  pipeline run <spec.json> [--as <name>]  Run an ETL pipeline (extract → land raw →
                       SQL transform models → data-quality tests) into a fresh instance

High availability:
  ha enable            Provision a hot standby streaming from main
  ha status            Show replication status (primary + standby)
  ha failover          Promote the standby to primary (reroutes 'main')
  ha disable           Remove the standby
  ha failback          After a failover: move 'main' back to its own container, keeping every write

Serverless front door:
  gateway [--addr :6432] [--idle 2m]
                       Smart SQL gateway: reads dbname=<branch> and routes to it,
                       auto-resuming suspended branches, auto-suspending idle ones (--idle 0 = off)
  controlplane [--addr :8080]
                       Control-plane REST API (JSON; the web UI is a separate app in web/)

Agent Branch API:
  serve [--addr :8088] Run the HTTP API: one database branch per AI agent
  mcp [--key <key_…>]  Run the MCP server on stdio: an agent framework gets a database,
                       runs SQL, sees what it changed (Blackbox), and throws it away.
                       Needs an API key (FOX_API_KEY or --key); a key scoped
                       to one branch limits the server to that branch

Auth (admin):
  user create <email>            Create an account (prompts for a password)
  user list | passwd <email> | delete <email>   List accounts, reset a password, delete an account
  setup-token                    Show the token the web sign-up needs for the first account
  apikey create <email> [name]   Mint an API key (shown once)
  apikey list <email>            List a user's API keys
  apikey revoke <email> <id>     Revoke an API key
  admin grant <email> [--branch <name>]   Let a user override the destructive-DDL guardrail
  admin revoke <email> [--branch <name>]  Remove that permission
  admin list [--branch <name>]            Show who may override (default: main + running branches)

  version              Print the fox version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}

	// On macOS/Windows, forward engine commands into the managed Linux VM so the
	// user only ever runs `fox …`. On Linux (or inside the VM) this is a no-op.
	if handled, err := host.Maybe(os.Args[1:]); handled {
		must(err)
		return
	}

	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Printf("fox %s\n", version.Version)
	case "setup":
		must(host.Setup())
	case "vm":
		must(host.VM(os.Args[2:]))
	case "uninstall":
		must(host.Uninstall(os.Args[2:]))
	case "start":
		// Linux host: look for a newer release while the stack starts. (macOS and
		// Windows check on the host before forwarding; the guest never checks.)
		notice := func() {}
		if brand.Getenv("IN_GUEST") == "" {
			notice = host.StartUpdateNotice()
		}
		must(branch.Up())
		for name, args := range services {
			must(daemon.Start(name, args))
		}
		fmt.Println("\nFoxByte is up (background):")
		if web.FS() != nil {
			fmt.Println("  web UI       https://localhost:8080")
		}
		fmt.Println("  control API  https://localhost:8080/api/status")
		fmt.Println("  agent API    https://localhost:8088   (POST /agents/{id}/branch)")
		fmt.Println("  gateway(SQL) postgresql://dbadmin:<API_KEY>@localhost:6432/<branch>?sslmode=require")
		fmt.Println("  storage      http://localhost:9001   (console login in ~/.fox/secrets.json)")
		if web.FS() == nil {
			fmt.Println("\nThe web UI isn't embedded in this build — run it with:  make web-dev   (http://localhost:5173)")
		}
		// No account and no key are created here. A key is a credential: it
		// should be made by the person who will use it, once they have signed
		// in, not minted by a background service and left in a file.
		firstRunNotice()
		fmt.Println("\nFor the connection string above, make an API key: the API keys page in the")
		fmt.Println("web UI, or `fox apikey create <email> <name>`. It is shown once.")
		fmt.Println("Stop everything with: fox stop")
		notice()
	case "update":
		updateCmd(os.Args[2:])
	case "_update-guest": // the engine-side steps of `fox update`
		updateGuestCmd(os.Args[2:])
	case "stop":
		for name := range services {
			daemon.Stop(name)
		}
		must(branch.Down())
		fmt.Println("stopped: control API, agent API, gateway, and all containers")
	case "logs":
		svc := "gateway"
		if len(os.Args) > 2 {
			svc = os.Args[2]
		}
		b, err := os.ReadFile(daemon.LogPath(svc))
		if err != nil {
			fmt.Printf("no log for %q yet\n", svc)
		} else {
			fmt.Print(string(b))
		}
	case "up":
		must(branch.Up())
	case "down":
		for name := range services {
			daemon.Stop(name)
		}
		must(branch.Down())
	case "status":
		fmt.Println("=== servers ===")
		fmt.Printf("control API: %s\n", daemon.Status("controlplane"))
		fmt.Printf("gateway: %s\n", daemon.Status("gateway"))
		fmt.Printf("agent API: %s\n", daemon.Status("api"))
		fmt.Println()
		must(branch.Status())
	case "psql":
		must(branch.PsqlShell("main"))
	case "backup":
		if len(os.Args) < 3 {
			fmt.Println("usage: fox backup <create|list|export|restore>")
			os.Exit(2)
		}
		switch os.Args[2] {
		case "create":
			must(branch.Backup())
		case "list":
			must(branch.BackupList())
		case "export":
			must(exportCmd(os.Args[3:], true))
		case "restore":
			a, err := host.ParseRestoreArgs(os.Args[3:])
			must(err)
			must(branch.RestoreExport(a.File, a.Branch, a.As))
			fmt.Printf("Restored %s from %s into the new branch %q.\n", a.Branch, a.File, a.As)
		default:
			fmt.Printf("unknown backup subcommand: %s\n", os.Args[2])
			os.Exit(2)
		}
	case "_export-guest": // the VM's half of `fox backup export` from a host
		must(exportCmd(os.Args[2:], false))
	case "pg", "postgres":
		pgCmd(os.Args[2:])
	case "_pg-upgrade-plan": // the VM's halves of `fox pg upgrade` from a host
		os.Exit(pgPlan())
	case "_pg-upgrade-apply":
		must(branch.ApplyUpgrade())
	case "_pg-rollback-plan":
		must(showRollback())
	case "_pg-rollback":
		must(branch.RollbackUpgrade())
	case "_pg-finalize-plan":
		must(branch.ShowFinalize(os.Stdout))
	case "_pg-finalize":
		must(branch.FinalizeUpgrade())
	case "restore":
		ts := restoreArg(os.Args[2:])
		if ts == "" {
			fmt.Println("usage: fox restore --to '<timestamp>'|latest")
			os.Exit(2)
		}
		must(branch.Restore(ts))
	case "branch":
		branchCmd(os.Args[2:])
	case "impact":
		impactCmd(os.Args[2:])
	case "ledger", "blackbox": // Blackbox is the product name; both commands work
		ledgerCmd(os.Args[2:])
	case "import":
		importCmd(os.Args[2:])
	case "import-cutover":
		if len(os.Args) < 3 {
			fmt.Println("usage: fox import-cutover <instance>")
			os.Exit(2)
		}
		must(branch.ImportCutover(os.Args[2]))
	case "pipeline":
		pipelineCmd(os.Args[2:])
	case "ha":
		haCmd(os.Args[2:])
	case "user":
		userCmd(os.Args[2:])
	case "setup-token":
		setupTokenCmd()
	case "_first-run": // Windows setup captures `start`'s output, so it asks for this part again
		firstRunNotice()
	case "apikey":
		apikeyCmd(os.Args[2:])
	case "admin":
		adminCmd(os.Args[2:])
	case "policy":
		policyCmd(os.Args[2:])
	case "serve":
		must(agentapi.Serve(addrFlag(os.Args[2:], listenAddr("8088"))))
	case "controlplane":
		must(controlplane.Serve(addrFlag(os.Args[2:], listenAddr("8080"))))
	case "gateway":
		// The internal package is still named "proxy"; the user-facing command is "gateway".
		must(proxy.Serve(addrFlag(os.Args[2:], listenAddr("6432")), durFlag(os.Args[2:], "--idle", 2*time.Minute)))
	case "mcp":
		// MCP server on stdio: an agent framework drives branches + the ledger.
		// It acts as an API key's account, so the key comes first.
		must(mcp.Serve(mcpKey(os.Args[2:])))
	default:
		fmt.Printf("unknown command: %s\n\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(2)
	}
}

// mcpKey is the API key `fox mcp` acts as: `--key <key_…>`, else
// FOX_API_KEY. A key on the command line is visible in the process list,
// so the environment variable is what a client config should use -- but the
// flag stays, for trying the server by hand.
func mcpKey(args []string) string {
	if k := optValue(args, "--key"); k != "" {
		return k
	}
	return brand.Getenv("API_KEY")
}

// restoreArg accepts either `--to <ts>` or a bare `<ts>`.
func restoreArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	if args[0] == "--to" {
		if len(args) < 2 {
			return ""
		}
		return args[1]
	}
	return args[0]
}

// importCmd handles `fox import --from <source> [--as <instance>]`, migrating a
// Postgres source or a .sql/.csv/.json file into a fresh FoxByte instance.
func importCmd(args []string) {
	var source, target, kind, srcname string
	var continuous bool
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--continuous":
			continuous = true
		case "--from":
			if i+1 < len(args) {
				source, i = args[i+1], i+1
			}
		case "--as", "--to":
			if i+1 < len(args) {
				target, i = args[i+1], i+1
			}
		case "--kind": // for streamed (--from -) imports: sql|csv|json
			if i+1 < len(args) {
				kind, i = args[i+1], i+1
			}
		case "--srcname": // origin name for a streamed import (default target/table)
			if i+1 < len(args) {
				srcname, i = args[i+1], i+1
			}
		default:
			if source == "" && !strings.HasPrefix(args[i], "-") {
				source = args[i]
			}
		}
	}
	if source == "" {
		fmt.Println("usage: fox import --from <postgres://… | file.sql|.csv|.json> [--as <instance>]")
		os.Exit(2)
	}
	// A dash means the file is streamed on stdin (used when the launcher forwards
	// a local file from the client machine into the VM).
	if source == "-" {
		k, err := branch.ParseKind(kind)
		must(err)
		if srcname == "" {
			srcname = "stdin"
		}
		_, err = branch.ImportReader(os.Stdin, k, srcname, target)
		must(err)
		return
	}
	if continuous {
		_, err := branch.ImportContinuous(source, target)
		must(err)
		return
	}
	_, err := branch.Import(source, target)
	must(err)
}

// pipelineCmd handles `fox pipeline run <spec.json> [--as <instance>]`: an ETL
// pipeline (extract → land raw → SQL transforms → tests) into a fresh instance.
func pipelineCmd(args []string) {
	if len(args) < 2 || args[0] != "run" {
		fmt.Println("usage: fox pipeline run <spec.json> [--as <instance>]")
		os.Exit(2)
	}
	specPath, target := args[1], ""
	for i := 2; i < len(args); i++ {
		if args[i] == "--as" && i+1 < len(args) {
			target, i = args[i+1], i+1
		}
	}
	b, err := os.ReadFile(specPath)
	must(err)
	var spec branch.PipelineSpec
	must(json.Unmarshal(b, &spec))
	if target == "" {
		target = "pl-" + strings.TrimSuffix(filepath.Base(specPath), filepath.Ext(specPath))
	}
	res, err := branch.RunPipeline(&branch.Progress{Log: os.Stdout}, spec, target)
	must(err)
	if res.Failed {
		os.Exit(1)
	}
}

// ledgerCmd handles `fox ledger [branch] [--limit N]` and
// `fox ledger revert --to <ts>` (a point-in-time restore of main, like `fox restore`).
func ledgerCmd(args []string) {
	if ledgerV2Cmd(args) { // checkpoint, integrity, export
		return
	}
	if len(args) > 0 && args[0] == "revert" {
		ts := restoreArg(args[1:])
		if ts == "" {
			fmt.Println("usage: fox ledger revert --to '<timestamp>'|latest")
			os.Exit(2)
		}
		fmt.Println("Restoring main to that moment in a disposable container on :5433 (the same as `fox restore`).")
		fmt.Println("Nothing is reverted: main and every branch stay as they are.")
		must(branch.Restore(ts))
		fmt.Println("For a branch holding main as it was just before a specific change: fox blackbox branch-before <entry id>  (ids: fox blackbox entries)")
		return
	}
	if len(args) > 0 && args[0] == "upgrade" {
		ledgerUpgradeCmd(args[1:])
		return
	}
	if len(args) > 0 && args[0] == "verify" {
		name := "main"
		if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
			name = args[1]
		}
		msg, err := branch.LedgerVerify(name)
		must(err)
		fmt.Println(msg)
		return
	}
	name, limit := "main", 50
	for i := 0; i < len(args); i++ {
		if args[i] == "--limit" && i+1 < len(args) {
			if n, err := strconv.Atoi(args[i+1]); err == nil {
				limit = n
			}
			i++
		} else if !strings.HasPrefix(args[i], "-") {
			name = args[i]
		}
	}
	must(branch.Ledger(name, limit))
}

// addrFlag parses `--addr <addr>`, falling back to def.
func addrFlag(args []string, def string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--addr" {
			return args[i+1]
		}
	}
	return def
}

// durFlag parses `<name> <duration>` (e.g. --idle 90s), falling back to def.
func durFlag(args []string, name string, def time.Duration) time.Duration {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			if d, err := time.ParseDuration(args[i+1]); err == nil {
				return d
			}
		}
	}
	return def
}

// branchCmd dispatches `fox branch <subcommand>`.
func branchCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: fox branch <create|list|delete|owner|reset|suspend|resume> [name]")
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		name := firstPositional(args[1:], "--from")
		if name == "" {
			fmt.Println("usage: fox branch create <name> [--from <branch>]")
			os.Exit(2)
		}
		must(branch.Create(name, optValue(args[1:], "--from")))
		// Made here, it is nobody's but an admin's — even if an account once
		// owned a branch of that name.
		forgetOwner(name)
	case "list":
		must(branch.List())
	case "delete":
		if len(args) < 2 {
			fmt.Println("usage: fox branch delete <name>")
			os.Exit(2)
		}
		must(branch.Delete(args[1]))
		forgetOwner(args[1])
	case "owner":
		branchOwnerCmd(args[1:])
	case "reset":
		if len(args) < 2 {
			fmt.Println("usage: fox branch reset <name> [--from <parent>]")
			os.Exit(2)
		}
		parent := "main"
		for i := 2; i < len(args); i++ {
			if args[i] == "--from" && i+1 < len(args) {
				parent = args[i+1]
				i++
			}
		}
		must(branch.Reset(args[1], parent))
	case "suspend":
		if len(args) < 2 {
			fmt.Println("usage: fox branch suspend <name>")
			os.Exit(2)
		}
		must(branch.Suspend(args[1]))
	case "resume":
		if len(args) < 2 {
			fmt.Println("usage: fox branch resume <name>")
			os.Exit(2)
		}
		must(branch.Wake(args[1]))
	case "diff":
		diffCmd(args[1:])
	default:
		fmt.Printf("unknown branch subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

// haCmd dispatches `fox ha <subcommand>`.
func haCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: fox ha <enable|status|failover|disable|failback>")
		os.Exit(2)
	}
	switch args[0] {
	case "enable":
		must(branch.HAEnable())
	case "status":
		must(branch.HAStatus())
	case "failover":
		must(branch.HAFailover())
	case "disable":
		must(branch.HADisable())
	case "failback":
		must(branch.HAFailback())
	default:
		fmt.Printf("unknown ha subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func openStore() *auth.Store {
	s, err := auth.OpenFromEnv()
	must(err)
	s.OnFirstUser = func(u auth.User) { branch.AdminForFirstAccount(u.Email) }
	return s
}

func foxbyteDir() string { return brand.StateDir() }

func configPath() string { return filepath.Join(foxbyteDir(), "config") }

// firstRunNotice tells the person who started a fresh install how to make its
// first account, with the setup token the sign-up page asks for. Nothing is
// printed once an account exists.
func firstRunNotice() {
	accounts, ok := anyAccount()
	if !ok || accounts {
		return
	}
	tok, err := auth.EnsureSetupToken()
	if err != nil {
		fmt.Printf("\nFirst run: create your account with `%s user create <email>` (no setup token: %v).\n", brand.CLI, err)
		return
	}
	fmt.Println("\nFirst run: create your account at https://localhost:8080 with this setup token:")
	fmt.Println("  " + tok)
	fmt.Printf("(or `%s user create <email>` here). That first account can override the\n", brand.CLI)
	fmt.Printf("destructive-change guardrail. `%s setup-token` shows the token again.\n", brand.CLI)
}

// setupTokenCmd prints the first-run setup token, while the install has no
// account; afterwards there is none.
func setupTokenCmd() {
	accounts, ok := anyAccount()
	if !ok {
		must(fmt.Errorf("cannot open the account store"))
	}
	if accounts {
		fmt.Printf("This install already has its first account, so there is no setup token.\n"+
			"An admin adds accounts with `%s user create <email>`.\n", brand.CLI)
		return
	}
	tok, err := auth.EnsureSetupToken()
	must(err)
	fmt.Println(tok)
}

// anyAccount reports whether this install has any account yet, so the banner
// can tell a first-time user what to do. ok is false if the store cannot be
// opened, in which case the banner simply says less.
func anyAccount() (accounts bool, ok bool) {
	store, err := auth.OpenFromEnv()
	if err != nil {
		return false, false
	}
	return store.HasAnyUser(), true
}

// branchOwnerCmd is `fox branch owner <name> [email]`: who owns a branch, or
// give it to an account. A branch made here has no owner, so this is how an
// admin hands one to the person who will use it.
func branchOwnerCmd(args []string) {
	if len(args) == 0 || len(args) > 2 {
		fmt.Printf("usage: %s branch owner <name> [email]\n", brand.CLI)
		os.Exit(2)
	}
	name := args[0]
	if !branch.Exists(name) {
		must(fmt.Errorf("no branch %q", name))
	}
	s := openStore()
	defer s.Close()
	if len(args) == 1 {
		uid, ok := s.BranchOwner(name)
		if !ok {
			fmt.Printf("%s has no owner: only admins can reach it\n", name)
			return
		}
		for _, a := range mustAccounts(s) {
			if a.ID == uid {
				fmt.Printf("%s is owned by %s\n", name, a.Email)
				return
			}
		}
		fmt.Printf("%s is owned by account %d, which no longer exists\n", name, uid)
		return
	}
	u, ok := s.UserByEmail(args[1])
	if !ok {
		must(fmt.Errorf("no such user: %s", args[1]))
	}
	must(s.SetBranchOwner(name, u.ID))
	fmt.Printf("%s is now owned by %s\n", name, u.Email)
}

func mustAccounts(s *auth.Store) []auth.Account {
	list, err := s.ListAccounts()
	must(err)
	return list
}

// forgetOwner drops a branch's owner record, for a branch made or deleted at
// the command line. Best-effort: the store may not exist yet.
func forgetOwner(name string) {
	if s, err := auth.OpenFromEnv(); err == nil {
		_ = s.ForgetBranch(name)
		s.Close()
	}
}

// userCmd is `fox user`: accounts, for whoever runs the engine (audit v2 G16).
func userCmd(args []string) {
	usage := func() {
		fmt.Printf("usage: %[1]s user create <email>\n       %[1]s user list\n       %[1]s user passwd <email>\n       %[1]s user delete <email>\n", brand.CLI)
		os.Exit(2)
	}
	if len(args) == 0 {
		usage()
	}
	switch args[0] {
	case "create":
		if len(args) < 2 {
			usage()
		}
		must(userCreate(args[1]))
	case "list":
		list, err := openStore().ListAccounts()
		must(err)
		fmt.Printf("%-4s  %-40s  %-10s  %4s  %8s\n", "ID", "EMAIL", "CREATED", "KEYS", "BRANCHES")
		for _, a := range list {
			fmt.Printf("%-4d  %-40s  %-10s  %4d  %8d\n", a.ID, a.Email, time.Unix(a.Created, 0).Format("2006-01-02"), a.Keys, a.Branches)
		}
	case "passwd":
		if len(args) < 2 {
			usage()
		}
		fmt.Print("new password (min 8 chars): ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		must(openStore().ResetPassword(args[1], strings.TrimSpace(line)))
		fmt.Printf("password changed for %s; its sessions were signed out\n", args[1])
	case "delete":
		if len(args) < 2 {
			usage()
		}
		s := openStore()
		u, ok := s.UserByEmail(args[1])
		if !ok {
			must(fmt.Errorf("no such user: %s", args[1]))
		}
		must(s.DeleteAccount(u.ID))
		if err := branch.RevokeAdmin("main", u.Email); err != nil {
			fmt.Fprintf(os.Stderr, "note: could not revoke %s's admin grant on main: %v\n", u.Email, err)
		}
		fmt.Printf("deleted %s: its sessions, keys and pipelines are gone; its branches are now an admin's\n", u.Email)
	default:
		usage()
	}
}

func userCreate(email string) error {
	fmt.Print("password (min 8 chars): ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	pw := strings.TrimSpace(line)
	if len(pw) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	u, err := openStore().CreateUser(email, pw)
	if err != nil {
		return err
	}
	fmt.Printf("created user %s (id %d)\n", u.Email, u.ID)
	return nil
}

func apikeyCmd(args []string) {
	if len(args) < 2 {
		fmt.Println("usage: fox apikey <create|list|revoke> <email> [name|id]")
		os.Exit(2)
	}
	s := openStore()
	u, ok := s.UserByEmail(args[1])
	if !ok {
		must(fmt.Errorf("no such user: %s (create it with: fox user create %s)", args[1], args[1]))
	}
	switch args[0] {
	case "create":
		name := "key"
		if len(args) > 2 {
			name = args[2]
		}
		secret, info, err := s.CreateAPIKey(u.ID, name)
		must(err)
		fmt.Printf("API key %q created — copy it now, it won't be shown again:\n\n  %s\n", info.Name, secret)
	case "list":
		keys, err := s.ListKeys(u.ID)
		must(err)
		if len(keys) == 0 {
			fmt.Println("no API keys")
			return
		}
		for _, k := range keys {
			fmt.Printf("  %s  %-16s  %s…\n", k.ID, k.Name, k.Prefix)
		}
	case "revoke":
		if len(args) < 3 {
			fmt.Println("usage: fox apikey revoke <email> <id>")
			os.Exit(2)
		}
		must(s.RevokeKey(u.ID, args[2]))
		fmt.Println("revoked")
	default:
		fmt.Printf("unknown apikey subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

// exportCmd writes an export where --out says (by default into the state
// directory) and, when announce is set, says where it went. The VM's half of a
// host export stays quiet about its temporary path: the host names the real one.
func exportCmd(args []string, announce bool) error {
	a, err := host.ParseExportArgs(args)
	if err != nil {
		return err
	}
	out := a.Out
	if out == "" {
		out = host.DefaultExportPath()
	}
	m, err := branch.Export(branch.ExportOptions{Out: out, Branches: a.Branches})
	if err != nil {
		return err
	}
	if _, err := branch.ReadExport(out, ""); err != nil {
		return fmt.Errorf("the export was written but does not verify: %w", err)
	}
	if announce {
		fmt.Printf("Export written to %s — %d branch(es), verified.\n", out, len(m.Branches))
	}
	return nil
}

// pgPlan prints the upgrade plan and returns the exit status the host reads:
// 0 ready, 1 refused, host.PlanExitUpToDate nothing to do.
func pgPlan() int {
	p, err := branch.PlanUpgrade()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	p.Render(os.Stdout)
	switch {
	case p.UpToDate():
		return host.PlanExitUpToDate
	case len(p.Refusals()) > 0:
		return 1
	}
	return 0
}

func showRollback() error {
	r, err := branch.PlanRollback()
	if err != nil {
		return err
	}
	r.Render(os.Stdout)
	return nil
}

// pgCmd is `fox pg …` on Linux and inside the VM; on a host, `pg upgrade` is
// run by host.Maybe, which forwards each step here.
func pgCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: fox pg <status|upgrade>")
		os.Exit(2)
	}
	switch args[0] {
	case "status":
		must(branch.PGStatus(os.Stdout))
	case "upgrade":
		a, err := host.ParsePgUpgradeArgs(args[1:])
		must(err)
		switch {
		case a.Rollback:
			must(host.ConfirmThen(a.UpgradeOptions, showRollback, branch.RollbackUpgrade))
		case a.Finalize:
			must(host.ConfirmThen(a.UpgradeOptions, func() error { return branch.ShowFinalize(os.Stdout) }, branch.FinalizeUpgrade))
		default:
			must(host.RunUpgrade(host.UpgradeSteps{
				Plan: func() error {
					switch pgPlan() {
					case 0:
						return nil
					case host.PlanExitUpToDate:
						return host.ErrUpToDate
					}
					return fmt.Errorf("refusing to upgrade (see above) — nothing was changed")
				},
				Export: func(out string) error { return exportCmd([]string{"--out", out}, true) },
				Apply:  branch.ApplyUpgrade,
			}, a.UpgradeOptions, os.Stdin, os.Stdout))
		}
	default:
		fmt.Printf("unknown pg subcommand: %s\n", args[0])
		os.Exit(2)
	}
}
