// SPDX-License-Identifier: AGPL-3.0-or-later

// Command fox is the control CLI for the FoxByte PostgreSQL branching
// platform. It runs inside the Linux dev VM (ZFS + Docker) and manages the
// unified stack: object storage (MinIO), the primary Postgres ("main") with WAL
// archiving, point-in-time restore, and instant copy-on-write branches.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
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
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/errhint"
	"github.com/thefoxbyte/foxbyte/internal/host"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
	"github.com/thefoxbyte/foxbyte/internal/license"
	"github.com/thefoxbyte/foxbyte/internal/mcp"
	"github.com/thefoxbyte/foxbyte/internal/proxy"
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

const usage = `FoxByte — Postgres branching control CLI

Usage:
  fox <command> [args]

Setup:
  setup                One-time: create/start the local engine VM (macOS: Lima, Windows: WSL2) and bring the stack up
  vm [status|shell]    The engine VM (macOS: Lima, Windows: WSL2): its state and size, or a shell inside it
  uninstall [--keep-data] [--yes]
                       Remove FoxByte from this machine: containers, storage, state and the command
  update [--check]     Install the newest release: new engine, restarted servers, Blackbox upgrades — data untouched
                       (--yes skips the confirmation, --version vX.Y.Z picks a release)
  upgrade --edition enterprise
                       Switch to the Enterprise edition of the version you run (or --edition standard
                       to switch back); shows its licence first — data untouched

Stack:
  start                Bring EVERYTHING up in the background: stack + gateway + APIs
  stop                 Stop background servers and all containers
  up                   Bring up the stack: network + MinIO + primary 'main' (archiving)
  down                 Same as stop: stops the background servers and all containers
                       (ZFS data preserved)
  status               Show servers, main readiness, stored backups, and branches
  check                Check this install and say what to do about anything wrong
  logs [gateway|api]   Print a background server's log
  connect [branch]     Show how an application reaches a branch, then open psql on it
  psql [branch]        Open a psql shell on a branch (default 'main')
  sql [--branch b] [--format table|csv|tsv|markdown|json|insert|xlsx] "<sql>" | -
                       Run SQL and print the result, to read or to paste (--no-header, --raw, --table <t>)
  export [--branch b] [--format csv|tsv|json|xlsx] "<sql>" | - > file
                       Every row a query returns, streamed to a file; read only, and recorded in the security log
  history [--branch b] [--limit n] [--json] [--user <email>] | purge | status | on | off | retention <days>
                       The SQL people ran (console, API, fox sql, fox export), never results; kept 90 days
  schema [--branch b] [<object> [--ddl]] [--search t] [--kind k] [--all] [--json]
                       What a branch holds, and each object's CREATE script (read only)
  track [<table> [--off] [--label-existing] [--created c] [--updated u] [--by col]] [--new on|off] [--branch b]
                       Keep who changed each row and when (created_at, updated_at, last_modified_by)
  pii scan [--branch b] [--sample n] [--json]
                       Find personal data (Aadhaar, PAN, mobile, card, email…) by column names
                       and sampled values; keeps where, never the values (Enterprise)
  pii [findings] [--branch b] [--json]
                       What scans have found on a branch
  demo seed|drop|sql [branch]
                       The sample tables (users, projects, events). A first start
                       seeds main; FOX_NO_DEMO=1 starts empty

Durability / time-travel:
  backup create        Base backup of 'main' -> object storage
  backup list          List base backups in object storage
  backup prune [--keep N]  Delete all but the newest N full backups (the schedule keeps FOX_BACKUP_RETAIN, 7)
  backup verify        Prove a restore works: probe row -> WAL archive -> restore -> read it back
                       (the control plane also does this on a schedule, FOX_RESTORE_CHECK_INTERVAL)
  backup target        Where backups go; set s3://bucket[/prefix] --endpoint <url> --access-key <key> [--region r] [--path-style] [--allow-http]; local
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
  branch request <source> [--to <target>]
                       Offer this branch's schema changes for review, to apply to another
                       branch (default 'main'). Nothing is applied until it is approved.

Promotion — review a branch's changes, then apply them (schema only):
  request list [--open] [--target b]   Change requests, newest first
  request show <id>                    Its statements, in the order they ran
  request approve <id> [--note "…"]    Apply them to the target, in one transaction
  request reject <id> [--note "…"]     Decline; the target is untouched

Blackbox — the database's record of every schema change (RECORD layer; fox ledger … works too):
  blackbox [branch] [--limit N]   Show captured DDL changes — attributed & policy-checked
  blackbox verify [branch]        Verify the tamper-evident hash chain is intact
  blackbox upgrade [branch|--all] Apply the current Blackbox definition to existing branches
  realtime status | setup | teardown | slots   The row-level change feed
  blackbox checkpoint [branch]    Anchor new entries outside the database (Merkle checkpoint)
  blackbox anchor-key             Print the public key anchors are signed with (for fox-verify --pubkey)
  blackbox anchor-target [show | set s3://… | none]
                                  Keep every anchor in a bucket under Object Lock (COMPLIANCE), out of the admin's reach
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

Front door:
  gateway [--addr :6432] [--idle 2m]
                       Smart SQL gateway: reads dbname=<branch> and routes to it,
                       auto-resuming suspended branches, auto-suspending idle ones (--idle 0 = off)
  controlplane [--addr :8080]
                       Control-plane REST API and, in release builds, the web console
                       (development builds serve the console with: make web-dev)

Agent Branch API:
  serve [--addr :8088] Run the HTTP API: one database branch per AI agent
  mcp [--key <key_…>]  Run the MCP server on stdio: an agent framework gets a database,
                       runs SQL, sees what it changed (Blackbox), and throws it away.
                       Needs an API key (FOX_API_KEY or --key); a key scoped
                       to one branch limits the server to that branch

Auth (admin):
  user create <email>            Create an account (prompts for a password)
  user passwd <email>            Set a new password when one is forgotten — a password cannot be
                                 recovered, only replaced. Signs that account out everywhere.
  user list | delete <email>     List accounts, or delete one
  setup-token                    Show the token the web sign-up needs for the first account
  audit [--limit N]              The security log: sign-ins, keys, passwords, accounts, admins, refusals
  audit verify [--pubkey <file>] Check the security log's hash chain, its anchors and their signatures
  audit checkpoint               Anchor the security log's new events now (the control plane does it on a schedule)
  apikey create <email> [name] [--agent]
                                 Mint an API key (shown once); --agent mints
                                 one to give an AI agent, recorded as an agent
  apikey list <email>            List a user's API keys
  apikey revoke <email> <id>     Revoke an API key
  admin grant <email> [--branch <name>]   Let a user override the destructive-DDL guardrail
  admin revoke <email> [--branch <name>]  Remove that permission
  admin list [--branch <name>]            Show who may override (default: main + running branches)
  guardrail limit [--table <t>] [--branch <name>] [<rows>|none]
                                          Show or set how many rows one agent UPDATE/DELETE may change in a table
  guardrail budget [--table <t>] [--per <1h>] [--branch <name>] [<rows>|none]
                                          Show or set how many rows one agent may change in a table per window, across statements

  license [show]       The paid-edition licence, and this machine's fingerprint
  license activate <file|->   Install one  ·  license rebind  ·  license remove

  version              Print the fox version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		fmt.Print(enterpriseUsage())
		os.Exit(2)
	}

	// A licence activated while the VM was down never reached the engine, so
	// bringing the stack up is the second chance `fox license activate` says it
	// is. Before the forward, not after: the engine reads its entitlement once,
	// when it starts.
	//
	// Quiet and best-effort. The case it repairs has already been reported once,
	// and a licence is never a reason a database fails to come up.
	//
	// Reconciled rather than pushed: a licence activated in the console exists
	// only in the engine, and pushing this machine's copy over it would undo an
	// upgrade. The newer activation wins, both ways (syncLicenceWithEngine).
	// On macOS and Windows, an engine switched to the other edition from the
	// console leaves fox here behind. Catch up first, then run the command on
	// the new fox, so its output is the edition the person now has.
	if exe := host.SyncLauncherEdition(os.Args[1]); exe != "" {
		rerun(exe)
	}

	if sub := os.Args[1]; sub == "start" || sub == "up" {
		syncLicenceWithEngine(true)
	}
	// And before `uninstall --keep-data` deletes the VM, whose copy may be the
	// only one: the data being kept includes the licence that unlocks it.
	if os.Args[1] == "uninstall" && hasFlag(os.Args[2:], "--keep-data") {
		syncLicenceWithEngine(false)
	}

	// On macOS/Windows, forward engine commands into the managed Linux VM so the
	// user only ever runs `fox …`. On Linux (or inside the VM) this is a no-op.
	if handled, err := host.Maybe(os.Args[1:]); handled {
		must(err)
		return
	}

	// Past here this process is the engine, so tell internal/edition what the
	// installed licence unlocks. Before here it is the launcher, which forwards
	// rather than runs and has nothing to entitle.
	//
	// Silent on every failure — no licence, no key, lapsed, forged. A refusal
	// belongs where someone asks for a paid feature, which can name the feature
	// and the way out; announcing it on every command would be noise for the
	// Standard installs that are the common case.
	license.Install()

	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Println(versionLine())
	case "setup":
		must(host.Setup())
	case "vm":
		must(host.VM(os.Args[2:]))
	case "uninstall":
		must(host.Uninstall(os.Args[2:]))
	case "license":
		must(licenseCmd(os.Args[2:]))
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
	case "upgrade": // switch edition: Standard ⇄ Enterprise, same version
		upgradeCmd(os.Args[2:])
	case "_edition-switch": // the console's Install button, run detached by the control plane
		editionSwitchCmd(os.Args[2:])
	case "_update-guest": // the engine-side steps of `fox update`
		updateGuestCmd(os.Args[2:])
	case "stop", "down":
		// down is the same command: removing the containers leaves the servers
		// nothing to serve, so it has always stopped them too (#152).
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
	case "status":
		fmt.Println("=== servers ===")
		fmt.Printf("control API: %s\n", daemon.Status("controlplane"))
		fmt.Printf("gateway: %s\n", daemon.Status("gateway"))
		fmt.Printf("agent API: %s\n", daemon.Status("api"))
		fmt.Println()
		must(branch.Status())
	case "psql":
		must(branch.PsqlShell(argOr(os.Args[2:], "main")))
	case "sql":
		sqlCmd(os.Args[2:])
	case "export":
		resultExportCmd(os.Args[2:])
	case "history":
		historyCmd(os.Args[2:])
	case "schema":
		schemaCmd(os.Args[2:])
	case "track":
		trackCmd(os.Args[2:])
	case "pii":
		piiCmd(os.Args[2:])
	case "check":
		checkCmd(os.Args[2:])
	case "connect":
		must(branch.Connect(argOr(os.Args[2:], "main"), hasFlag(os.Args[2:], "--dsn")))
	case "demo":
		demoCmd(os.Args[2:])
	case "backup":
		if len(os.Args) < 3 {
			fmt.Println("usage: fox backup <create|list|prune|verify|target|export|restore>")
			os.Exit(2)
		}
		switch os.Args[2] {
		case "create":
			must(branch.Backup())
		case "list":
			must(branch.BackupList())
		case "prune":
			keep := 7
			if v := optValue(os.Args[3:], "--keep"); v != "" {
				n, err := strconv.Atoi(v)
				if err != nil || n < 1 {
					must(fmt.Errorf("--keep needs a number of at least 1"))
				}
				keep = n
			}
			must(branch.Prune(keep))
		case "verify":
			// Proof rather than argument: write a row, wait for its WAL segment to
			// be archived, restore the newest base backup into a container of its
			// own, and look for the row.
			fmt.Println("Proving a restore works. This restores a full copy of main, so it takes a while.")
			c, err := branch.VerifyRestore(func(f string, a ...any) { fmt.Printf(f, a...) })
			if err != nil {
				must(fmt.Errorf("the backups did not restore: %w", err))
			}
			fmt.Printf("\nOK — restored from %s in %ds, and the probe row was there (%d user table(s)).\nBackups read from %s.\n",
				c.BaseBackup, c.Seconds, c.Tables, c.Target)
		case "target":
			backupTargetCmd(os.Args[3:])
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
	case "request":
		requestCmd(os.Args[2:])
	case "branch":
		branchCmd(os.Args[2:])
	case "impact":
		requireFeature(edition.Impact)
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
		requireFeature(edition.Pipelines)
		pipelineCmd(os.Args[2:])
	case "realtime":
		must(realtimeCmd(os.Args[2:]))
	case "ha":
		haCmd(os.Args[2:])
	case "node":
		nodeCmd(os.Args[2:])
	case "user":
		userCmd(os.Args[2:])
	case "setup-token":
		setupTokenCmd()
	case "audit":
		auditCmd(os.Args[2:])
	case "_first-run": // Windows setup captures `start`'s output, so it asks for this part again
		firstRunNotice()
	case "apikey":
		apikeyCmd(os.Args[2:])
	case "guardrail":
		guardrailCmd(os.Args[2:])
	case "admin":
		adminCmd(os.Args[2:])
	case "policy":
		policyCmd(os.Args[2:])
	// The long-running processes keep their entitlement in step with the
	// licence file (license.Watch), so a licence activated in the console or
	// pushed from the host is honoured by all of them without a restart. The
	// control plane starts its own, because it also records the change in the
	// security log and the store for that is opened inside it.
	case "serve":
		license.Watch(nil)
		must(agentapi.Serve(addrFlag(os.Args[2:], listenAddr("8088"))))
	case "controlplane":
		must(controlplane.Serve(addrFlag(os.Args[2:], listenAddr("8080"))))
	case "gateway":
		license.Watch(nil)
		// The internal package is still named "proxy"; the user-facing command is "gateway".
		must(proxy.Serve(addrFlag(os.Args[2:], listenAddr("6432")), durFlag(os.Args[2:], "--idle", 2*time.Minute)))
	case "mcp":
		license.Watch(nil)
		// MCP server on stdio: an agent framework drives branches + the ledger.
		// It acts as an API key's account, so the key comes first.
		must(mcp.Serve(mcpKey(os.Args[2:])))
	default:
		// The paid edition's commands. In the Standard build this is compiled
		// out and always returns false, so they are not commands that refuse —
		// they are commands that do not exist (cmd/fox/enterprise_off.go).
		if enterpriseCmd(os.Args[1:]) {
			return
		}
		fmt.Printf("unknown command: %s\n\n", os.Args[1])
		fmt.Print(usage)
		fmt.Print(enterpriseUsage())
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
		fmt.Println("usage: fox branch <create|list|delete|owner|reset|suspend|resume|diff|request> [name]")
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		name := firstPositional(args[1:], "--from")
		if name == "" {
			fmt.Println("usage: fox branch create <name> [--from <branch>]")
			os.Exit(2)
		}
		started := time.Now()
		must(branch.Create(name, optValue(args[1:], "--from")))
		// Made here, it is nobody's but an admin's — even if an account once
		// owned a branch of that name.
		forgetOwner(name)
		// Create used to leave the container id docker printed as the last word
		// on the screen. What a person needs is the name, how long it took, and
		// a line they can paste into an application.
		fmt.Printf("\nBranch %q is ready in %s.\n", name, took(started))
		branch.PrintConnectHint(os.Stdout, name)
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
	case "request":
		branchRequestCmd(args[1:])
	default:
		fmt.Printf("unknown branch subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

// haCmd dispatches `fox ha <subcommand>`.
func haCmd(args []string) {
	if len(args) == 0 {
		fmt.Printf("usage: %s ha <enable|status|failover [--force]|disable|failback|sync on|sync off|drill|watch|witness|repair-roles>\n", brand.CLI)
		os.Exit(2)
	}
	switch args[0] {
	case "enable":
		must(branch.HAEnable())
	case "status":
		must(branch.HAStatus())
	case "failover":
		// --force is for a primary on another machine that the operator has
		// already stopped or isolated. It never skips stopping a local one.
		must(branch.HAFailover(hasFlag(args, "--force")))
	case "disable":
		must(branch.HADisable())
	case "failback":
		must(branch.HAFailback())
	case "sync":
		haSyncCmd(args[1:])
	case "drill":
		haDrillCmd(args[1:])
	case "repair-roles":
		haRepairRolesCmd()
	case "watch":
		haWatchCmd(args[1:])
	case "witness":
		haWitnessCmd(args[1:])
	default:
		fmt.Printf("unknown ha subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

// haWatchCmd is automatic failover: it runs on the standby, watches the
// primary, and promotes when a witness agrees the primary has gone.
//
// Deliberately a command somebody starts rather than something the engine does
// by itself. An automatic failover is a decision about data, taken while
// nobody is looking; it should be switched on by a person who has placed a
// witness and knows where it is.
func haWatchCmd(args []string) {
	if hasFlag(args, "-h") || hasFlag(args, "--help") {
		fmt.Printf("usage: %s ha watch --witness <url> [--token T] [--after 60s] [--every 10s] [--once] [--dry-run]\n\n"+
			"Runs on a standby that joined a primary elsewhere. Every round it asks two\n"+
			"questions — can I reach the primary, and can the witness — and promotes only\n"+
			"when both say no for --after. One opinion is never enough: two machines cannot\n"+
			"tell a dead primary from one they cannot reach, and promoting on a guess makes\n"+
			"two primaries whose copies cannot be merged.\n\n"+
			"The witness goes on a third host, where the clients are. `%s ha witness` runs it.\n"+
			"--dry-run prints every decision and acts on none, which is how to try this.\n", brand.CLI, brand.CLI)
		return
	}
	must(branch.Watch(branch.WatchOptions{
		Witness:  optValue(args, "--witness"),
		Token:    optOr(args, "--token", os.Getenv(brand.EnvName("HA_WITNESS_TOKEN"))),
		Interval: durFlag(args, "--every", -1),
		// Negative means "not given", so `--after 0s` can mean what it says:
		// promote as soon as both observers agree, which is how a drill asks.
		After:  durFlag(args, "--after", -1),
		Once:   hasFlag(args, "--once"),
		DryRun: hasFlag(args, "--dry-run"),
	}))
}

// haWitnessCmd runs the witness: the third opinion a promotion needs.
func haWitnessCmd(args []string) {
	primary := optValue(args, "--primary")
	if primary == "" || hasFlag(args, "-h") || hasFlag(args, "--help") {
		fmt.Printf("usage: %s ha witness --primary <host:port> [--addr :7070] [--token T]\n\n"+
			"Answers one question, over HTTP: can this host reach that primary? A standby\n"+
			"running `%s ha watch` promotes only when it and the witness agree that the\n"+
			"primary has gone.\n\n"+
			"Run it on a third host — where the clients are, not beside either database.\n"+
			"A witness that is cut off from the primary alongside the standby will agree\n"+
			"with it about a primary that is still serving somebody else.\n", brand.CLI, brand.CLI)
		os.Exit(2)
	}
	must(branch.ServeWitness(optOr(args, "--addr", ":7070"), primary,
		optOr(args, "--token", os.Getenv(brand.EnvName("HA_WITNESS_TOKEN")))))
}

// haRepairRolesCmd rewrites the role passwords inside the database to the ones
// this install derives from its own secret.
//
// A promotion of a copy taken from another machine does this by itself; this is
// the hand crank for when it could not — the warning it prints names this
// command — and for a copy restored or moved by other means. It needs no
// current password: psql reaches Postgres over the container's socket, which
// the image's pg_hba trusts.
func haRepairRolesCmd() {
	touched, err := branch.RewriteRolePasswords("")
	must(err)
	if len(touched) == 0 {
		fmt.Println("no role here is one this install manages, so nothing was changed.")
		return
	}
	fmt.Printf("rewrote %d role password(s) to this install's own: %s\n",
		len(touched), strings.Join(touched, ", "))
	fmt.Println("clients authenticate at the gateway with an API key, so nothing they hold changes.")
}

// haSyncCmd is zero-data-loss mode: `on` makes every commit wait for the
// standby, `off` releases them. Spelled as two words rather than a flag on
// `ha enable` because it is a decision about what a commit means, taken and
// untaken independently of whether a standby exists.
func haSyncCmd(args []string) {
	if len(args) == 0 {
		fmt.Printf("usage: %s ha sync <on|off>\n\n"+
			"on   a commit is not reported until the standby has it on disk. No write is\n"+
			"     lost if this machine dies, and every write waits for the second one.\n"+
			"off  commits never wait. A lost machine costs up to 60 seconds of writes.\n\n"+
			"`%s ha status` says which is in effect.\n", brand.CLI, brand.CLI)
		os.Exit(2)
	}
	switch args[0] {
	case "on":
		must(branch.SyncEnable())
	case "off":
		must(branch.SyncDisable())
	default:
		fmt.Printf("unknown: %s ha sync %s — expected on or off\n", brand.CLI, args[0])
		os.Exit(2)
	}
}

// haDrillCmd runs a failover drill and writes the report.
//
// It needs --yes because it causes a real outage: the primary is killed without
// warning, which is the only way to measure what that costs. Nothing is lost
// that the standby had received, and the report says so.
func haDrillCmd(args []string) {
	if hasFlag(args, "-h") || hasFlag(args, "--help") {
		fmt.Printf("usage: %s ha drill --yes [--writes N] [--failback]\n"+
			"       %s ha drill --takeover [--wait 10m]      (on the surviving machine)\n\n"+
			"Kills the primary while writes are in flight, promotes the standby through\n"+
			"`%s ha failover`, and reports what it cost: acknowledged writes lost (RPO) and\n"+
			"time until the new primary took a write (RTO).\n\n"+
			"This is an outage. Writes fail from the kill until the promotion completes,\n"+
			"usually a few seconds. No write the standby had already received is lost.\n\n"+
			"  --writes N   rows to write, half of them before the kill (default 400)\n"+
			"  --failback   return to normal running afterwards, and time that too\n\n"+
			"--takeover measures a failover between machines, run on the standby: it waits\n"+
			"for the primary elsewhere to stop answering — you stop it, or it fails — and\n"+
			"then for this machine to serve writes, whether `%s ha watch` promoted it or a\n"+
			"person did. It stops nothing and promotes nothing itself. RTO then includes\n"+
			"noticing, which is the number a client experiences; RPO cannot be measured from\n"+
			"the surviving side and is reported as such rather than guessed at.\n\n"+
			"The report is written to %s and printed.\n",
			brand.CLI, brand.CLI, brand.CLI, brand.CLI, branch.DrillReportDir())
		return
	}
	if hasFlag(args, "--takeover") {
		// No --yes: this drill breaks nothing. It watches, and what it is
		// waiting for is an outage somebody else causes.
		o := branch.DrillOptions{Takeover: true, Wait: durFlag(args, "--wait", 10*time.Minute)}
		r, err := branch.DrillTakeover(o)
		reportDrill(r)
		must(err)
		return
	}
	if !hasFlag(args, "--yes") {
		fmt.Printf("A drill is a real outage: it kills the primary while writes are in flight and\n"+
			"promotes the standby. Writes fail for a few seconds; nothing the standby already\n"+
			"had is lost.\n\nRun it with --yes when you are ready:\n  %s ha drill --yes\n", brand.CLI)
		os.Exit(2)
	}
	writes := 400
	if v := optValue(args, "--writes"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 2 {
			fmt.Fprintf(os.Stderr, "error: --writes %q is not a number of rows above 1\n", v)
			os.Exit(2)
		}
		writes = n
	}
	o := branch.DrillOptions{Writes: writes, Failback: hasFlag(args, "--failback")}
	r, err := branch.Drill(o)
	reportDrill(r)
	must(err)
}

// reportDrill prints and saves a drill's report.
//
// Done even when the drill failed part way, because a drill that went wrong is
// the most interesting kind and the numbers it reached are the evidence of what
// happened. But only once it started: a drill refused for having no standby has
// nothing to report, and a document of zeroes would bury the refusal.
func reportDrill(r branch.DrillResult) {
	if !r.Measured() {
		return
	}
	path, werr := branch.SaveDrillReport(r)
	fmt.Println()
	fmt.Print(r.Report())
	if werr == nil {
		fmt.Printf("\nSaved to %s\n", path)
	}
}

// nodeCmd is `fox node`: letting a standby on another machine reach this
// primary, which is the one thing in the engine that puts Postgres on a
// network. Everything else keeps it off one on purpose.
func nodeCmd(args []string) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Printf("usage: %s node <expose --address A --peer B [--port N] | unexpose | join <token> | leave | status | token>\n\n"+
			"expose     publish this primary for a standby on another machine: TLS with a\n"+
			"           certificate that names --address, admitting only the %s role and\n"+
			"           only from --peer. Restarts main, because a published port is fixed\n"+
			"           when the container is made.\n"+
			"unexpose   take it back off the network.\n"+
			"join       on the other machine: become a standby of the primary a token\n"+
			"           describes, copying it over TLS and verifying its certificate.\n"+
			"leave      stop following it; the standby and its copy are removed.\n"+
			"status     what is published or followed, if anything.\n"+
			"token      print the join token again, for the other machine.\n",
			brand.CLI, branch.ReplicationRole)
		return
	}
	switch args[0] {
	case "expose":
		addr, peer := optValue(args, "--address"), optValue(args, "--peer")
		if addr == "" || peer == "" {
			fmt.Printf("usage: %s node expose --address <this machine> --peer <the standby's address>\n\n"+
				"--address is what the standby will dial, and what the certificate names.\n"+
				"--peer is the standby's address; only that machine is admitted.\n", brand.CLI)
			os.Exit(2)
		}
		port := 0
		if v := optValue(args, "--port"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 || n > 65535 {
				fmt.Fprintf(os.Stderr, "error: --port %q is not a port\n", v)
				os.Exit(2)
			}
			port = n
		}
		if !hasFlag(args, "--yes") {
			fmt.Printf("This publishes Postgres on %s so a standby on %s can copy it.\n\n"+
				"  · over TLS only, with a certificate naming %s\n"+
				"  · as %s, which can copy the database and read none of it\n"+
				"  · from %s only\n\n"+
				"main restarts, so connections drop for a few seconds. Nothing else is published:\n"+
				"clients still reach branches through the gateway.\n\n"+
				"Run it with --yes when you are ready.\n",
				addr, peer, addr, branch.ReplicationRole, peer)
			os.Exit(2)
		}
		must(branch.NodeExpose(addr, peer, port))
	case "unexpose":
		must(branch.NodeUnexpose())
	case "join":
		if len(args) < 2 {
			fmt.Printf("usage: %s node join <token>\n\n"+
				"The token comes from `%s node expose` on the primary. It carries that\n"+
				"install's CA certificate, its address, and the %s password — and nothing\n"+
				"else, so this machine cannot derive any other role's credentials.\n\n"+
				"This machine's own 'main' is left alone and sits idle while it follows\n"+
				"the other primary. Re-running this rebuilds the standby from scratch.\n",
				brand.CLI, brand.CLI, branch.ReplicationRole)
			os.Exit(2)
		}
		must(branch.NodeJoin(args[1]))
		warnStandbyLicence()
	case "leave":
		must(branch.NodeLeave())
	case "status":
		if d := branch.DescribeJoin(); d != "" {
			fmt.Println(d)
		}
		fmt.Println(branch.DescribeExposure())
	case "token":
		tok, err := branch.JoinToken()
		must(err)
		fmt.Println(tok)
	default:
		fmt.Printf("unknown node subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

// warnStandbyLicence says what a standby node's licence will cost it on
// promotion, because nothing else does and the moment it matters is the worst
// moment to find out.
func warnStandbyLicence() {
	if w := standbyLicenceWarning(edition.Enterprise, license.Install()); w != "" {
		fmt.Print(w)
	}
}

// standbyLicenceWarning is what to say, given the edition and the licence this
// install is honouring. A pure function of both, so the words can be read in a
// test rather than only seen on a machine that has just joined one.
//
// Why it is needed at all: a licence is per-install state —
// ~/.fox/license.json — and `node join` copies the primary's *database*, not
// its state directory. So a machine that has just joined runs whatever licence
// it was given itself, which on a fresh standby node is none. Measured, that is
// not a grace period: a paid feature on an unlicensed enterprise build refuses
// outright, "this build can run it, but no licence covers …". Promote that
// machine and the paid features stop with it.
//
// And note what it deliberately does *not* warn about. A licence activated on
// another machine and copied here keeps working indefinitely: a fingerprint
// mismatch is a Warning in internal/license, Warning unlocks, and the 14-day
// grace applies to expiry alone. So the dangerous state is an *absent* licence
// rather than a mismatched one — the opposite of what docs/FOX_HA_Plan.md §3.1
// assumed, which is why that section has been corrected.
//
// In cmd/fox rather than internal/branch: the engine has no business knowing
// about licences, and internal/host already imports internal/branch, so
// reaching the other way would be a cycle.
func standbyLicenceWarning(enterprise bool, st license.Status) string {
	if !enterprise {
		return "" // a Standard build has no paid features to lose
	}
	if st.Unlocks() {
		if st.State == license.Warning {
			// It works, and will go on working after a promotion. Said anyway,
			// because somebody reading this is deciding whether this machine is
			// ready to be promoted.
			return fmt.Sprintf("\nNote: this machine's licence warns — %s.\n"+
				"It still unlocks the paid features, here and after a promotion.\n", st.Reason)
		}
		return ""
	}
	return fmt.Sprintf("\nWARNING: this machine has no licence that unlocks the paid features.\n\n"+
		"  Replication and promotion do not need one, so the standby and `%s ha failover`\n"+
		"  work regardless. But a licence is per-install state — joining copied the\n"+
		"  primary's database, not its licence — so if this machine is promoted, the paid\n"+
		"  features stop with it: the change feed, policy authoring, impact analysis,\n"+
		"  change requests, pipelines, signed anchors and compliance export.\n\n"+
		"  Not a grace period: an unlicensed enterprise build refuses them at once.\n\n"+
		"  Activate a licence for this machine before you need it:\n"+
		"    %s license activate <file>\n\n"+
		"  A site licence (one with no machine fingerprint) covers every node of a pair,\n"+
		"  which is what to ask for when buying HA.\n", brand.CLI, brand.CLI)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		// A docker socket or a psql password message says nothing about what to
		// type next; errhint adds that line when it recognises the failure.
		if h := errhint.For(err); h != "" {
			fmt.Fprintln(os.Stderr, "\n"+h)
		}
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
		// Nothing to bootstrap; on a Linux host the console is still worth
		// opening, since nobody typed a URL.
		openConsole("")
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
	openConsole(tok)
}

// openConsole opens the web console for a user who is at this machine, with the
// setup token already in the link when there is one. It does nothing inside the
// engine VM (no display there — the host opens it after the forwarded start) and
// nothing when there is no console in this build.
func openConsole(setupToken string) {
	if web.FS() == nil {
		return
	}
	u := host.ConsoleURL("", setupToken)
	if !host.OpenURL(u) {
		return
	}
	if setupToken != "" {
		fmt.Println("\nOpening the console, with the setup token filled in — choose an email and a password there.")
		return
	}
	fmt.Printf("\nOpening the console: %s\n", u)
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
	s.Audit(auth.EvOwnerChanged, cliActor(), name, "", "now owned by "+u.Email)
	fmt.Printf("%s is now owned by %s\n", name, u.Email)
}

func mustAccounts(s *auth.Store) []auth.Account {
	list, err := s.ListAccounts()
	must(err)
	return list
}

// backupTargetCmd is `fox backup target`: show, set a remote S3 target, or go
// back to the local object store (audit v2 G18). The secret key is read from
// FOX_BACKUP_S3_SECRET_KEY or asked for, never taken as an argument: the
// process list and the shell history would keep it.
func backupTargetCmd(args []string) {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "", "show":
		t, err := branch.CurrentTarget()
		must(err)
		fmt.Printf("backups go to %s\n", t.Describe())
		if t.Remote() {
			lock, err := branch.CheckTarget(t)
			switch {
			case err != nil:
				fmt.Println("  not reachable now:", err)
			case lock == "":
				fmt.Println("  reachable; no Object Lock retention on the bucket")
			default:
				fmt.Println("  reachable;", strings.SplitN(lock, "\n", 2)[0])
			}
		}
	case "set":
		if len(args) < 2 {
			fmt.Printf("usage: %s backup target set s3://bucket[/prefix] --endpoint <https-url> --access-key <key> [--region <r>] [--path-style] [--allow-http]\n", brand.CLI)
			os.Exit(2)
		}
		bucket, prefix, err := branch.ParseTargetURL(args[1])
		must(err)
		t := branch.Target{Kind: "s3", Bucket: bucket, Prefix: prefix,
			Endpoint:  optValue(args, "--endpoint"),
			AccessKey: optValue(args, "--access-key"),
			Region:    optValue(args, "--region"),
			PathStyle: hasFlag(args, "--path-style")}
		if t.Region == "" {
			t.Region = "us-east-1"
		}
		t.SecretKey = strings.TrimSpace(brand.Getenv("BACKUP_S3_SECRET_KEY"))
		if t.SecretKey == "" {
			fmt.Print("secret key: ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			t.SecretKey = strings.TrimSpace(line)
		}
		must(branch.SetBackupTarget(t, hasFlag(args, "--allow-http")))
	case "local":
		must(branch.SetBackupTarget(branch.Target{Kind: "local"}, false))
	default:
		fmt.Printf("usage: %[1]s backup target [show] | %[1]s backup target set s3://… | %[1]s backup target local\n", brand.CLI)
		os.Exit(2)
	}
}

// hasFlag reports whether a bare flag appears in args.
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// auditCmd is `fox audit`: the security log (audit v2 G28).
func auditCmd(args []string) {
	s := openStore()
	defer s.Close()
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
	}
	switch sub {
	case "", "log":
		limit := 50
		if v := optValue(args, "--limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		evs, err := s.RecentSecurityEvents(limit)
		must(err)
		if len(evs) == 0 {
			fmt.Println("the security log is empty")
			return
		}
		for _, e := range evs {
			at := e.At
			if t, err := time.Parse(time.RFC3339Nano, e.At); err == nil {
				at = t.Local().Format("2006-01-02 15:04:05")
			}
			fmt.Printf("%6d  %s  %-28s %-26s %-28s %-15s %s\n", e.ID, at, e.Kind, e.Actor, e.Subject, e.IP, e.Detail)
		}
	case "verify":
		evs, err := s.SecurityEvents(0, 0)
		must(err)
		anchors, err := ledger.LoadAnchors(branch.SecurityLogAnchorDir())
		must(err)
		keyFile := optValue(args, "--pubkey")
		if keyFile == "" {
			keyFile = branch.AnchorKeyPath() + ".pub"
		}
		pub, perr := ledger.ReadPublicKey(keyFile)
		if perr != nil {
			pub = nil
		}
		rep := branch.VerifySecurityLog(evs, anchors, pub)
		if pub == nil {
			rep.Notes = append(rep.Notes, "signatures not checked: no public key at "+keyFile)
		}
		if rep.Intact {
			fmt.Printf("security log intact: %d events, %d anchored in %d anchor(s), %d not yet anchored\n",
				rep.Rows, rep.AnchoredRows, rep.Checkpoints, rep.UnanchoredRows)
		} else {
			fmt.Printf("security log TAMPERED: %d events\n", rep.Rows)
		}
		for _, p := range rep.Problems {
			fmt.Println("  problem:", p)
		}
		for _, n := range rep.Notes {
			fmt.Println("  note:", n)
		}
		if !rep.Intact {
			os.Exit(1)
		}
	case "checkpoint":
		a, err := branch.CheckpointSecurityLog(s)
		must(err)
		if a == nil {
			fmt.Println("security log: nothing new to anchor")
			return
		}
		fmt.Printf("security log anchored: events %d–%d, signed by key %s\n", a.FromID, a.ToID, a.KeyID)
	default:
		fmt.Printf("usage: %[1]s audit [--limit N] | %[1]s audit verify [--pubkey <file>] | %[1]s audit checkpoint\n", brand.CLI)
		os.Exit(2)
	}
}

// cliActor names whoever ran a command, for the security log: the local user.
func cliActor() string {
	name := os.Getenv("SUDO_USER")
	if name == "" {
		name = os.Getenv("USER")
	}
	if name == "" {
		name = "unknown"
	}
	return "cli:" + name
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
		must(refuseIfAccountsAreACopy("a password changed"))
		fmt.Print("new password (min 8 chars): ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		st := openStore()
		must(st.ResetPassword(args[1], strings.TrimSpace(line)))
		st.Audit(auth.EvPasswordReset, cliActor(), args[1], "", "fox user passwd")
		fmt.Printf("password changed for %s; its sessions were signed out\n", args[1])
	case "delete":
		if len(args) < 2 {
			usage()
		}
		must(refuseIfAccountsAreACopy("an account deleted"))
		s := openStore()
		u, ok := s.UserByEmail(args[1])
		if !ok {
			must(fmt.Errorf("no such user: %s", args[1]))
		}
		must(s.DeleteAccount(u.ID))
		s.Audit(auth.EvAccountDeleted, cliActor(), u.Email, "", "fox user delete")
		if err := branch.RevokeAdmin("main", u.Email); err != nil {
			fmt.Fprintf(os.Stderr, "note: could not revoke %s's admin grant on main: %v\n", u.Email, err)
		}
		fmt.Printf("deleted %s: its sessions, keys and pipelines are gone; its branches are now an admin's\n", u.Email)
	default:
		usage()
	}
}

// refuseIfAccountsAreACopy stops an account change on a machine that follows a
// primary elsewhere.
//
// Such a machine's account store is a copy (HA plan phase 2): the primary ships
// its accounts and this node applies them, replacing what is here. So an
// account created here would vanish at the next copy, and — worse — a key
// revoked here would come back. A security action that silently undoes itself
// is the one kind of refusal worth being firm about, which is why reads are
// untouched and every change is refused.
func refuseIfAccountsAreACopy(what string) error {
	if !branch.SharedStateIsACopy() {
		return nil
	}
	return fmt.Errorf("this machine follows a primary elsewhere, so its accounts are a copy of that "+
		"primary's — %s here would be undone by the next copy. Do it on the primary and it arrives "+
		"here within seconds (`%s ha status` says how current this copy is)", what, brand.CLI)
}

func userCreate(email string) error {
	// Said before the password is asked for rather than after it is typed.
	if err := refuseIfAccountsAreACopy("an account made"); err != nil {
		return err
	}
	fmt.Print("password (min 8 chars): ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	pw := strings.TrimSpace(line)
	if len(pw) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	st := openStore()
	u, err := st.CreateUser(email, pw)
	if err != nil {
		return err
	}
	st.Audit(auth.EvRegister, cliActor(), u.Email, "", "fox user create")
	fmt.Printf("created user %s (id %d)\n", u.Email, u.ID)
	return nil
}

func apikeyCmd(args []string) {
	// --agent may come anywhere after the subcommand.
	agent := false
	rest := args[:0:0]
	for _, a := range args {
		if a == "--agent" {
			agent = true
			continue
		}
		rest = append(rest, a)
	}
	args = rest
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
		must(refuseIfAccountsAreACopy("a key minted"))
		name := "key"
		if len(args) > 2 {
			name = args[2]
		}
		create, label := s.CreateAPIKey, ""
		if agent {
			create, label = s.CreateAgentKey, " [agent]"
		}
		secret, info, err := create(u.ID, name)
		must(err)
		s.Audit(auth.EvKeyCreated, cliActor(), info.Prefix+"… ("+info.Name+")"+label+" for "+u.Email, "", "fox apikey create")
		fmt.Printf("API key %q created — copy it now, it won't be shown again:\n\n  %s\n", info.Name, secret)
		if agent {
			fmt.Printf("\nAn agent key: it opens %s's branches through the Gateway as an agent,\n"+
				"so its changes are recorded as an agent's and the agent guardrails apply.\n"+
				"It cannot sign in to the console or the control-plane API.\n", u.Email)
		}
	case "list":
		keys, err := s.ListKeys(u.ID)
		must(err)
		if len(keys) == 0 {
			fmt.Println("no API keys")
			return
		}
		for _, k := range keys {
			kind := "account"
			switch {
			case k.Kind != "":
				kind = k.Kind
			case k.Scope != "":
				kind = "scoped"
			}
			fmt.Printf("  %s  %-16s  %-8s  %s…\n", k.ID, k.Name, kind, k.Prefix)
		}
	case "revoke":
		if len(args) < 3 {
			fmt.Println("usage: fox apikey revoke <email> <id>")
			os.Exit(2)
		}
		// Refused on a follower above all here: a key revoked on a copy comes
		// back with the next one, so the person told it was revoked would be
		// wrong about the one thing they most need to be right about.
		must(refuseIfAccountsAreACopy("a key revoked"))
		// An id that is not there says so: `fox apikey list <email>` shows the
		// real ones. Printing "revoked" for a typo left the key working.
		if err := s.RevokeKey(u.ID, args[2]); err != nil {
			if errors.Is(err, auth.ErrNoSuchKey) {
				must(fmt.Errorf("%s has no API key %q — list them with `%s apikey list %s`", u.Email, args[2], brand.CLI, u.Email))
			}
			must(err)
		}
		s.Audit(auth.EvKeyRevoked, cliActor(), "key "+args[2]+" of "+u.Email, "", "fox apikey revoke")
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
