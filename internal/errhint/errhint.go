// SPDX-License-Identifier: AGPL-3.0-or-later

// Package errhint turns the failures a new user actually meets into a sentence
// they can act on.
//
// The engine shells out to docker, limactl, wsl and psql, and until now their
// errors reached the user as-is: "Cannot connect to the Docker daemon at
// unix:///var/run/docker.sock" says nothing about `fox setup`, and "password
// authentication failed for user" says nothing about API keys. Each entry here
// pairs a pattern with one sentence and the single command that fixes it.
//
// The rule for adding one: it must be a failure a person hits while using
// FoxByte normally, and the hint must name the next thing to type. Anything
// else stays as the underlying error, which is still printed — a hint explains a
// message, it never replaces it.
package errhint

import (
	"errors"
	"regexp"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// A hint is a pattern and what to say when it matches.
type hint struct {
	re   *regexp.Regexp
	says string // one sentence, then the command, with %s for the CLI name
}

// hints are tried in order, so put the specific before the general.
var hints = []hint{
	{regexp.MustCompile(`(?i)cannot connect to the docker daemon|docker daemon is not running|is the docker daemon running`),
		"Docker isn't running inside the engine VM.\nBring the stack back with: %s start   (or `%s setup` if this machine is new)"},
	{regexp.MustCompile(`(?i)no (foxbyte )?vm yet|no (foxbyte )?wsl distro yet|instance .* does not exist`),
		"This machine has no engine VM yet.\nCreate it once with: %s setup"},
	{regexp.MustCompile(`(?i)lima is required|limactl: (command )?not found|executable file not found in \$path.*limactl`),
		"Lima runs the engine VM on macOS and isn't installed.\nInstall it, then set up: brew install lima && %s setup"},
	{regexp.MustCompile(`(?i)wsl is required|wsl\.exe.*not found`),
		"WSL2 runs the engine on Windows and isn't installed.\nInstall it (as administrator), reboot, then: %s setup"},
	{regexp.MustCompile(`(?i)address already in use|bind: address already in use|port is already allocated`),
		"Something else already holds that port.\nSee what is listening, then either stop it or move FoxByte with FOX_LISTEN / --addr.\nIf an older FoxByte is still up: %s stop"},
	{regexp.MustCompile(`(?i)password authentication failed`),
		"That password isn't right for this branch. Through the gateway on :6432 the password is an API key, not your account password.\nMint one with: %s apikey create <email> <name>   (it is shown once)"},
	{regexp.MustCompile(`(?i)connection refused|could not reach branch|no such host|could not connect to server`),
		"Nothing answered there. The stack may be down, or the branch suspended.\nCheck it with: %s check"},
	{regexp.MustCompile(`(?i)(401 unauthorized|failed to resolve reference|pull access denied|manifest unknown)`),
		"A container image could not be fetched: the registry refused it or no longer has it.\nIf this is the object store, the images are mirrored to FoxByte's own registry — update to a release that carries the new names, or point the engine at a copy you have: FOX_MINIO_IMAGE and FOX_MC_IMAGE."},
	{regexp.MustCompile(`(?i)did not finish within .* and was stopped`),
		"That command was still running when its deadline passed, so it was stopped — usually a Docker daemon or an object store that stopped answering.\nCheck what the engine can see: %s check"},
	{regexp.MustCompile(`(?i)canceling statement due to statement timeout|context deadline exceeded|timed out after`),
		"The statement ran longer than its time limit and was cancelled — nothing was left half-applied.\nFor a long migration, run it through psql instead: %s connect <branch>"},
	{regexp.MustCompile(`(?i)cannot insert multiple commands into a prepared statement`),
		"A prepared statement holds one command, so this call could not take a script.\nThe console and POST /api/branches/{name}/query do run scripts — they fall back to the simple protocol, where Postgres wraps the whole script in one transaction.\nFor a long migration, a shell is still better: %s connect <branch>"},
	{regexp.MustCompile(`(?i)no space left on device|disk quota exceeded|out of space`),
		"The engine's disk is full. Branches are copy-on-write, so old ones and old backups are the usual cause.\nSee what is using it, then delete a branch or prune backups: %s status   then   %s backup prune --keep 3"},
	{regexp.MustCompile(`(?i)permission denied.*docker\.sock|got permission denied while trying to connect`),
		"This user may not talk to Docker inside the VM.\nRe-run the one-time setup, which fixes the group: %s setup"},
	{regexp.MustCompile(`(?i)x509|certificate signed by unknown authority|tls: failed to verify`),
		"The engine's TLS certificate wasn't accepted. It is self-signed on a local install, which is expected.\nFor curl add -k; for psql use sslmode=require (not verify-full)"},
	{regexp.MustCompile(`(?i)invalid name: use letters`),
		"A branch name may hold letters, digits, '.', '-' and '_', at most 63, starting with a letter or digit."},
	{regexp.MustCompile(`(?i)guardrail|blocked by policy`),
		"The Blackbox policy gate refused this change; it was recorded either way.\nSee the rule and who may override it with: %s policy list"},
}

// For returns a hint for err, or "" when nothing here explains it.
func For(err error) string {
	if err == nil {
		return ""
	}
	return ForText(err.Error())
}

// ForText is For on a message that is not an error value — the text of a failed
// command, or an error crossing a process or HTTP boundary.
func ForText(msg string) string {
	if strings.TrimSpace(msg) == "" {
		return ""
	}
	for _, h := range hints {
		if h.re.MatchString(msg) {
			return fill(h.says)
		}
	}
	return ""
}

// fill puts the CLI's name into a hint. A hint may name the command more than
// once, so every %s is replaced.
func fill(s string) string {
	for strings.Contains(s, "%s") {
		s = strings.Replace(s, "%s", brand.CLI, 1)
	}
	return s
}

// Wrap returns err with its hint appended, for a caller that prints one error
// and nothing else. It returns err unchanged when there is no hint.
func Wrap(err error) error {
	h := For(err)
	if h == "" {
		return err
	}
	return errors.New(err.Error() + "\n\n" + h)
}
