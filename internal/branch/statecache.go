// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Every gateway connection and console request used to ask docker where its
// branch was: an inspect for the state, the same inspect again inside
// EnsureRunning, another for the IP. Three `sudo docker` processes per
// connection, each allowed ten minutes, so a dockerd that stopped answering held
// every request for ten minutes.
//
// So one inspect now answers both questions, it gets seconds rather than
// minutes, and what it found is kept briefly for the callers behind it.
//
// The gateway, the control plane and the CLI are separate processes, and this
// memory is not shared between them. A suspend run elsewhere cannot clear it, so
// the rules below are what make keeping it safe:
//
//   - Only "running, at this address" is ever kept. A branch seen stopped or
//     absent is not remembered at all, so no stale "absent" can exist to send
//     anybody down startContainer's `docker rm -f`.
//   - What to do about a branch that is not running is decided by probeContainer,
//     which always asks docker and shares its answer with nobody.
//   - A docker that did not answer is ErrStateUnknown, never "absent".
//   - An address that turns out not to work is forgotten and routed again
//     (ForgetBackends; the gateway's connectBackend, the console's connectSession).

// stateCacheTTL is how long a branch seen running is believed without asking
// again. Short because it is the window in which another process's suspend goes
// unnoticed; long enough that a burst of connections costs one inspect.
const stateCacheTTL = 2 * time.Second

// ErrStateUnknown: docker could not say what state a container is in. Not a
// statement that the container is missing, and the difference matters: "absent"
// is what recreates one.
var ErrStateUnknown = errors.New("could not read the container's state from docker")

// containerFacts is what one inspect says about a container.
type containerFacts struct {
	state string // running | exited | created | paused | ... | absent
	ip    string // on the engine's docker network; "" when not attached
}

// serving reports whether these facts can route a connection.
func (f containerFacts) serving() bool { return f.state == "running" && f.ip != "" }

func (f containerFacts) addr() string { return f.ip + ":5432" }

// inspectFormat puts a container's name, state and IP on one line. `index`
// rather than the dotted path containerIP uses, because a container not on the
// network has no such key and a dotted path would fail the whole inspect.
var inspectFormat = `{{.Name}}|{{.State.Status}}|{{with index .NetworkSettings.Networks "` + network + `"}}{{.IPAddress}}{{end}}`

// inspectContainers is the docker call behind every answer here, a variable so
// a test can count it. docker prints what it found and fails over what it did
// not, so the output is worth reading even with an error.
var inspectContainers = func(d time.Duration, conts []string) (string, error) {
	args := append([]string{"inspect", "--type", "container", "-f", inspectFormat}, conts...)
	return captureWithin(d, "docker", args...)
}

// parseFacts reads inspectFormat's lines, keyed by container name.
func parseFacts(out string) map[string]containerFacts {
	facts := map[string]containerFacts{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(ln), "|")
		if len(f) != 3 || f[1] == "" {
			continue
		}
		facts[strings.TrimPrefix(f[0], "/")] = containerFacts{state: f[1], ip: f[2]}
	}
	return facts
}

// isNoSuchContainer tells docker saying a container does not exist from docker
// not saying anything. Only the first may be read as "absent".
func isNoSuchContainer(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such")
}

// probeContainer asks docker now, on a short deadline, and shares the answer
// with nobody. It is what a decision to start or recreate a container has to
// stand on.
func probeContainer(cont string) (containerFacts, error) {
	out, err := inspectContainers(execProbe, []string{cont})
	if f, ok := parseFacts(out)[cont]; ok {
		return f, nil
	}
	if isNoSuchContainer(err) {
		return containerFacts{state: "absent"}, nil
	}
	if err == nil {
		err = fmt.Errorf("docker inspect said nothing about %s", cont)
	}
	return containerFacts{}, fmt.Errorf("%w: %v", ErrStateUnknown, err)
}

// stateGen counts the state changes this process has made. Whatever was read
// under an earlier value is out of date, however recently it was read.
var stateGen atomic.Uint64

// stateNow is the clock of everything in this file, so a test can move it.
var stateNow = time.Now

// noteStateChange says this process has just changed a container, a dataset or
// which container is the primary. It goes after the change, because a read made
// while a `docker stop` is running still says "running".
func noteStateChange() {
	containers.mu.Lock()
	defer containers.mu.Unlock()
	stateGen.Add(1)
	clear(containers.entries)
}

// ForgetBackends drops every address kept here, for a caller that has just
// failed to reach one. The next routing asks docker again.
func ForgetBackends() { noteStateChange() }

// changesContainers recognises the docker commands that change what is running.
// Checked where every command is run, rather than at each place that stops or
// starts something, so that one added later cannot forget to. `docker run --rm`
// is a tool in a throwaway container, and the backup listing runs one a minute.
func changesContainers(name string, args []string) bool {
	if name != "docker" || len(args) == 0 {
		return false
	}
	switch args[0] {
	case "start", "stop", "restart", "kill", "rm", "create", "pause", "unpause", "rename":
		return true
	case "run":
		for _, a := range args[1:] {
			if a == "--rm" {
				return false
			}
		}
		return true
	}
	return false
}

// noteIfChange is noteStateChange for a command that has just finished,
// successfully or not: one that failed may still have done part of its work.
func noteIfChange(name string, args []string) {
	if changesContainers(name, args) {
		noteStateChange()
	}
}

// probeFlight is one inspect in progress, for the callers waiting on it.
type probeFlight struct {
	gen   uint64
	done  chan struct{}
	facts containerFacts
	err   error
}

// containerCache is the per-container memory: at most one inspect at a time for
// a container, and its answer kept for stateCacheTTL if the container was
// serving.
type containerCache struct {
	mu      sync.Mutex
	entries map[string]cachedFacts
	flights map[string]*probeFlight
}

type cachedFacts struct {
	facts   containerFacts
	expires time.Time
}

var containers = &containerCache{entries: map[string]cachedFacts{}, flights: map[string]*probeFlight{}}

// lookup answers from memory or from the inspect already under way, and starts
// one if there is neither.
//
// A caller may only act on a serving answer. Anything else came from nowhere
// that a decision can stand on: it may be another caller's inspect from a moment
// ago. Those go on to probeContainer.
//
// A flight begun before a state change is not joined, and what it finds is not
// kept: it may have read the world from before the change.
func (c *containerCache) lookup(cont string) (containerFacts, error) {
	c.mu.Lock()
	if e, ok := c.entries[cont]; ok && stateNow().Before(e.expires) {
		c.mu.Unlock()
		return e.facts, nil
	}
	gen := stateGen.Load()
	if fl, ok := c.flights[cont]; ok && fl.gen == gen {
		c.mu.Unlock()
		<-fl.done
		return fl.facts, fl.err
	}
	fl := &probeFlight{gen: gen, done: make(chan struct{})}
	c.flights[cont] = fl
	c.mu.Unlock()

	fl.facts, fl.err = probeContainer(cont)

	c.mu.Lock()
	if c.flights[cont] == fl {
		delete(c.flights, cont)
	}
	if fl.err == nil && fl.facts.serving() && fl.gen == stateGen.Load() {
		c.entries[cont] = cachedFacts{facts: fl.facts, expires: stateNow().Add(stateCacheTTL)}
	}
	c.mu.Unlock()
	close(fl.done)
	return fl.facts, fl.err
}
