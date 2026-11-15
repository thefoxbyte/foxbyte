// SPDX-License-Identifier: AGPL-3.0-or-later

package license

import (
	"log"
	"os"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/safego"
)

// Keeping a running process's entitlement in step with the licence file.
//
// The entitlement used to be read once, when a process started, and that was
// fine while the only way to change a licence was a command followed by a
// restart. It stopped being fine when the console learned to activate one: the
// control plane honoured it at once and the Gateway, the Agent API and a running
// MCP session went on refusing the same features until somebody restarted them
// — so the button said "activated" and half the product disagreed. Every
// long-running process now watches the file and re-reads it when it changes.
//
// It also re-reads on a timer when nothing has changed, because a licence can
// change state without being touched: it expires, it enters its grace period,
// the grace runs out. A process that only looked at start-up would honour a
// licence for as long as it happened to stay up past the date it ended.

const (
	// watchEvery is how often the file is looked at. A stat, so it costs
	// nothing; two seconds is quicker than anyone closes a modal.
	watchEvery = 2 * time.Second
	// reevaluateEvery is how often the licence is read again with the file
	// unchanged, for the transitions that happen with time alone. Ten minutes
	// is far finer than any expiry is stated in.
	reevaluateEvery = 10 * time.Minute
)

// stamp is enough of a file's identity to notice it being replaced: Save
// writes a temporary file and renames it over, so a new licence is a new size,
// a new modification time, or both — and a removed one is no file at all.
type stamp struct {
	exists bool
	size   int64
	mod    time.Time
}

func stampOf(path string) stamp {
	fi, err := os.Stat(path)
	if err != nil {
		return stamp{}
	}
	return stamp{exists: true, size: fi.Size(), mod: fi.ModTime()}
}

// shouldReinstall is the whole decision, pure so it can be read in a test: the
// file changed, or it has been long enough that time alone may have changed
// what the same file means.
func shouldReinstall(prev, cur stamp, sinceEvaluated, every time.Duration) bool {
	return prev != cur || sinceEvaluated >= every
}

// changed reports whether two statuses are different enough to say so. The
// reason text is left out on purpose: "expires in 9 days" becoming "expires in
// 8 days" is the same state, and logging it every ten minutes would bury the
// line that matters among ones that do not.
func changed(a, b Status) bool {
	return a.State != b.State || a.License.ID != b.License.ID || a.Unlocks() != b.Unlocks()
}

// Watch re-reads the licence whenever its file changes, and on a slow timer
// regardless, for as long as the process runs. onChange, if given, is told
// each time what the process now honours — the control plane passes the
// security log's recorder, so a licence that arrives mid-run is recorded when
// it starts being honoured rather than at the next restart.
//
// Only for long-running processes. A command that runs and exits reads the
// licence when it starts, which is already the newest it can be.
func Watch(onChange func(Status)) {
	// The first look happens here, before the goroutine exists, and the
	// licence is read again right after it. Taken inside the goroutine
	// instead, a licence written between this returning and the goroutine's
	// first look was taken for the starting state and missed — for ten
	// minutes, until the timer came round. The race detector's slower
	// scheduling is what showed it.
	path := Path()
	prev := stampOf(path)
	before := Installed()
	if after := Install(); changed(before, after) && onChange != nil {
		onChange(after)
	}
	// A panic would stop the watch (the entitlement then stays as it last
	// was) rather than the whole process.
	safego.Go("licence watch", func() { watch(path, prev, watchEvery, reevaluateEvery, onChange, nil) })
}

// watch is the loop, starting from a look already taken, and stoppable for
// tests. A process never stops it: it runs for as long as the process does.
func watch(path string, prev stamp, every, reevaluate time.Duration, onChange func(Status), stop <-chan struct{}) {
	evaluated := time.Now()
	for {
		select {
		case <-stop:
			return
		case <-time.After(every):
		}
		cur := stampOf(path)
		if !shouldReinstall(prev, cur, time.Since(evaluated), reevaluate) {
			continue
		}
		before := Installed()
		after := Install()
		prev, evaluated = cur, time.Now()
		if !changed(before, after) {
			continue
		}
		log.Printf("licence: now %s%s", after.State.Code(), describeForLog(after))
		if onChange != nil {
			onChange(after)
		}
	}
}

func describeForLog(st Status) string {
	switch {
	case st.Present() && st.Unlocks():
		return " — " + st.License.ID + " unlocks the paid features in this process"
	case st.Present():
		return " — " + st.License.ID + " is installed and unlocks nothing: " + st.Reason
	}
	return " — no licence, so the paid features are locked in this process"
}
