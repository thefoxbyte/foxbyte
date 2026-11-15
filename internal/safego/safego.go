// SPDX-License-Identifier: AGPL-3.0-or-later

// Package safego keeps a panic on a background goroutine from taking the whole
// process with it. net/http recovers a panic in a handler, but nothing recovers
// one on a goroutine the code starts itself: a bug in a backup scheduler or a
// catalog scan would otherwise stop the control plane, the Gateway's sessions
// and every other job along with it.
//
// A recovered panic is logged with its stack, so it is still seen and fixed;
// it just costs that one job, or that one tick of a scheduler, and no more.
package safego

import (
	"fmt"
	"log"
	"runtime/debug"
)

// Catch recovers a panic, logs it with its stack under name, and hands it to
// onPanic as an error (onPanic may be nil). It must be deferred directly —
// `defer safego.Catch(...)` — because recover only works in the deferred call
// itself, not in anything it calls.
func Catch(name string, onPanic func(error)) {
	p := recover()
	if p == nil {
		return
	}
	logf("%s: recovered from a panic: %v\n%s", name, p, debug.Stack())
	if onPanic != nil {
		onPanic(fmt.Errorf("%s: internal error: %v", name, p))
	}
}

// Run calls f and returns its panic, if any, as an error. A scheduler wraps
// each tick in Run, so a tick that panics is logged and the next one still
// comes.
func Run(name string, f func()) (err error) {
	defer Catch(name, func(e error) { err = e })
	f()
	return nil
}

// Go runs f on a new goroutine, recovering any panic.
func Go(name string, f func()) {
	go func() {
		defer Catch(name, nil)
		f()
	}()
}

// logf is log.Printf, swapped in tests.
var logf = log.Printf
