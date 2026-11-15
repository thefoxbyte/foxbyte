// SPDX-License-Identifier: AGPL-3.0-or-later

package safego

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func captureLog(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var b strings.Builder
	old := logf
	logf = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&b, f, a...)
	}
	t.Cleanup(func() { logf = old })
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return b.String()
	}
}

func TestRunRecoversAndLogsStack(t *testing.T) {
	got := captureLog(t)
	err := Run("backups", func() { panic("boom") })
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Run returned %v, want the panic as an error", err)
	}
	out := got()
	if !strings.Contains(out, "backups: recovered from a panic: boom") || !strings.Contains(out, "goroutine") {
		t.Fatalf("log should name the job, the panic and the stack, got:\n%s", out)
	}
}

func TestRunWithoutPanic(t *testing.T) {
	ran := false
	if err := Run("x", func() { ran = true }); err != nil || !ran {
		t.Fatalf("Run = %v, ran %v", err, ran)
	}
}

// A scheduler that wraps each tick in Run keeps ticking after one panics.
func TestLoopSurvivesAPanickingTick(t *testing.T) {
	captureLog(t)
	ticks := 0
	for i := range 3 {
		_ = Run("tick", func() {
			ticks++
			if i == 0 {
				panic("first tick")
			}
		})
	}
	if ticks != 3 {
		t.Fatalf("ran %d ticks, want 3", ticks)
	}
}

func TestGoRecovers(t *testing.T) {
	got := captureLog(t)
	done := make(chan struct{})
	Go("reaper", func() {
		defer close(done)
		panic(fmt.Errorf("nil map"))
	})
	<-done
	// close(done) runs before Catch does, so wait a moment for the log line.
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(got(), "reaper: recovered from a panic") {
		if time.Now().After(deadline) {
			t.Fatalf("no log of the recovered panic, got:\n%s", got())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCatchHandsThePanicOn(t *testing.T) {
	captureLog(t)
	ch := make(chan error, 1)
	func() {
		defer Catch("stream", func(err error) { ch <- err })
		var m map[string]int
		m["x"] = 1
	}()
	if err := <-ch; err == nil || !strings.Contains(err.Error(), "stream: internal error") {
		t.Fatalf("onPanic got %v", err)
	}
}
