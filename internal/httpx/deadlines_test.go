// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A body that stops arriving is cut off at the read deadline, rather than
// holding the handler (and, for an upload, its temporary file) for ever.
func TestDeadlinesCutOffASlowBody(t *testing.T) {
	got := make(chan error, 1)
	srv := httptest.NewServer(Deadlines(func(*http.Request) Budget { return Budget{Read: 200 * time.Millisecond} })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := io.ReadAll(r.Body)
			got <- err
		})))
	defer srv.Close()

	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Promise 100 bytes and send 5.
	fmt.Fprintf(c, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nhello")

	select {
	case err := <-got:
		if err == nil {
			t.Fatal("the stalled body was read to its end without an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled body was still being waited for after 5s")
	}
}

// Once the body is in, the read deadline is lifted: a handler that works past
// it keeps its context, and its answer arrives.
func TestDeadlinesLiftAfterTheBody(t *testing.T) {
	srv := httptest.NewServer(Deadlines(func(*http.Request) Budget { return Budget{Read: 100 * time.Millisecond} })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.ReadAll(r.Body); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			time.Sleep(400 * time.Millisecond)
			if err := r.Context().Err(); err != nil {
				http.Error(w, "context ended: "+err.Error(), 500)
				return
			}
			io.WriteString(w, "ok")
		})))
	defer srv.Close()

	res, err := http.Post(srv.URL, "text/plain", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(b) != "ok" {
		t.Fatalf("got %d %q, want 200 ok", res.StatusCode, b)
	}
}

// A request past its write budget cannot go on writing for ever.
func TestDeadlinesBoundTheResponse(t *testing.T) {
	failed := make(chan error, 1)
	srv := httptest.NewServer(Deadlines(func(*http.Request) Budget { return Budget{Write: 200 * time.Millisecond} })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			chunk := []byte(strings.Repeat("x", 64<<10))
			for {
				if _, err := w.Write(chunk); err != nil {
					failed <- err
					return
				}
			}
		})))
	defer srv.Close()

	// A client that asks and never reads.
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	select {
	case <-failed:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler was still writing to a reader that never read")
	}
}

// An event stream's quiet stretches outlast StreamWriteTimeout: the deadline
// covers each write and is lifted after it. Over HTTP/2 too, where a deadline
// left set ends the stream even while nothing is written.
func TestStreamWriteSurvivesQuietStretches(t *testing.T) {
	old := StreamWriteTimeout
	StreamWriteTimeout = 100 * time.Millisecond
	defer func() { StreamWriteTimeout = old }()

	h := Deadlines(func(*http.Request) Budget { return Budget{} })(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := range 3 {
			if err := StreamWrite(w, func() error { _, err := fmt.Fprintf(w, "event %d\n", i); return err }); err != nil {
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
	}))
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%v", h2), func(t *testing.T) {
			srv := httptest.NewUnstartedServer(h)
			srv.EnableHTTP2 = h2
			srv.StartTLS()
			defer srv.Close()
			res, err := srv.Client().Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if h2 && res.ProtoMajor != 2 {
				t.Fatalf("spoke HTTP/%d, want 2", res.ProtoMajor)
			}
			sc := bufio.NewScanner(res.Body)
			n := 0
			for sc.Scan() {
				n++
			}
			if n != 3 {
				t.Fatalf("read %d events, want 3 (err %v)", n, sc.Err())
			}
		})
	}
}

// Past the cap, a heavy request is refused at once with 429 and a reason.
func TestLimiterRefusesPastTheCap(t *testing.T) {
	l := NewLimiter("imports", 1)
	release := make(chan struct{})
	inside := make(chan struct{})
	h := l.Wrap(func(w http.ResponseWriter, r *http.Request) {
		close(inside)
		<-release
		io.WriteString(w, "done")
	})

	var wg sync.WaitGroup
	wg.Add(1)
	first := httptest.NewRecorder()
	go func() {
		defer wg.Done()
		h(first, httptest.NewRequest("POST", "/api/import", nil))
	}()
	<-inside

	second := httptest.NewRecorder()
	h(second, httptest.NewRequest("POST", "/api/import", nil))
	if second.Code != http.StatusTooManyRequests || !strings.Contains(second.Body.String(), "1 imports already running") {
		t.Fatalf("second got %d %q, want 429 naming the cap", second.Code, second.Body.String())
	}
	if second.Header().Get("Retry-After") == "" {
		t.Error("a 429 should say when to try again")
	}

	close(release)
	wg.Wait()
	if first.Code != 200 {
		t.Fatalf("first got %d", first.Code)
	}
	// And the slot is free again.
	third := httptest.NewRecorder()
	release = make(chan struct{})
	inside = make(chan struct{})
	close(release)
	h(third, httptest.NewRequest("POST", "/api/import", nil))
	if third.Code != 200 {
		t.Fatalf("after the first finished, got %d", third.Code)
	}
}
