// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A stream that has not yet had an event to send must still answer 200.
// WriteHeader only buffers the status line; without a flush, a client that
// gives up after a few seconds (the subscriber cap's "a place frees up")
// sees no response at all.
func TestAQuietStreamStillAnswers200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := newSSE(w); !ok {
			http.Error(w, "cannot stream", http.StatusInternalServerError)
			return
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *http.Response, 1)
	errc := make(chan error, 1)
	go func() {
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			errc <- err
			return
		}
		got <- res
	}()
	select {
	case res := <-got:
		defer res.Body.Close()
		cancel()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200 before any event", res.StatusCode)
		}
		if ct := res.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Fatalf("content-type %q", ct)
		}
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("no status line within 2s: the stream buffered 200 until the first event")
	}
}
