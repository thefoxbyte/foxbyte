// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The decision an unattended process makes at four in the morning.
//
// The two wrong answers cost different amounts, and that asymmetry is the whole
// design: promoting while the primary is alive gives two primaries and two
// divergent copies that cannot be merged, and failing to promote a dead one
// gives an outage somebody ends. So every uncertain case must resolve to not
// promoting.
func TestWatchDecide(t *testing.T) {
	const after = time.Minute
	cases := []struct {
		what      string
		primaryUp bool
		view      witnessView
		downFor   time.Duration
		want      watchAction
	}{
		{"the primary answers", true, witnessSilent, 0, watchWait},
		{"…even if the witness is confused", true, witnessPrimaryDown, 0, watchWait},
		{"gone, but not for long enough", false, witnessPrimaryDown, 30 * time.Second, watchWait},
		{"gone, and the witness agrees", false, witnessPrimaryDown, time.Minute, watchPromote},
		{"…and well past the threshold", false, witnessPrimaryDown, time.Hour, watchPromote},
		{"the witness reaches it: this machine is the cut-off one", false, witnessPrimaryUp, time.Hour, watchRefuse},
		{"no second opinion to be had", false, witnessSilent, time.Hour, watchBlind},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			if got := watchDecide(c.primaryUp, c.view, c.downFor, after); got != c.want {
				t.Errorf("watchDecide(%v, %v, %s) = %v, want %v", c.primaryUp, c.view, c.downFor, got, c.want)
			}
		})
	}
}

// Stated as a property rather than inferred from the table: exactly one
// combination promotes, and it is the one where two independent observers agree
// for long enough.
func TestOnlyAgreementPromotes(t *testing.T) {
	for _, up := range []bool{true, false} {
		for _, v := range []witnessView{witnessSilent, witnessPrimaryUp, witnessPrimaryDown} {
			for _, d := range []time.Duration{0, time.Second, time.Minute, time.Hour} {
				got := watchDecide(up, v, d, time.Minute)
				agreed := !up && v == witnessPrimaryDown && d >= time.Minute
				if (got == watchPromote) != agreed {
					t.Errorf("primaryUp=%v %v downFor=%s decided %v", up, v, d, got)
				}
			}
		}
	}
	// And the one combination is the one the loop and the log agree on.
	if !witnessAgreesPrimaryIsGone(witnessPrimaryDown) {
		t.Error("the agreement test disagrees with the decision")
	}
	for _, v := range []witnessView{witnessSilent, witnessPrimaryUp} {
		if witnessAgreesPrimaryIsGone(v) {
			t.Errorf("%v counts as agreement", v)
		}
	}
}

// A silent witness is not a witness. The distinction between "it says the
// primary is fine" and "it did not answer" has to survive into the log, or an
// operator cannot tell a quiet healthy night from a watcher that has been
// unable to do its job since Tuesday.
func TestABlindWatcherSaysSoDistinctly(t *testing.T) {
	if watchDecide(false, witnessSilent, time.Hour, time.Minute) == watchDecide(false, witnessPrimaryUp, time.Hour, time.Minute) {
		t.Error("being unable to ask and being told no are the same decision")
	}
	if witnessSilent.String() == witnessPrimaryUp.String() {
		t.Error("…and they read the same in a log line")
	}
	for _, v := range []witnessView{witnessSilent, witnessPrimaryUp, witnessPrimaryDown} {
		if v.String() == "" {
			t.Errorf("view %d has no words", v)
		}
	}
}

// Refused without a witness, and that refusal is the feature: an automatic
// failover configured without a third opinion is a scheduled split brain, so
// the command does not work rather than working most of the time.
func TestWatchRefusesWithoutAWitness(t *testing.T) {
	err := Watch(WatchOptions{})
	if err == nil {
		t.Fatal("ha watch ran with no witness")
	}
	for _, want := range []string{"needs a witness", "two primaries", "ha witness"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
}

func TestWatchDefaultsLandInsideTheMinuteThePlanPromises(t *testing.T) {
	o := WatchOptions{After: -1}
	o.withDefaults()
	if o.After > time.Minute {
		t.Errorf("a promotion waits %s, which is past the minute phase 3 promises", o.After)
	}
	if o.Interval <= 0 || o.After/o.Interval < 3 {
		t.Errorf("%s/%s is too few rounds for a decision this expensive", o.After, o.Interval)
	}
	// And a caller's own values are kept.
	custom := WatchOptions{Interval: time.Second, After: 5 * time.Second}
	custom.withDefaults()
	if custom.Interval != time.Second || custom.After != 5*time.Second {
		t.Errorf("the defaults overwrote what was asked for: %+v", custom)
	}
	// Zero is a request and must survive: it is how a drill asks for a
	// promotion as soon as both observers agree. An interval of zero is only
	// ever an omission, since a watcher without one is a busy loop.
	drill := WatchOptions{After: 0, Interval: 0}
	drill.withDefaults()
	if drill.After != 0 {
		t.Errorf("--after 0s became %s, so a drill cannot ask for an immediate decision", drill.After)
	}
	if drill.Interval != watchIntervalDefault {
		t.Errorf("an omitted interval became %s", drill.Interval)
	}
}

// The witness, as an HTTP handler against a real listener. Two things worth
// asserting: it answers the one question truthfully, and it does not confirm to
// a stranger that it is a witness at all.
func TestWitnessAnswersOneQuestion(t *testing.T) {
	// Something that is listening, and an address that is not.
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	// Port 0: nothing can listen there, so connecting fails at once on every
	// system. A port freed by closing a listener was used before, and the test
	// servers below were sometimes handed that very port, so the "down" primary
	// answered (seen in CI).
	downAddr := "127.0.0.1:0"

	t.Run("it reaches a primary that is up", func(t *testing.T) {
		srv := httptest.NewServer(WitnessHandler(up.Addr().String(), ""))
		defer srv.Close()
		v, a, err := AskWitness(srv.URL+WitnessPath, "", 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if v != witnessPrimaryUp || !a.Reachable {
			t.Errorf("view = %v, answer = %+v", v, a)
		}
		if a.Witness == "" || a.At == "" {
			t.Errorf("the answer does not say who gave it or when: %+v", a)
		}
	})

	t.Run("and says so when it cannot", func(t *testing.T) {
		srv := httptest.NewServer(WitnessHandler(downAddr, ""))
		defer srv.Close()
		v, a, err := AskWitness(srv.URL+WitnessPath, "", 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if v != witnessPrimaryDown || a.Reachable {
			t.Errorf("view = %v, answer = %+v", v, a)
		}
	})

	t.Run("a stranger is not told this is a witness", func(t *testing.T) {
		srv := httptest.NewServer(WitnessHandler(up.Addr().String(), "s3cret"))
		defer srv.Close()
		// 404, not 401: a witness that confirms it is one to anybody who asks
		// is a map of somebody's database cluster.
		resp, err := http.Get(srv.URL + WitnessPath)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("an unauthenticated ask got %s, want 404", resp.Status)
		}
		// And the right token works.
		if v, _, err := AskWitness(srv.URL+WitnessPath, "s3cret", 5*time.Second); err != nil || v != witnessPrimaryUp {
			t.Errorf("with the token: %v, %v", v, err)
		}
		// A wrong one is refused, and the refusal is not silence-shaped: the
		// watcher must read it as "could not ask", never as agreement.
		if v, _, err := AskWitness(srv.URL+WitnessPath, "wrong", 5*time.Second); err == nil || v != witnessSilent {
			t.Errorf("with a wrong token: %v, %v", v, err)
		}
	})

	t.Run("a witness that is not there is silent, not agreeing", func(t *testing.T) {
		v, _, err := AskWitness("http://127.0.0.1:1"+WitnessPath, "", time.Second)
		if err == nil {
			t.Error("asking nothing succeeded")
		}
		if v != witnessSilent {
			t.Errorf("an unreachable witness gave view %v", v)
		}
		// Which decides nothing: the promotion needs an opinion, and this is
		// the absence of one.
		if watchDecide(false, v, time.Hour, time.Minute) == watchPromote {
			t.Error("an unreachable witness was counted as agreement")
		}
	})

	t.Run("an unreadable answer is silence too", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		defer srv.Close()
		if v, _, err := AskWitness(srv.URL, "", time.Second); err == nil || v != witnessSilent {
			t.Errorf("view = %v, err = %v", v, err)
		}
	})
}

// The witness needs an address it can dial, and a bad one must be a refusal
// rather than a witness that reports every primary as gone.
func TestWitnessNeedsHostAndPort(t *testing.T) {
	for _, bad := range []string{"", "primary.example.com", "primary.example.com:", ":5432x"} {
		if _, err := primaryAnswering(bad, time.Second); err == nil {
			t.Errorf("primaryAnswering(%q) accepted it", bad)
		}
	}
	if err := ServeWitness(":0", "not-an-address", ""); err == nil {
		t.Error("the witness started with an address it cannot dial")
	}
	// And a bad address reaches the answer rather than being swallowed: a
	// witness answering "unreachable" because it was misconfigured would
	// agree with every standby about every primary.
	var a WitnessAnswer
	rec := httptest.NewRecorder()
	WitnessHandler("nonsense", "").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, WitnessPath, nil))
	if err := json.NewDecoder(rec.Body).Decode(&a); err != nil {
		t.Fatal(err)
	}
	if a.Error == "" {
		t.Errorf("a misconfigured witness reported a clean 'unreachable': %+v", a)
	}
}
