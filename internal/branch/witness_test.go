// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testWitnessToken = "a-test-token-of-plenty-length"

// askTLS asks a test witness served over TLS.
func askTLS(srv *httptest.Server, token string) (witnessView, WitnessAnswer, error) {
	return AskWitness(WitnessAsk{URL: srv.URL + WitnessPath, Token: token, Timeout: 5 * time.Second})
}

// The witness, as an HTTP handler against a real listener. It answers the one
// question truthfully, and it does not confirm to a stranger that it is a
// witness at all.
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
		srv := httptest.NewTLSServer(WitnessHandler(up.Addr().String(), testWitnessToken))
		defer srv.Close()
		v, a, err := askTLS(srv, testWitnessToken)
		if err != nil {
			t.Fatal(err)
		}
		if v != witnessPrimaryUp || !a.Reachable {
			t.Errorf("view = %v, answer = %+v", v, a)
		}
		if a.Witness == "" || a.At == "" || a.MAC == "" || a.Nonce == "" {
			t.Errorf("the answer does not say who gave it, when, or for which request: %+v", a)
		}
	})

	t.Run("and says so when it cannot", func(t *testing.T) {
		srv := httptest.NewTLSServer(WitnessHandler(downAddr, testWitnessToken))
		defer srv.Close()
		v, a, err := askTLS(srv, testWitnessToken)
		if err != nil {
			t.Fatal(err)
		}
		if v != witnessPrimaryDown || a.Reachable {
			t.Errorf("view = %v, answer = %+v", v, a)
		}
	})

	t.Run("a stranger is not told this is a witness", func(t *testing.T) {
		srv := httptest.NewTLSServer(WitnessHandler(up.Addr().String(), testWitnessToken))
		defer srv.Close()
		// 404, not 401: a witness that confirms it is one to anybody who asks
		// is a map of somebody's database cluster. No credential at all, a
		// nonce with no MAC, and the old bearer form all get the same.
		client := srv.Client()
		nonce := strings.Repeat("ab", witnessNonceBytes)
		for what, set := range map[string]func(*http.Request){
			"nothing":          func(*http.Request) {},
			"the bare token":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testWitnessToken) },
			"a MAC, no scheme": func(r *http.Request) { r.Header.Set("Authorization", witnessRequestMAC(testWitnessToken, nonce)) },
			"another token MAC": func(r *http.Request) {
				r.Header.Set("Authorization", witnessAuthScheme+" "+witnessRequestMAC("another-token-entirely", nonce))
			},
		} {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+WitnessPath+"?nonce="+nonce, nil)
			set(req)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("an ask with %s got %s, want 404", what, resp.Status)
			}
		}
		// A wrong token is refused, and the refusal is not silence-shaped: the
		// watcher must read it as "could not ask", never as agreement.
		if v, _, err := askTLS(srv, "the-wrong-token-but-long-enough"); err == nil || v != witnessSilent {
			t.Errorf("with a wrong token: %v, %v", v, err)
		}
		// And the right one works.
		if v, _, err := askTLS(srv, testWitnessToken); err != nil || v != witnessPrimaryUp {
			t.Errorf("with the token: %v, %v", v, err)
		}
	})

	t.Run("a handler with no token answers nobody", func(t *testing.T) {
		srv := httptest.NewTLSServer(WitnessHandler(up.Addr().String(), ""))
		defer srv.Close()
		// Even a watcher that also has no token: the MAC of an empty key is
		// computable by anyone, so it proves nothing.
		nonce := strings.Repeat("cd", witnessNonceBytes)
		req, _ := http.NewRequest(http.MethodGet, srv.URL+WitnessPath+"?nonce="+nonce, nil)
		req.Header.Set("Authorization", witnessAuthScheme+" "+witnessRequestMAC("", nonce))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("a tokenless witness answered: %s", resp.Status)
		}
	})

	t.Run("a witness that is not there is silent, not agreeing", func(t *testing.T) {
		v, _, err := AskWitness(WitnessAsk{URL: "https://127.0.0.1:1" + WitnessPath, Token: testWitnessToken, Timeout: time.Second})
		if err == nil {
			t.Error("asking nothing succeeded")
		}
		if v != witnessSilent {
			t.Errorf("an unreachable witness gave view %v", v)
		}
		if watchDecide(false, v, time.Hour, time.Minute) == watchPromote {
			t.Error("an unreachable witness was counted as agreement")
		}
	})

	t.Run("an unreadable answer is silence too", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		defer srv.Close()
		if v, _, err := askTLS(srv, testWitnessToken); err == nil || v != witnessSilent {
			t.Errorf("view = %v, err = %v", v, err)
		}
	})

	t.Run("plain HTTP is refused before anything is sent", func(t *testing.T) {
		srv := httptest.NewServer(WitnessHandler(downAddr, testWitnessToken))
		defer srv.Close()
		if v, _, err := AskWitness(WitnessAsk{URL: srv.URL + WitnessPath, Token: testWitnessToken}); err == nil || v != witnessSilent {
			t.Errorf("an http:// witness was asked: %v, %v", v, err)
		}
	})
}

// The witness refuses to start without a token, or with one too short to be a
// key, and says how to set one rather than starting in a weaker mode.
func TestWitnessRefusesToStartWithoutAToken(t *testing.T) {
	for _, tok := range []string{"", "   ", "s3cret"} {
		err := ServeWitness("127.0.0.1:0", "127.0.0.1:5432", tok)
		if !errors.Is(err, errWitnessToken) {
			t.Errorf("ServeWitness with token %q: %v", tok, err)
			continue
		}
		if !strings.Contains(err.Error(), "--token") {
			t.Errorf("the refusal does not say how to set a token: %v", err)
		}
	}
	// The address is checked first, as before.
	if err := ServeWitness(":0", "not-an-address", testWitnessToken); err == nil {
		t.Error("the witness started with an address it cannot dial")
	}
}

// Each check an answer must pass, on its own.
func TestVerifyWitnessAnswer(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	nonce := strings.Repeat("0f", witnessNonceBytes)
	genuine := func() WitnessAnswer {
		a := WitnessAnswer{Primary: "10.0.0.1:5432", Reachable: false, At: now.Format(time.RFC3339),
			Witness: "w1", Nonce: nonce}
		a.MAC = witnessAnswerMAC(testWitnessToken, a)
		return a
	}
	if err := verifyWitnessAnswer(testWitnessToken, nonce, genuine(), now); err != nil {
		t.Fatalf("a genuine answer was refused: %v", err)
	}
	for what, c := range map[string]struct {
		edit  func(*WitnessAnswer)
		nonce string
		now   time.Time
		token string
	}{
		"the verdict flipped":         {edit: func(a *WitnessAnswer) { a.Reachable = true }},
		"the witness renamed":         {edit: func(a *WitnessAnswer) { a.Witness = "w2" }},
		"the primary changed":         {edit: func(a *WitnessAnswer) { a.Primary = "10.0.0.2:5432" }},
		"an error added":              {edit: func(a *WitnessAnswer) { a.Error = "x" }},
		"the time moved":              {edit: func(a *WitnessAnswer) { a.At = now.Add(time.Second).Format(time.RFC3339) }},
		"no MAC":                      {edit: func(a *WitnessAnswer) { a.MAC = "" }},
		"another request's nonce":     {nonce: strings.Repeat("f0", witnessNonceBytes)},
		"a different token":           {token: "a-different-token-entirely"},
		"held back past the window":   {now: now.Add(witnessFreshness + time.Second)},
		"dated too far in the future": {now: now.Add(-witnessFreshness - time.Second)},
	} {
		a := genuine()
		if c.edit != nil {
			c.edit(&a)
		}
		n, at, tok := nonce, now, testWitnessToken
		if c.nonce != "" {
			n = c.nonce
		}
		if !c.now.IsZero() {
			at = c.now
		}
		if c.token != "" {
			tok = c.token
		}
		if err := verifyWitnessAnswer(tok, n, a, at); err == nil {
			t.Errorf("%s: the answer was accepted", what)
		}
	}
	// A MAC re-made with the right token over an old time is still refused for
	// its age: knowing the token does not make a stale answer fresh.
	old := genuine()
	old.At = now.Add(-time.Hour).Format(time.RFC3339)
	old.MAC = witnessAnswerMAC(testWitnessToken, old)
	if err := verifyWitnessAnswer(testWitnessToken, nonce, old, now); err == nil {
		t.Error("an hour-old answer was accepted")
	}
}

// tamperingWitness sits in front of a real witness and changes what it says,
// the way something on the network between the two machines could.
func tamperingWitness(t *testing.T, real http.Handler, edit func(*WitnessAnswer)) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		real.ServeHTTP(rec, r)
		var a WitnessAnswer
		if err := json.NewDecoder(rec.Body).Decode(&a); err != nil {
			w.WriteHeader(rec.Code)
			return
		}
		edit(&a)
		_ = json.NewEncoder(w).Encode(a)
	}))
}

// A changed answer, or one replayed from an earlier round, is no verdict, and
// a round given it does not promote.
func TestTamperedOrReplayedAnswersAreNoVerdict(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	real := WitnessHandler(up.Addr().String(), testWitnessToken)

	t.Run("a flipped verdict", func(t *testing.T) {
		// The witness reaches the primary; the answer is changed to say it
		// does not. Accepting that is exactly the split brain.
		srv := tamperingWitness(t, real, func(a *WitnessAnswer) { a.Reachable = false })
		defer srv.Close()
		v, _, err := askTLS(srv, testWitnessToken)
		if err == nil || v != witnessSilent {
			t.Fatalf("a flipped answer gave %v, %v", v, err)
		}
		action, _, _, _ := watchRound(false, time.Hour, 0, func() (witnessView, WitnessAnswer, error) {
			return askTLS(srv, testWitnessToken)
		})
		if action != watchBlind {
			t.Errorf("a round given a flipped answer decided %v, want blind", action)
		}
	})

	t.Run("a made-up answer", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a := WitnessAnswer{Primary: "p", Reachable: false, At: time.Now().UTC().Format(time.RFC3339),
				Witness: "w", Nonce: r.URL.Query().Get("nonce")}
			a.MAC = witnessAnswerMAC("not-the-shared-token-at-all", a)
			_ = json.NewEncoder(w).Encode(a)
		}))
		defer srv.Close()
		if v, _, err := askTLS(srv, testWitnessToken); err == nil || v != witnessSilent {
			t.Errorf("an answer signed with another key gave %v, %v", v, err)
		}
	})

	t.Run("a replayed answer", func(t *testing.T) {
		// The first answer is genuine and is recorded; every later request is
		// sent that same recording.
		down := WitnessHandler("127.0.0.1:0", testWitnessToken)
		var mu sync.Mutex
		var recorded []byte
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			if recorded == nil {
				rec := httptest.NewRecorder()
				down.ServeHTTP(rec, r)
				recorded = bytes.Clone(rec.Body.Bytes())
			}
			_, _ = w.Write(recorded)
		}))
		defer srv.Close()
		if v, _, err := askTLS(srv, testWitnessToken); err != nil || v != witnessPrimaryDown {
			t.Fatalf("the genuine first answer was refused: %v, %v", v, err)
		}
		v, _, err := askTLS(srv, testWitnessToken)
		if err == nil || v != witnessSilent {
			t.Errorf("a replayed answer gave %v, %v", v, err)
		}
		action, _, _, _ := watchRound(false, time.Hour, 0, func() (witnessView, WitnessAnswer, error) {
			return askTLS(srv, testWitnessToken)
		})
		if action == watchPromote {
			t.Error("a replayed 'primary unreachable' promoted")
		}
	})
}

// Pinning the certificate: the right fingerprint is accepted and any other is
// refused before anything is sent.
func TestWitnessCertificatePin(t *testing.T) {
	srv := httptest.NewTLSServer(WitnessHandler("127.0.0.1:0", testWitnessToken))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	right := hex.EncodeToString(sum[:])
	ask := func(fp string) (witnessView, error) {
		v, _, err := AskWitness(WitnessAsk{URL: srv.URL + WitnessPath, Token: testWitnessToken,
			Fingerprint: fp, Timeout: 5 * time.Second})
		return v, err
	}
	if v, err := ask(right); err != nil || v != witnessPrimaryDown {
		t.Errorf("the right fingerprint: %v, %v", v, err)
	}
	// As the witness prints it, or with colons and in capitals.
	var colons []string
	for i := 0; i < len(right); i += 2 {
		colons = append(colons, strings.ToUpper(right[i:i+2]))
	}
	if v, err := ask(strings.Join(colons, ":")); err != nil || v != witnessPrimaryDown {
		t.Errorf("the right fingerprint, with colons: %v, %v", v, err)
	}
	if v, err := ask(strings.Repeat("00", 32)); err == nil || v != witnessSilent {
		t.Errorf("a wrong fingerprint: %v, %v", v, err)
	}
}

// The request MAC's format is pinned, because the integration suite computes
// it with openssl rather than with this code. This vector came from:
//
//	printf '22:fox-witness-request-v1\n64:%s\n' "$N" | openssl dgst -sha256 -hmac k -r
func TestWitnessRequestMACMatchesOpenSSL(t *testing.T) {
	const nonce = "db88e52ee7aaeab27bc7a089aa9c42b83cb2b9e996a56659cf6d98473e0972d1"
	const want = "d341c582bb6ccf08daa71f2ae6cdfada1b8c8f5be4cedd036281be6d8c47dbbb"
	if got := witnessRequestMAC("k", nonce); got != want {
		t.Errorf("witnessRequestMAC = %s, want %s", got, want)
	}
}

// The witness needs an address it can dial, and a bad one must be a refusal
// rather than a witness that reports every primary as gone.
func TestWitnessNeedsHostAndPort(t *testing.T) {
	for _, bad := range []string{"", "primary.example.com", "primary.example.com:", ":5432x"} {
		if _, err := primaryAnswering(bad, time.Second); err == nil {
			t.Errorf("primaryAnswering(%q) accepted it", bad)
		}
	}
	// And a bad address reaches the answer rather than being swallowed: a
	// witness answering "unreachable" because it was misconfigured would
	// agree with every standby about every primary.
	nonce := strings.Repeat("ab", witnessNonceBytes)
	req := httptest.NewRequest(http.MethodGet, WitnessPath+"?nonce="+nonce, nil)
	req.Header.Set("Authorization", witnessAuthScheme+" "+witnessRequestMAC(testWitnessToken, nonce))
	rec := httptest.NewRecorder()
	WitnessHandler("nonsense", testWitnessToken).ServeHTTP(rec, req)
	var a WitnessAnswer
	if err := json.NewDecoder(rec.Body).Decode(&a); err != nil {
		t.Fatal(err)
	}
	if a.Error == "" {
		t.Errorf("a misconfigured witness reported a clean 'unreachable': %+v", a)
	}
}
