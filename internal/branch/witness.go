// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/tlsutil"
)

// The third opinion, without which automatic failover is a way to produce two
// primaries — phase 3 of docs/FOX_HA_Plan.md.
//
// fenceRemotePrimary already says what the gap is: "it cannot cover a network
// partition: if this machine cannot reach the primary but clients still can,
// promoting here produces exactly the split-brain above and no amount of local
// probing can tell the two situations apart." Two machines cannot answer that
// question about each other. Somebody else has to look.
//
// So this is the monitor node the plan asked for, in the smallest form that
// answers the question: a process on a third host that replies to exactly one
// question — can *it* reach the primary? The standby promotes only when both
// opinions agree that the primary is gone. One opinion is not enough and three
// is a different product.
//
// Why not pg_auto_failover or Patroni, which the plan leaned towards. Both want
// to own the cluster: they create the data directory, write the recovery
// configuration and perform the promotion. This engine owns all three —
// branches are ZFS clones of a data directory it made, `node join` writes
// primary_conninfo, and HAFailover promotes behind a fence it checks itself.
// Marrying either one would mean handing over the parts branching is built on.
// There is a second reason, measured when fencing landed and recorded in §6.3
// of the plan: pg_auto_failover installs for PostgreSQL 18 from pgdg, but its
// last tagged release is April 2025 and the PG 17/18/19 work is untagged on
// `main` — a dependency whose maintenance we would be betting the failover on.
// What those projects are actually for is the quorum, and that is the part
// reproduced here: a witness, and a refusal without one.
//
// What this does not do, said plainly rather than implied:
//
//   - It is not consensus. Two observers agreeing is not a majority of three
//     voters; it is two independent observations. A witness that is itself
//     partitioned from the primary while clients are not would agree with the
//     standby and the promotion would be wrong. Placing the witness where the
//     clients are is therefore the operator's decision and the one that
//     matters, which is why `ha watch` prints it rather than assuming it.
//   - It carries no authority over the data. An answer cannot by itself
//     promote anything: the standby must independently have failed to reach
//     the primary.
//
// Because the answer decides an unattended promotion, the watcher has to know
// it came from the witness and was given just now. So:
//
//   - a shared token is required on both sides, with no tokenless mode. The
//     token itself never travels: each request carries an HMAC of a fresh
//     nonce made with it, which the witness checks in constant time;
//   - each answer carries an HMAC, made with the same token, over the verdict,
//     the time and the watcher's nonce. The watcher rejects an answer whose
//     MAC, nonce or time does not check out, so an answer cannot be altered on
//     the way, made up, or replayed from an earlier round;
//   - it is served over TLS, with the engine's self-signed certificate
//     (internal/tlsutil). The MAC is what makes an answer authentic; the
//     watcher can additionally pin the certificate's fingerprint, which the
//     witness prints when it starts;
//   - any answer that fails a check counts as no answer. The watcher then
//     does not promote (watchBlind), which is the safe way to be wrong.

// WitnessPath is the one question a witness answers.
const WitnessPath = "/ha/primary"

// witnessAuthScheme names the request MAC in the Authorization header.
const witnessAuthScheme = "Fox-Witness"

// witnessMinToken is the shortest token accepted. The token is an HMAC key, and
// a short one could be guessed offline from a single answer.
const witnessMinToken = 16

// witnessFreshness is how far an answer's time may be from the watcher's
// clock. The nonce already ties an answer to one request; this also bounds how
// long an answer can be held back. Generous, because the two clocks are on
// different machines, and an answer refused for skew means no promotion rather
// than a wrong one.
const witnessFreshness = 2 * time.Minute

// witnessNonceBytes is the size of the watcher's nonce: enough that one is
// never repeated.
const witnessNonceBytes = 32

// WitnessAnswer is what it says. The witness names itself so a report, or a
// log line after an incident, says who gave the second opinion.
type WitnessAnswer struct {
	Primary   string `json:"primary"`
	Reachable bool   `json:"reachable"`
	At        string `json:"at"`
	Witness   string `json:"witness"`
	Error     string `json:"error,omitempty"`
	// Nonce is the watcher's, echoed back, and MAC covers it with everything
	// above. Together they are what makes the answer this round's and the
	// witness's.
	Nonce string `json:"nonce"`
	MAC   string `json:"mac"`
}

// errWitnessToken is returned when a token is missing or too short, on either
// side.
var errWitnessToken = errors.New("witness token")

// checkWitnessToken refuses a missing or short token, and says how to set one.
// Witnesses and watchers configured by an older release, which accepted no
// token, land here and get the instructions rather than a quiet downgrade.
func checkWitnessToken(token string) error {
	if len(strings.TrimSpace(token)) >= witnessMinToken {
		return nil
	}
	what := "no witness token is set"
	if strings.TrimSpace(token) != "" {
		what = fmt.Sprintf("the witness token is shorter than %d characters", witnessMinToken)
	}
	return fmt.Errorf("%w: %s, and automatic failover is refused without one: the watcher must be "+
		"able to tell the witness's answer from anybody else's.\n"+
		"Set the same token on the witness and on the standby, either with --token or in %s.\n"+
		"A new one, if you need it: %s",
		errWitnessToken, what, brand.EnvName("HA_WITNESS_TOKEN"), newWitnessToken())
}

// newWitnessToken makes a token for the message above.
func newWitnessToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "(run: openssl rand -hex 32)"
	}
	return hex.EncodeToString(b)
}

// witnessMAC is HMAC-SHA256 under the token over a purpose and some fields,
// hex-encoded. Each field is length-prefixed, so two different sets of fields
// can never produce the same input.
func witnessMAC(token, purpose string, fields ...string) string {
	m := hmac.New(sha256.New, []byte(strings.TrimSpace(token)))
	for _, f := range append([]string{purpose}, fields...) {
		fmt.Fprintf(m, "%d:%s\n", len(f), f)
	}
	return hex.EncodeToString(m.Sum(nil))
}

// witnessRequestMAC is what a watcher sends to show it holds the token.
func witnessRequestMAC(token, nonce string) string {
	return witnessMAC(token, "fox-witness-request-v1", nonce)
}

// witnessAnswerMAC covers every field of an answer except the MAC itself.
func witnessAnswerMAC(token string, a WitnessAnswer) string {
	return witnessMAC(token, "fox-witness-answer-v1",
		a.Nonce, a.Primary, strconv.FormatBool(a.Reachable), a.At, a.Witness, a.Error)
}

// validNonce is 64 hex characters, which is what a watcher sends. Anything else
// is not a watcher.
func validNonce(n string) bool {
	if len(n) != 2*witnessNonceBytes {
		return false
	}
	_, err := hex.DecodeString(n)
	return err == nil
}

// witnessProbeTimeout is how long the witness waits for the primary. Short: a
// primary that takes three seconds to accept a connection is not a primary
// anybody is being served by, and the watcher is already counting consecutive
// failures rather than acting on one.
const witnessProbeTimeout = 3 * time.Second

// primaryAnswering reports whether something accepts a connection at an
// address. The same question RemotePrimaryAnswering asks of the join record,
// asked of an address a witness was given — and deliberately no more than that:
// a witness holds no credential of ours and needs none to say whether the
// machine is answering at all.
func primaryAnswering(addr string, timeout time.Duration) (bool, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("%q is not host:port", addr)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return false, fmt.Errorf("%q has no port number", addr)
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false, nil
	}
	_ = c.Close()
	return true, nil
}

// WitnessHandler is the witness as an http.Handler, so what it answers can be
// read in a test rather than against a running host.
//
// With no usable token it answers nobody. ServeWitness refuses to start that
// way; this is the same rule for anything that mounts the handler itself.
func WitnessHandler(primary, token string) http.Handler {
	mux := http.NewServeMux()
	me, _ := os.Hostname()
	tokenOK := checkWitnessToken(token) == nil
	mux.HandleFunc(WitnessPath, func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		if !tokenOK || r.Method != http.MethodGet || !validNonce(nonce) ||
			!requestMACIs(r.Header.Get("Authorization"), witnessRequestMAC(token, nonce)) {
			// 404 rather than 401: a witness that confirms it is a witness to
			// anybody who asks is a map of somebody's database cluster.
			http.NotFound(w, r)
			return
		}
		up, err := primaryAnswering(primary, witnessProbeTimeout)
		a := WitnessAnswer{
			Primary:   primary,
			Reachable: up,
			At:        time.Now().UTC().Format(time.RFC3339),
			Witness:   me,
			Nonce:     nonce,
		}
		if err != nil {
			a.Error = err.Error()
		}
		a.MAC = witnessAnswerMAC(token, a)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(a)
	})
	return mux
}

// requestMACIs compares the presented request MAC with the expected one in
// constant time, so the time a refusal takes says nothing about how much of a
// guess was right.
func requestMACIs(header, want string) bool {
	h := strings.TrimSpace(header)
	if !strings.HasPrefix(h, witnessAuthScheme+" ") {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(h, witnessAuthScheme))
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// ServeWitness runs the witness until the process is stopped.
func ServeWitness(addr, primary, token string) error {
	if _, _, err := net.SplitHostPort(primary); err != nil {
		return fmt.Errorf("--primary must be host:port (the primary's Postgres address): %w", err)
	}
	if err := checkWitnessToken(token); err != nil {
		return err
	}
	cfg, err := tlsutil.ServerConfig()
	if err != nil {
		return fmt.Errorf("the witness serves over TLS and could not load a certificate: %w", err)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           WitnessHandler(primary, token),
		TLSConfig:         cfg,
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Printf("witness for %s on https://%s%s\n", primary, addr, WitnessPath)
	if fp := certFingerprint(cfg); fp != "" {
		fmt.Printf("certificate fingerprint (sha256): %s\n", fp)
	}
	fmt.Printf("point a standby at it, with the same token, with:\n  %s ha watch --witness https://%s%s "+
		"--witness-fingerprint <the fingerprint above>\n\n", brand.CLI, addr, WitnessPath)
	fmt.Println("Put this somewhere the clients are, not beside either database: its whole job is")
	fmt.Println("to say whether the primary is reachable from where the work is.")
	return srv.ListenAndServeTLS("", "")
}

// certFingerprint is the SHA-256 of the served certificate, the value a
// watcher can pin.
func certFingerprint(cfg *tls.Config) string {
	if cfg == nil || len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(cfg.Certificates[0].Certificate[0])
	return hex.EncodeToString(sum[:])
}

// normaliseFingerprint accepts the hex with or without colons, in either case.
func normaliseFingerprint(fp string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fp), ":", ""))
}

// witnessView is what the second opinion amounts to this round.
type witnessView int

const (
	witnessSilent      witnessView = iota // it could not be asked, or its answer did not check out
	witnessPrimaryUp                      // it reaches the primary
	witnessPrimaryDown                    // it does not either
)

func (v witnessView) String() string {
	switch v {
	case witnessPrimaryUp:
		return "the witness reaches the primary"
	case witnessPrimaryDown:
		return "the witness cannot reach the primary either"
	}
	return "the witness could not be asked"
}

// WitnessAsk is how a watcher reaches its witness.
type WitnessAsk struct {
	URL         string        // https://host:port/ha/primary
	Token       string        // shared with the witness; required
	Fingerprint string        // the witness certificate's SHA-256, to pin; optional
	Timeout     time.Duration // for the whole exchange
}

// checkWitnessURL refuses a URL the watcher cannot use, before any round runs.
// http:// is named on its own because it is what every setup from an older
// release has.
func checkWitnessURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not a witness URL; it looks like https://host:7070%s", raw, WitnessPath)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("the witness is served over TLS, so its URL starts https://, not %s:// (%s). "+
			"Restart the witness with this release and change the URL here", u.Scheme, raw)
	}
	return nil
}

// AskWitness puts the question. A witness that cannot be reached is silent
// rather than agreeing: the whole point is that a promotion needs two
// opinions, and an absent one is not an opinion. So is one whose answer fails
// verification: an answer that cannot be shown to be the witness's, given in
// reply to this request, is treated as if nobody had answered.
func AskWitness(q WitnessAsk) (witnessView, WitnessAnswer, error) {
	if err := checkWitnessToken(q.Token); err != nil {
		return witnessSilent, WitnessAnswer{}, err
	}
	if err := checkWitnessURL(q.URL); err != nil {
		return witnessSilent, WitnessAnswer{}, err
	}
	raw := make([]byte, witnessNonceBytes)
	if _, err := rand.Read(raw); err != nil {
		return witnessSilent, WitnessAnswer{}, fmt.Errorf("making a nonce: %w", err)
	}
	nonce := hex.EncodeToString(raw)
	u, _ := url.Parse(strings.TrimSpace(q.URL))
	qs := u.Query()
	qs.Set("nonce", nonce)
	u.RawQuery = qs.Encode()

	timeout := q.Timeout
	if timeout <= 0 {
		timeout = watchAskTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return witnessSilent, WitnessAnswer{}, err
	}
	req.Header.Set("Authorization", witnessAuthScheme+" "+witnessRequestMAC(q.Token, nonce))
	resp, err := witnessClient(q.Fingerprint).Do(req)
	if err != nil {
		return witnessSilent, WitnessAnswer{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return witnessSilent, WitnessAnswer{}, fmt.Errorf("the witness answered %s — check the URL and the token",
			resp.Status)
	}
	var a WitnessAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&a); err != nil {
		return witnessSilent, WitnessAnswer{}, fmt.Errorf("the witness's answer was not readable: %w", err)
	}
	if err := verifyWitnessAnswer(q.Token, nonce, a, time.Now()); err != nil {
		return witnessSilent, a, err
	}
	if a.Reachable {
		return witnessPrimaryUp, a, nil
	}
	return witnessPrimaryDown, a, nil
}

// verifyWitnessAnswer is every check an answer must pass before it counts.
// Pure, so each refusal can be tested on its own.
func verifyWitnessAnswer(token, nonce string, a WitnessAnswer, now time.Time) error {
	if !hmac.Equal([]byte(a.MAC), []byte(witnessAnswerMAC(token, a))) {
		return errors.New("the witness's answer failed verification (its MAC does not match: " +
			"a different token, or an altered answer), so it counts as no answer")
	}
	if subtle.ConstantTimeCompare([]byte(a.Nonce), []byte(nonce)) != 1 {
		return errors.New("the witness's answer was for a different request, so it counts as no answer")
	}
	at, err := time.Parse(time.RFC3339, a.At)
	if err != nil {
		return errors.New("the witness's answer has no readable time, so it counts as no answer")
	}
	if d := now.Sub(at); d > witnessFreshness || d < -witnessFreshness {
		return fmt.Errorf("the witness's answer is dated %s, %s from this machine's clock, so it counts "+
			"as no answer. Check both clocks", a.At, d.Round(time.Second))
	}
	return nil
}

// witnessClient speaks TLS to the witness and follows no redirects, since a
// redirect would send the request MAC somewhere else.
//
// The certificate is the witness's own self-signed one, so there is no chain to
// verify. Authenticity comes from the answer's MAC; when a fingerprint is
// given, the certificate must also be that one.
func witnessClient(fingerprint string) *http.Client {
	pin := normaliseFingerprint(fingerprint)
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Chain verification is replaced, not dropped: see the comment above.
		InsecureSkipVerify: true, //nolint:gosec // self-signed witness; the MAC and the pin authenticate it
		VerifyConnection: func(cs tls.ConnectionState) error {
			if pin == "" {
				return nil
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the witness presented no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(pin)) != 1 {
				return errors.New("the witness's certificate is not the one pinned with --witness-fingerprint")
			}
			return nil
		},
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("the witness redirected the request; a witness answers where it is asked")
		},
	}
}

// witnessAgreesPrimaryIsGone is the only combination that may promote, written
// once so the loop and the log cannot disagree about it.
func witnessAgreesPrimaryIsGone(v witnessView) bool { return v == witnessPrimaryDown }
