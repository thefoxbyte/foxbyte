// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// forwardIn keeps the settings, the store, the token and the CA somewhere
// harmless.
func forwardIn(t *testing.T) {
	t.Helper()
	settingsIn(t)
	storeIn(t)
	dir := t.TempDir()
	oldCA, oldTok := forwardCAPath, forwardTokenPath
	forwardCAPath = func() string { return filepath.Join(dir, "ca.pem") }
	forwardTokenPath = func() string { return filepath.Join(dir, "token") }
	t.Cleanup(func() { forwardCAPath, forwardTokenPath = oldCA, oldTok })
}

// seed appends records made from lines to the store, on a day, continuing
// the chain, as a collection does.
func seed(t *testing.T, day string, lines ...string) {
	t.Helper()
	s, err := loadAuditState()
	if err != nil {
		t.Fatal(err)
	}
	var recs []AuditRecord
	for _, l := range lines {
		r, ok := recordFromLine("main", []byte(l))
		if !ok {
			t.Fatalf("not a record: %s", l)
		}
		sealRecord(&r, s.Seq+1, s.Head)
		s.Seq, s.Head = r.Seq, r.Hash
		recs = append(recs, r)
	}
	if err := appendForensic(day, recs); err != nil {
		t.Fatal(err)
	}
	size, err := appendDay(day, recs)
	if err != nil {
		t.Fatal(err)
	}
	s.Days[day] = size
	if err := saveAuditState(s); err != nil {
		t.Fatal(err)
	}
}

// collector is an HTTPS receiver that keeps what it is sent.
type collector struct {
	mu    sync.Mutex
	auth  []string
	lines []map[string]any
	fail  int // answer this status instead, when set
	srv   *httptest.Server
}

func newCollector(t *testing.T) *collector {
	c := &collector{}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.fail != 0 {
			w.WriteHeader(c.fail)
			return
		}
		c.auth = append(c.auth, r.Header.Get("Authorization"))
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				t.Errorf("a line is not JSON: %s", sc.Text())
			}
			c.lines = append(c.lines, m)
		}
		if r.Header.Get("Content-Type") != "application/x-ndjson" || r.URL.RawQuery != "" {
			t.Errorf("content type %q, query %q", r.Header.Get("Content-Type"), r.URL.RawQuery)
		}
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *collector) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.srv.Certificate().Raw})
}

func (c *collector) seqs() []int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []int64
	for _, l := range c.lines {
		out = append(out, int64(l["seq"].(float64)))
	}
	return out
}

func TestParseForwardURL(t *testing.T) {
	for _, ok := range []string{"https://siem.example.com/ingest", "syslog://logs.example.com", "syslog://logs.example.com:6514", "syslog+tls://10.0.0.5:1514"} {
		if _, err := ParseForwardURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for bad, why := range map[string]string{
		"http://siem.example.com/ingest":       "unencrypted",
		"udp://logs.example.com:514":           "unencrypted",
		"syslog+udp://logs.example.com":        "unencrypted",
		"https://user:secret@siem.example.com": "password",
		"syslog://logs.example.com/x":          "no path",
		"ftp://x":                              "not a way",
		"siem.example.com":                     "not a URL",
	} {
		if _, err := ParseForwardURL(bad); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: want %q, got %v", bad, why, err)
		}
	}
}

func TestSetForwardRefuses(t *testing.T) {
	forwardIn(t)
	if err := SetAuditForward("syslog://logs.example.com", ForwardOptions{Token: "t"}); err == nil {
		t.Error("a token for syslog")
	}
	if err := SetAuditForward("https://siem.example.com", ForwardOptions{CAPEM: []byte("not a certificate")}); err == nil {
		t.Error("a CA bundle with no certificate")
	}
	if err := SetAuditForward("https://siem.example.com", ForwardOptions{Token: "a\nb"}); err == nil {
		t.Error("a token of two lines")
	}
	if LoadAuditSettings().Forward != nil {
		t.Error("a refused setting was kept")
	}
}

func TestForwardHTTPS(t *testing.T) {
	forwardIn(t)
	c := newCollector(t)
	seed(t, "2026-11-04", lineObject, lineTxn, lineForensic)

	// From the next record by default: what is already there is not sent.
	if err := SetAuditForward(c.srv.URL+"/ingest", ForwardOptions{Token: "tok-123", CAPEM: c.caPEM(), By: "admin@x.in"}); err != nil {
		t.Fatal(err)
	}
	if res, err := ForwardAudit(); err != nil || res.Sent != 0 {
		t.Fatalf("nothing new: %+v %v", res, err)
	}
	// From the start: everything still kept.
	if err := SetAuditForward(c.srv.URL+"/ingest", ForwardOptions{Token: "tok-123", CAPEM: c.caPEM(), FromStart: true}); err != nil {
		t.Fatal(err)
	}
	res, err := ForwardAudit()
	if err != nil || res.Sent != 3 {
		t.Fatalf("from the start: %+v %v", res, err)
	}
	if got := c.seqs(); len(got) != 3 || got[0] != 1 || got[2] != 3 {
		t.Fatalf("received %v", got)
	}
	l := c.lines[2]
	if c.auth[0] != "Bearer tok-123" || l["source"] != "bb-audit" || l["hash"] == "" || l["prev"] == "" || l["text_sha"] == nil {
		t.Fatalf("a forwarded record: %v, auth %q", l, c.auth[0])
	}
	if _, has := l["text"]; has {
		t.Fatal("statement text went without being asked for")
	}
	if st, _ := os.Stat(forwardTokenPath()); st == nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the token is not kept 0600: %v", st)
	}
	if b, _ := os.ReadFile(auditSettingsPath()); strings.Contains(string(b), "tok-123") {
		t.Fatal("the token is in the settings")
	}

	// Nothing new: nothing sent again.
	if res, err := ForwardAudit(); err != nil || res.Sent != 0 {
		t.Fatalf("again: %+v %v", res, err)
	}

	// The collector fails: the records wait, the failure is kept and, after
	// five minutes, a finding.
	seed(t, "2026-11-05", lineObject, lineError)
	c.fail = 503
	if _, err := ForwardAudit(); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("a 503: %v", err)
	}
	st := AuditForwardStatus()
	if st.Position != 3 || st.Waiting != 2 || st.LastErr == "" || st.Host != strings.TrimPrefix(c.srv.URL, "https://") {
		t.Fatalf("status while failing: %+v", st)
	}
	fs := loadForwardState()
	in := findingsInput{Now: time.Now(), Forward: LoadAuditSettings().Forward, FState: fs}
	in.State, _ = loadAuditState()
	if f := forwardFindings(in); len(f) != 0 {
		t.Fatalf("a failure a moment old is not yet a finding: %+v", f)
	}
	in.Now = time.Now().Add(6 * time.Minute)
	if f := forwardFindings(in); len(f) != 1 || f[0].Kind != "forward" || !strings.Contains(f[0].Detail, "2 wait") {
		t.Fatalf("a failure for six minutes: %+v", f)
	}
	c.fail = 0
	if res, err := ForwardAudit(); err != nil || res.Sent != 2 {
		t.Fatalf("working again: %+v %v", res, err)
	}
	if got := c.seqs(); len(got) != 5 || got[4] != 5 {
		t.Fatalf("after the failure: %v", got)
	}
	if st := AuditForwardStatus(); st.LastErr != "" || st.Waiting != 0 || st.Sent != 5 {
		t.Fatalf("caught up: %+v", st)
	}

	// Asked for, the text goes too.
	if err := SetAuditForward(c.srv.URL, ForwardOptions{CAPEM: c.caPEM(), Text: true, FromStart: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := ForwardAudit(); err != nil {
		t.Fatal(err)
	}
	if l := c.lines[7]; l["text"] != "UPDATE orders SET a = 1, b = 'x'" {
		t.Fatalf("with text: %v", l)
	}
	if c.auth[len(c.auth)-1] != "" {
		t.Fatal("a token sent after forwarding was set without one")
	}

	// Off: the token and CA go with it.
	if err := StopAuditForward(); err != nil || AuditForwardStatus() != nil {
		t.Fatalf("off: %v", err)
	}
	if _, err := os.Stat(forwardCAPath()); !os.IsNotExist(err) {
		t.Fatal("the CA bundle was kept after forwarding stopped")
	}
}

func TestForwardTrustsOnlyWhatItIsGiven(t *testing.T) {
	forwardIn(t)
	c := newCollector(t)
	seed(t, "2026-11-04", lineObject)
	if err := SetAuditForward(c.srv.URL, ForwardOptions{FromStart: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := ForwardAudit(); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a certificate nobody trusts: %v", err)
	}
	if len(c.seqs()) != 0 {
		t.Fatal("records went to a server whose certificate was not trusted")
	}
}

func TestForwardDoesNotFollowRedirects(t *testing.T) {
	forwardIn(t)
	c := newCollector(t)
	moved := httptest.NewTLSServer(http.RedirectHandler(c.srv.URL, http.StatusTemporaryRedirect))
	t.Cleanup(moved.Close)
	seed(t, "2026-11-04", lineObject)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: moved.Certificate().Raw})
	if err := SetAuditForward(moved.URL, ForwardOptions{CAPEM: ca, Token: "tok", FromStart: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := ForwardAudit(); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("a redirect: %v", err)
	}
}

func TestForwardCountsWhatRetentionRemoved(t *testing.T) {
	forwardIn(t)
	c := newCollector(t)
	seed(t, "2026-10-01", lineObject, lineTxn)
	seed(t, "2026-11-04", lineObject)
	if err := SetAuditForward(c.srv.URL, ForwardOptions{CAPEM: c.caPEM(), FromStart: true}); err != nil {
		t.Fatal(err)
	}
	// Retention takes the first day before anything was sent.
	s, _ := loadAuditState()
	if _, err := pruneDays(&s, "2026-11-01"); err != nil {
		t.Fatal(err)
	}
	if err := saveAuditState(s); err != nil {
		t.Fatal(err)
	}
	res, err := ForwardAudit()
	if err != nil || res.Sent != 1 || res.Skipped != 2 {
		t.Fatalf("after retention: %+v %v", res, err)
	}
	in := findingsInput{Now: time.Now(), Forward: LoadAuditSettings().Forward, FState: loadForwardState()}
	if f := forwardFindings(in); len(f) != 1 || !strings.Contains(f[0].Detail, "2 record(s) were removed by retention") {
		t.Fatalf("the finding: %+v", f)
	}
}

func TestForwardSyslog(t *testing.T) {
	forwardIn(t)
	cert, caPEM := selfSigned(t, "127.0.0.1")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		got <- readFrames(conn)
	}()
	seed(t, "2026-11-04", lineObject, lineError)
	if err := SetAuditForward("syslog://"+ln.Addr().String(), ForwardOptions{CAPEM: caPEM, FromStart: true}); err != nil {
		t.Fatal(err)
	}
	if res, err := ForwardAudit(); err != nil || res.Sent != 2 {
		t.Fatalf("syslog: %+v %v", res, err)
	}
	var frames []string
	select {
	case frames = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("the receiver got nothing")
	}
	if len(frames) != 2 {
		t.Fatalf("frames: %q", frames)
	}
	// <13*8+6>1 TIMESTAMP HOST APP PROCID MSGID SD MSG
	f := strings.SplitN(frames[0], " ", 8)
	if f[0] != "<110>1" || f[1] != "2026-11-04T10:00:01.500000Z" || f[3] != "bb-audit" || f[4] != "-" || f[5] != "statement" || f[6] != "-" {
		t.Fatalf("an RFC 5424 header: %q", f[:7])
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(f[7]), &m); err != nil || m["seq"].(float64) != 1 || m["object"] != "public.orders" {
		t.Fatalf("the message: %s %v", f[7], err)
	}
	if !strings.HasPrefix(frames[1], "<109>1 ") || !strings.Contains(frames[1], " outcome - ") {
		t.Fatalf("an error is a notice: %q", frames[1])
	}
}

func TestSyslogSeverity(t *testing.T) {
	m, err := syslogMessage(forwardedRecord{AuditRecord: AuditRecord{Kind: "gap", Time: "2026-11-04T10:00:00Z"}}, "h")
	if err != nil || !strings.HasPrefix(string(m), "<108>1 2026-11-04T10:00:00.000000Z h bb-audit - gap - {") {
		t.Fatalf("a gap is a warning: %s %v", m, err)
	}
}

// readFrames reads RFC 5425's octet-counted frames until the client closes.
func readFrames(r io.Reader) []string {
	br := bufio.NewReader(r)
	var out []string
	for {
		n, err := br.ReadString(' ')
		if err != nil {
			return out
		}
		size, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return append(out, "bad frame length "+n)
		}
		b := make([]byte, size)
		if _, err := io.ReadFull(br, b); err != nil {
			return out
		}
		out = append(out, string(b))
	}
}

func selfSigned(t *testing.T, ip string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "syslog test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP(ip)}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
