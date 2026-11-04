// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Forwarding the audit log to a SIEM (F6 Gate 1, step 5b; design, sections 9
// and 13).
//
// What goes is the store's records, never the raw files: the SIEM receives no
// more than the store holds, and each record with its sequence number and its
// place in the chain (prev, hash), so the copy there shows a record removed
// or changed here afterwards. Statement text, which forensic mode keeps beside
// the chain, goes only when asked for: once sent it is outside FoxByte's
// retention and purge.
//
// Two ways, both encrypted, since every record names a login:
//
//   - https://… : records as JSON lines, one POST per batch, a 2xx is
//     delivered. A bearer token, if the collector needs one, goes in the
//     Authorization header, never in the URL.
//   - syslog://host[:6514] : RFC 5424 messages over TLS, framed as RFC 5425
//     says (octet counting). Syslog has no acknowledgement: a batch the
//     connection took is counted delivered.
//
// Delivery is at least once. A position beside the store says how far the
// SIEM has got, and moves only once a batch is delivered, so a failure sends
// the batch again later; records wait in the store meanwhile, until their
// retention. Records retention removes before they are sent are counted, and
// a finding (auditfindings.go), as is forwarding that keeps failing.
//
// The token and a CA bundle are copied into files of the engine's own when
// forwarding is set, from the CLI's files or the console's form: nothing
// later makes the engine read a path someone named, so the console's admin
// cannot send a host file anywhere as a "token".

// AuditForward is where records are forwarded, in the settings.
type AuditForward struct {
	URL   string `json:"url"`
	Text  bool   `json:"text,omitempty"`  // forensic mode's statement text too
	CA    bool   `json:"ca,omitempty"`    // a CA bundle of its own, else the system's
	Token bool   `json:"token,omitempty"` // a bearer token (https only)
	By    string `json:"by"`
	Since string `json:"since"` // RFC 3339
}

// ForwardOptions are what setting forwarding takes besides the URL.
type ForwardOptions struct {
	Text      bool
	CAPEM     []byte // empty: the system's CAs
	Token     string // empty: none
	FromStart bool   // every record still kept, rather than from the next one
	By        string
}

// forwardState is how far the SIEM has got, beside the store's own state.
type forwardState struct {
	URL      string `json:"url"`                 // what the position is for
	Seq      int64  `json:"seq"`                 // the last record delivered
	Day      string `json:"day,omitempty"`       // the day file it is in: reading starts there
	Sent     int64  `json:"sent"`                // delivered since forwarding was set
	Skipped  int64  `json:"skipped,omitempty"`   // removed by retention before they were sent
	SkipAt   string `json:"skip_at,omitempty"`   // when that was last found
	LastOK   string `json:"last_ok,omitempty"`   // the last delivery
	LastTry  string `json:"last_try,omitempty"`  // the last attempt
	LastErr  string `json:"last_err,omitempty"`  // why the last attempt failed; "" when it did not
	ErrSince string `json:"err_since,omitempty"` // failing since
}

const (
	forwardBatch    = 500
	forwardPerRun   = 20 // batches per run: 10,000 records a minute
	forwardTimeout  = 30 * time.Second
	forwardLate     = 5 * time.Minute
	syslogPort      = "6514" // RFC 5425
	forwardAppName  = "bb-audit"
	syslogFacility  = 13 // log audit (RFC 5424)
	forwardTokenMax = 8 << 10
)

var (
	forwardCAPath    = func() string { return brand.StatePath("audit-forward-ca.pem") }
	forwardTokenPath = func() string { return brand.StatePath("audit-forward-token") }
)

func forwardStatePath() string { return AuditStoreDir() + "/forward.json" }

// ParseForwardURL checks a forwarding URL: https://… or syslog://host[:port],
// with nothing secret in it.
func ParseForwardURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%q is not a URL: forward to https://… or syslog://host[:port]", raw)
	}
	if u.User != nil {
		return nil, errors.New("the URL holds a user or password: give a token with --token-file instead, which is sent in a header and kept out of logs")
	}
	switch u.Scheme {
	case "https":
	case "syslog", "syslog+tls":
		if u.Path != "" && u.Path != "/" || u.RawQuery != "" {
			return nil, errors.New("a syslog URL is syslog://host[:port], with no path")
		}
	case "http", "udp", "tcp", "syslog+udp", "syslog+tcp":
		return nil, fmt.Errorf("%s:// sends records unencrypted, and every record names a login: use https://, or syslog:// (over TLS)", u.Scheme)
	default:
		return nil, fmt.Errorf("%s:// is not a way to forward: use https://… or syslog://host[:port]", u.Scheme)
	}
	return u, nil
}

// SetAuditForward sets where records are forwarded, replacing what was set.
func SetAuditForward(raw string, o ForwardOptions) error {
	u, err := ParseForwardURL(raw)
	if err != nil {
		return err
	}
	tok := strings.TrimSpace(o.Token)
	if tok != "" && u.Scheme != "https" {
		return errors.New("a token is for https:// only: a syslog server knows its clients by TLS")
	}
	if len(tok) > forwardTokenMax || strings.ContainsAny(tok, "\r\n") {
		return errors.New("the token must be one line, at most 8 KB")
	}
	if len(bytes.TrimSpace(o.CAPEM)) > 0 && !x509.NewCertPool().AppendCertsFromPEM(o.CAPEM) {
		return errors.New("the CA bundle holds no PEM certificate")
	}
	// The store's directory is in the audit log's own dataset. Set before the
	// log was ever turned on, the dataset is made first, with its quota, as
	// setup makes it: never a plain directory where it would be mounted.
	if _, err := os.Stat(AuditStoreDir()); err != nil {
		if err := ensureAuditStore(); err != nil {
			return err
		}
		if err := ensureAuditStoreDir(); err != nil {
			return err
		}
	}
	if err := writeSecret(forwardCAPath(), o.CAPEM); err != nil {
		return err
	}
	if err := writeSecret(forwardTokenPath(), []byte(tok)); err != nil {
		return err
	}

	unlock, err := lockAuditFile("forward.lock")
	if err != nil {
		return err
	}
	defer unlock()
	s, err := loadAuditState()
	if err != nil {
		return err
	}
	fs := forwardState{URL: u.String(), Seq: s.Seq}
	if o.FromStart {
		fs.Seq = s.Base.Seq
	}
	if err := saveForwardState(fs); err != nil {
		return err
	}
	set := LoadAuditSettings()
	set.Forward = &AuditForward{URL: u.String(), Text: o.Text, CA: len(bytes.TrimSpace(o.CAPEM)) > 0, Token: tok != "",
		By: o.By, Since: time.Now().UTC().Format(time.RFC3339)}
	return saveAuditSettings(set)
}

// StopAuditForward stops forwarding, and removes the token and CA it kept.
func StopAuditForward() error {
	set := LoadAuditSettings()
	set.Forward = nil
	if err := saveAuditSettings(set); err != nil {
		return err
	}
	for _, p := range []string{forwardCAPath(), forwardTokenPath(), forwardStatePath()} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// writeSecret writes a file only this user reads, or removes it when b is
// empty.
func writeSecret(path string, b []byte) error {
	if len(bytes.TrimSpace(b)) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadForwardState() forwardState {
	var fs forwardState
	if b, err := os.ReadFile(forwardStatePath()); err == nil {
		_ = json.Unmarshal(b, &fs)
	}
	return fs
}

func saveForwardState(fs forwardState) error {
	b, err := json.MarshalIndent(fs, "", " ")
	if err != nil {
		return err
	}
	tmp := forwardStatePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, forwardStatePath())
}

// ForwardStatus is forwarding as `status`, `fox check` and the console show it.
type ForwardStatus struct {
	*AuditForward
	Host     string `json:"host,omitempty"`
	Position int64  `json:"position"` // the last record delivered
	Head     int64  `json:"head"`     // the last record collected
	Waiting  int64  `json:"waiting"`
	Sent     int64  `json:"sent"`
	Skipped  int64  `json:"skipped,omitempty"`
	LastOK   string `json:"last_ok,omitempty"`
	LastErr  string `json:"last_err,omitempty"`
	ErrSince string `json:"err_since,omitempty"`
}

// AuditForwardStatus reads where forwarding stands; nil when it is not set.
func AuditForwardStatus() *ForwardStatus {
	f := LoadAuditSettings().Forward
	if f == nil {
		return nil
	}
	fs := loadForwardState()
	s, _ := loadAuditState()
	st := &ForwardStatus{AuditForward: f, Position: fs.Seq, Head: s.Seq, Sent: fs.Sent, Skipped: fs.Skipped,
		LastOK: fs.LastOK, LastErr: fs.LastErr, ErrSince: fs.ErrSince}
	if u, err := url.Parse(f.URL); err == nil {
		st.Host = u.Host
	}
	if st.Head > st.Position {
		st.Waiting = st.Head - st.Position
	}
	return st
}

// ForwardResult is what one run of the forwarder did.
type ForwardResult struct {
	Sent    int   // delivered
	Skipped int64 // found removed by retention before they were sent
	Waiting int64 // still to send
}

// forwardedRecord is a record as the SIEM receives it.
type forwardedRecord struct {
	Source string `json:"source"`
	AuditRecord
	Text string `json:"text,omitempty"`
}

// ForwardAudit sends what the SIEM has not had yet, as far as it goes: a
// failure is kept, for the findings, and the records wait for the next run.
// Nothing to do when forwarding is not set.
func ForwardAudit() (ForwardResult, error) {
	var res ForwardResult
	f := LoadAuditSettings().Forward
	if f == nil {
		return res, nil
	}
	if _, err := os.Stat(AuditStoreDir()); err != nil {
		return res, nil // nothing collected yet
	}
	unlock, err := lockAuditFile("forward.lock")
	if err != nil {
		return res, err
	}
	defer unlock()
	fs := loadForwardState()
	if fs.URL != f.URL { // the settings were edited by hand: start from the next record
		s, _ := loadAuditState()
		fs = forwardState{URL: f.URL, Seq: s.Seq}
	}
	send, err := newSender(f)
	if err != nil {
		return res, failForward(&fs, err)
	}
	defer send.close()
	for range forwardPerRun {
		recs, day, skipped, head, err := recordsAfter(fs.Seq, fs.Day, forwardBatch, f.Text)
		if err != nil {
			return res, failForward(&fs, err)
		}
		if skipped > 0 {
			fs.Skipped += skipped
			fs.SkipAt = time.Now().UTC().Format(time.RFC3339)
			res.Skipped += skipped
			log.Printf("audit log: %d record(s) were removed by retention before they could be forwarded", skipped)
		}
		if len(recs) == 0 {
			if head < fs.Seq { // the store was begun again under it: follow it from its start
				fs.Seq, fs.Day = head, ""
			}
			fs.LastErr, fs.ErrSince = "", ""
			fs.LastTry = time.Now().UTC().Format(time.RFC3339)
			return res, saveForwardState(fs)
		}
		if err := send.send(recs); err != nil {
			return res, failForward(&fs, err)
		}
		now := time.Now().UTC().Format(time.RFC3339)
		fs.Seq, fs.Day = recs[len(recs)-1].Seq, day
		fs.Sent += int64(len(recs))
		fs.LastOK, fs.LastTry, fs.LastErr, fs.ErrSince = now, now, "", ""
		res.Sent += len(recs)
		if err := saveForwardState(fs); err != nil {
			return res, err
		}
		res.Waiting = max(0, head-fs.Seq)
		if len(recs) < forwardBatch {
			return res, nil
		}
	}
	return res, nil
}

// failForward keeps why forwarding failed, and says it.
func failForward(fs *forwardState, err error) error {
	now := time.Now().UTC().Format(time.RFC3339)
	fs.LastTry, fs.LastErr = now, err.Error()
	if fs.ErrSince == "" {
		fs.ErrSince = now
	}
	if serr := saveForwardState(*fs); serr != nil {
		return serr
	}
	return err
}

// recordsAfter reads up to n records after seq, starting at the day file the
// last delivered record is in (the day files, read in date order, are the
// chain in order). skipped counts records retention removed after seq;
// head is the last record collected.
func recordsAfter(seq int64, fromDay string, n int, withText bool) (out []forwardedRecord, day string, skipped, head int64, err error) {
	unlock, err := lockAuditStore()
	if err != nil {
		return nil, "", 0, 0, err
	}
	defer unlock()
	s, err := loadAuditState()
	if err != nil {
		return nil, "", 0, 0, err
	}
	head = s.Seq
	if s.Base.Seq > seq {
		skipped, seq = s.Base.Seq-seq, s.Base.Seq
	}
	for _, d := range storedDays() {
		if d < fromDay || len(out) >= n {
			continue
		}
		recs, err := readDay(d)
		if err != nil {
			return nil, "", 0, 0, err
		}
		var texts map[int64]string
		for _, r := range recs {
			if r.Seq <= seq || len(out) >= n {
				continue
			}
			if r.Seq != seq+1 && len(out) == 0 && skipped == 0 {
				skipped = r.Seq - seq - 1
			}
			fr := forwardedRecord{Source: forwardAppName, AuditRecord: r}
			if withText && r.TextSHA != "" {
				if texts == nil {
					texts = dayTexts(d)
				}
				if t, ok := texts[r.Seq]; ok && textMatches(t, r.TextSHA) {
					fr.Text = t
				}
			}
			out = append(out, fr)
			day = d
		}
	}
	return out, day, skipped, head, nil
}

func dayTexts(day string) map[int64]string {
	out := map[int64]string{}
	ts, _ := readForensic(day)
	for _, t := range ts {
		out[t.Seq] = t.Text
	}
	return out
}

func textMatches(text, sha string) bool {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:]) == sha
}

// sender delivers batches to one place.
type sender interface {
	send([]forwardedRecord) error
	close()
}

func newSender(f *AuditForward) (sender, error) {
	u, err := ParseForwardURL(f.URL)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if f.CA {
		pem, err := os.ReadFile(forwardCAPath())
		if err != nil {
			return nil, fmt.Errorf("the CA bundle forwarding was set with is gone (%v): set forwarding again", err)
		}
		tc.RootCAs = x509.NewCertPool()
		if !tc.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("the CA bundle forwarding was set with holds no certificate: set forwarding again")
		}
	}
	if u.Scheme == "https" {
		tok := ""
		if f.Token {
			b, err := os.ReadFile(forwardTokenPath())
			if err != nil {
				return nil, fmt.Errorf("the token forwarding was set with is gone (%v): set forwarding again", err)
			}
			tok = strings.TrimSpace(string(b))
		}
		return &httpsSender{url: u.String(), token: tok, client: &http.Client{
			Timeout:   forwardTimeout,
			Transport: &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment},
			// A redirect is a failure, not followed: it would take the
			// records, and the token, somewhere nobody set.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}}, nil
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), syslogPort)
	}
	tc.ServerName = u.Hostname()
	return &syslogSender{addr: host, tls: tc, host: syslogHostname()}, nil
}

type httpsSender struct {
	url, token string
	client     *http.Client
}

func (h *httpsSender) send(recs []forwardedRecord) error {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(http.MethodPost, h.url, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("User-Agent", forwardAppName)
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending to %s: %w", req.URL.Host, scrubErr(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s answered %s", req.URL.Host, resp.Status)
	}
	return nil
}

func (h *httpsSender) close() { h.client.CloseIdleConnections() }

// scrubErr drops the URL a net/http error repeats: the host is said already,
// and a query string is nobody's business in a log.
func scrubErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

type syslogSender struct {
	addr, host string
	tls        *tls.Config
	conn       *tls.Conn
}

func (s *syslogSender) send(recs []forwardedRecord) error {
	if s.conn == nil {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: forwardTimeout}, "tcp", s.addr, s.tls)
		if err != nil {
			return fmt.Errorf("connecting to %s: %w", s.addr, err)
		}
		s.conn = c
	}
	var buf bytes.Buffer
	for _, r := range recs {
		m, err := syslogMessage(r, s.host)
		if err != nil {
			return err
		}
		buf.WriteString(strconv.Itoa(len(m)))
		buf.WriteByte(' ')
		buf.Write(m)
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(forwardTimeout))
	if _, err := s.conn.Write(buf.Bytes()); err != nil {
		s.conn.Close()
		s.conn = nil
		return fmt.Errorf("sending to %s: %w", s.addr, err)
	}
	return nil
}

// close ends the session properly: TLS's close_notify, then a moment for the
// server to take what it was sent.
func (s *syslogSender) close() {
	if s.conn == nil {
		return
	}
	_ = s.conn.CloseWrite()
	_ = s.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.Copy(io.Discard, s.conn)
	s.conn.Close()
}

// syslogMessage is one record as RFC 5424 has it: the record's JSON is the
// message, its kind the MSGID.
func syslogMessage(r forwardedRecord, host string) ([]byte, error) {
	sev := 6 // informational
	switch {
	case r.Kind == "gap":
		sev = 4 // warning: lines were lost
	case r.Kind == "outcome":
		sev = 5 // notice: an error
	}
	ts := "-"
	if t, err := time.Parse(time.RFC3339Nano, r.Time); err == nil {
		ts = t.UTC().Format("2006-01-02T15:04:05.000000Z") // at most six digits (RFC 5424, 6.2.3)
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	kind := r.Kind
	if kind == "" {
		kind = "-"
	}
	return []byte(fmt.Sprintf("<%d>1 %s %s %s - %s - %s", syslogFacility*8+sev, ts, host, forwardAppName, kind, body)), nil
}

// syslogHostname is this machine's name as RFC 5424 allows it: printable
// ASCII, no spaces, at most 255.
func syslogHostname() string {
	h, _ := os.Hostname()
	var b strings.Builder
	for _, c := range h {
		if c > 32 && c < 127 {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()[:min(b.Len(), 255)]
}
