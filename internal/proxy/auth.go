// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"github.com/thefoxbyte/foxbyte/internal/secrets"
)

// backendPassword is the Postgres role password for every branch. It is the
// per-install secret (internal/secrets) that the engine also sets on the
// containers — not a hardcoded default. The Gateway authenticates the client
// with an API key, then logs in to the backend on their behalf using this, so
// the real DB password never leaves the Gateway and clients only present a key.
func backendPassword() string { return secrets.Load().PGPassword }

// --- low-level message framing (post-startup Postgres protocol) ---

func readMsg(c net.Conn) (byte, []byte, error) {
	h := make([]byte, 5)
	if _, err := io.ReadFull(c, h); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:5])
	if n < 4 || n > 1<<24 {
		return 0, nil, fmt.Errorf("bad message length %d", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(c, body); err != nil {
		return 0, nil, err
	}
	return h[0], body, nil
}

func writeMsg(c net.Conn, typ byte, body []byte) error {
	out := make([]byte, 5+len(body))
	out[0] = typ
	binary.BigEndian.PutUint32(out[1:], uint32(4+len(body)))
	copy(out[5:], body)
	_, err := c.Write(out)
	return err
}

// --- client side: ask for a password and return it (expected to be an API key) ---

// requestClientPassword sends AuthenticationCleartextPassword and reads the
// client's PasswordMessage, returning the supplied secret.
func requestClientPassword(client net.Conn) (string, error) {
	req := make([]byte, 4)
	binary.BigEndian.PutUint32(req, 3) // AuthenticationCleartextPassword
	if err := writeMsg(client, 'R', req); err != nil {
		return "", err
	}
	typ, body, err := readMsg(client)
	if err != nil {
		return "", err
	}
	if typ != 'p' {
		return "", fmt.Errorf("expected PasswordMessage, got %q", typ)
	}
	return string(bytes.TrimRight(body, "\x00")), nil
}

// writeAuthOk tells the client authentication succeeded.
func writeAuthOk(client net.Conn) error {
	return writeMsg(client, 'R', make([]byte, 4)) // AuthenticationOk (code 0)
}

// --- backend side: log in to the branch's Postgres on the client's behalf ---

// backendAuth completes the backend's startup + authentication handshake up to
// (and including) AuthenticationOk, leaving the connection positioned right
// before the backend's ParameterStatus/BackendKeyData/ReadyForQuery messages —
// which the caller then pipes straight through to the client.
//
// password is the credential for params["user"]: the per-install secret for an
// ordinary client (backendPassword), or a branch's derived agent password when
// the Gateway logs in as that branch's own agent role.
func backendAuth(backend net.Conn, params map[string]string, password string) error {
	if _, err := backend.Write(buildStartup(params)); err != nil {
		return err
	}
	for {
		typ, body, err := readMsg(backend)
		if err != nil {
			return err
		}
		if typ == 'E' {
			return fmt.Errorf("backend refused connection")
		}
		if typ != 'R' || len(body) < 4 {
			return fmt.Errorf("unexpected message %q during backend auth", typ)
		}
		switch code := binary.BigEndian.Uint32(body[:4]); code {
		case 0: // AuthenticationOk
			return nil
		case 3: // cleartext password
			if err := writeMsg(backend, 'p', append([]byte(password), 0)); err != nil {
				return err
			}
		case 5: // md5 password
			if len(body) < 8 {
				return fmt.Errorf("short md5 auth message")
			}
			token := md5Password(params["user"], password, body[4:8])
			if err := writeMsg(backend, 'p', append([]byte(token), 0)); err != nil {
				return err
			}
		case 10: // SASL (SCRAM-SHA-256)
			if err := scramSHA256(backend, body[4:], password); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported backend auth method %d", code)
		}
	}
}

func md5Password(user, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + user))
	outer := md5.Sum(append([]byte(hex(inner[:])), salt...))
	return "md5" + hex(outer[:])
}

func hex(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0xf]
	}
	return string(out)
}

// scramSHA256 performs the SCRAM-SHA-256 exchange with the backend, consuming
// the server-final message so the next backend message is AuthenticationOk.
func scramSHA256(backend net.Conn, mechanisms []byte, password string) error {
	if !bytes.Contains(mechanisms, []byte("SCRAM-SHA-256")) {
		return fmt.Errorf("backend did not offer SCRAM-SHA-256")
	}
	clientNonce, err := nonce()
	if err != nil {
		return err
	}
	clientFirstBare := "n=,r=" + clientNonce
	clientFirst := "n,," + clientFirstBare

	// SASLInitialResponse: mechanism name, then the initial client message.
	var init []byte
	init = append(init, "SCRAM-SHA-256"...)
	init = append(init, 0)
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(clientFirst)))
	init = append(init, l...)
	init = append(init, clientFirst...)
	if err := writeMsg(backend, 'p', init); err != nil {
		return err
	}

	// AuthenticationSASLContinue: server-first-message.
	typ, body, err := readMsg(backend)
	if err != nil {
		return err
	}
	if typ != 'R' || binary.BigEndian.Uint32(body[:4]) != 11 {
		return fmt.Errorf("expected SASLContinue")
	}
	serverFirst := string(body[4:])
	attrs := scramAttrs(serverFirst)
	serverNonce, salt64, iterStr := attrs["r"], attrs["s"], attrs["i"]
	if !strings.HasPrefix(serverNonce, clientNonce) {
		return fmt.Errorf("server nonce mismatch")
	}
	salt, err := base64.StdEncoding.DecodeString(salt64)
	if err != nil {
		return err
	}
	iters, err := strconv.Atoi(iterStr)
	if err != nil {
		return err
	}

	saltedPassword := pbkdf2.Key([]byte(password), salt, iters, sha256.Size, sha256.New)
	clientKey := hmacSum(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientFinalNoProof := "c=biws,r=" + serverNonce
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalNoProof
	clientSignature := hmacSum(storedKey[:], []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSignature[i]
	}
	clientFinal := clientFinalNoProof + ",p=" + base64.StdEncoding.EncodeToString(proof)
	if err := writeMsg(backend, 'p', []byte(clientFinal)); err != nil {
		return err
	}

	// AuthenticationSASLFinal (server signature) — consume it.
	typ, _, err = readMsg(backend)
	if err != nil {
		return err
	}
	if typ != 'R' {
		return fmt.Errorf("expected SASLFinal")
	}
	return nil
}

func hmacSum(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func scramAttrs(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		if i := strings.IndexByte(part, '='); i > 0 {
			out[part[:i]] = part[i+1:]
		}
	}
	return out
}

func nonce() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ledgerOptions builds the Postgres startup `options` string that injects
// attribution settings for the Blackbox (read in-DB via
// current_setting('foxbyte.*')). It appends to any options the client sent.
// The values here (email, branch name, alphanumeric session) contain no spaces,
// so no escaping is required.
//
// ownSession adds a fresh bb.session for this connection. An agent's
// branch-scoped key passes false: an agent branch created with provenance keeps
// its session, task and parent as database defaults (branch.sessionDefaultsSQL),
// and a session set here would override the database's, so the agent's changes
// would no longer carry the session it was created with.
func ledgerOptions(existing, actor, branch string, ownSession bool) string {
	parts := []string{}
	if existing != "" {
		parts = append(parts, existing)
	}
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, "-c", k+"="+v)
		}
	}
	add("bb.actor", actor)
	// Attribute by the branch it routes to: an agent branch is an agent's, so its
	// DDL is recorded as agent activity rather than hardcoded "human". (Agent
	// branches are created by the Agent Branch API and named "agent-<id>".)
	kind := "human"
	if strings.HasPrefix(branch, "agent-") {
		kind = "agent"
	}
	add("bb.actor_kind", kind)
	add("bb.branch", branch)
	if ownSession {
		sid, _ := nonce()
		add("bb.session", strings.NewReplacer("+", "", "/", "", "=", "").Replace(sid))
	}
	return strings.Join(parts, " ")
}
