// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// A backend that speaks just enough SCRAM for the gateway's client. It signs
// with the real server key unless lie is set, which is something on the path
// that does not know the password.
func scramPeer(t *testing.T, password string, lie bool) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(3 * time.Second))
		_, raw, err := readMsg(server)
		if err != nil {
			return
		}
		rest := string(raw)
		i := strings.Index(rest, "n=,r=")
		if i < 0 {
			return
		}
		clientNonce := rest[i+len("n=,r="):]
		salt := []byte("saltsalt")
		serverFirst := "r=" + clientNonce + "srv,s=" + base64.StdEncoding.EncodeToString(salt) + ",i=4096"
		cont := make([]byte, 4+len(serverFirst))
		binary.BigEndian.PutUint32(cont[:4], 11)
		copy(cont[4:], serverFirst)
		if err := writeMsg(server, 'R', cont); err != nil {
			return
		}
		if _, _, err = readMsg(server); err != nil {
			return
		}
		sig := "v=not-the-signature"
		if !lie {
			salted := pbkdf2.Key([]byte(password), salt, 4096, sha256.Size, sha256.New)
			serverKey := hmacSum(salted, []byte("Server Key"))
			bare := "n=,r=" + clientNonce
			authMsg := bare + "," + serverFirst + "," + "c=biws,r=" + clientNonce + "srv"
			sig = "v=" + base64.StdEncoding.EncodeToString(hmacSum(serverKey, []byte(authMsg)))
		}
		fin := make([]byte, 4+len(sig))
		binary.BigEndian.PutUint32(fin[:4], 12)
		copy(fin[4:], sig)
		_ = writeMsg(server, 'R', fin)
	}()
	return client
}

func TestScramChecksTheServerSignature(t *testing.T) {
	good := scramPeer(t, "secret", false)
	defer good.Close()
	_ = good.SetDeadline(time.Now().Add(3 * time.Second))
	if err := scramSHA256(good, []byte("SCRAM-SHA-256\x00"), "secret"); err != nil {
		t.Fatalf("a real server signature was refused: %v", err)
	}
	bad := scramPeer(t, "secret", true)
	defer bad.Close()
	_ = bad.SetDeadline(time.Now().Add(3 * time.Second))
	if err := scramSHA256(bad, []byte("SCRAM-SHA-256\x00"), "secret"); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("a forged server signature: %v", err)
	}
}
