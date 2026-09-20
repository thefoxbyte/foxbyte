// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tlsutil provides a single self-signed TLS certificate that every
// FoxByte listener (the wire-protocol gateway, the control-plane API, and the
// agent API) serves. The cert is generated once on first use and cached under
// ~/.fox/tls, so a fresh install serves TLS with nothing to configure.
//
// The point is not a trusted chain — it is encryption on the wire. A client
// connecting with sslmode=require (Prisma's default, and most cloud drivers)
// gets an encrypted session and its API key never crosses the network in
// cleartext. sslmode=verify-full needs a CA-signed cert; point FOX_TLS_CERT
// and FOX_TLS_KEY at one to use it instead of the generated pair.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/foxbyte/foxbyte/internal/brand"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	envCert = "FOX_TLS_CERT"
	envKey  = "FOX_TLS_KEY"
)

var (
	mu       sync.Mutex
	cachedC  string
	cachedK  string
	cachedTC *tls.Config
)

// configDir returns ~/.fox, matching the convention used across the
// codebase (auth store, daemon pidfiles). Falls back to /tmp when the home
// directory is unavailable, as those callers do.
func configDir() string {
	return brand.StateDir()
}

// EnsureCert returns the paths to a servable cert/key pair, generating a
// self-signed pair under ~/.fox/tls on first use. FOX_TLS_CERT and
// FOX_TLS_KEY override it with an existing (e.g. CA-signed) pair; both
// must be set together. The result is cached for the process.
func EnsureCert() (certPath, keyPath string, err error) {
	mu.Lock()
	defer mu.Unlock()
	if cachedC != "" && cachedK != "" {
		return cachedC, cachedK, nil
	}

	if c, k := os.Getenv(envCert), os.Getenv(envKey); c != "" || k != "" {
		if c == "" || k == "" {
			return "", "", fmt.Errorf("set both %s and %s, or neither", envCert, envKey)
		}
		cachedC, cachedK = c, k
		return c, k, nil
	}

	dir := filepath.Join(configDir(), "tls")
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if fileExists(certPath) && fileExists(keyPath) {
		cachedC, cachedK = certPath, keyPath
		return certPath, keyPath, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("create tls dir: %w", err)
	}
	// Serialize generation across processes. The gateway, control-plane, and
	// agent API all start together and all call EnsureCert; without a lock they
	// each generate a keypair and interleave writes, leaving a cert.pem and
	// key.pem from different keypairs ("private key does not match public key").
	if err := withFileLock(filepath.Join(dir, ".lock"), func() error {
		if fileExists(certPath) && fileExists(keyPath) {
			return nil // another process generated it while we waited
		}
		return generateSelfSigned(certPath, keyPath)
	}); err != nil {
		return "", "", err
	}
	cachedC, cachedK = certPath, keyPath
	return certPath, keyPath, nil
}

// withFileLock runs fn while holding an exclusive lock file, so only one process
// generates the certificate at a time. A waiter re-checks for the files (fn is a
// no-op if they now exist). A lock older than the timeout is treated as stale
// (its holder died) and stolen.
func withFileLock(lockPath string, fn func() error) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			defer os.Remove(lockPath)
			return fn()
		}
		if !os.IsExist(err) {
			return fmt.Errorf("tls lock: %w", err)
		}
		if time.Now().After(deadline) {
			_ = os.Remove(lockPath) // steal a stale lock
			continue
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ServerConfig returns a *tls.Config that serves the EnsureCert pair. The
// gateway uses it to wrap a raw net.Conn (tls.Server); the HTTP servers use the
// cert/key paths directly with ListenAndServeTLS.
func ServerConfig() (*tls.Config, error) {
	mu.Lock()
	if cachedTC != nil {
		mu.Unlock()
		return cachedTC, nil
	}
	mu.Unlock()

	certPath, keyPath, err := EnsureCert()
	if err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load tls keypair: %w", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}

	mu.Lock()
	cachedTC = cfg
	mu.Unlock()
	return cfg, nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// generateSelfSigned writes a P-256 self-signed cert valid for localhost and the
// loopback addresses — the only names a locally-forwarded connection presents.
func generateSelfSigned(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}
	// A long validity: this is a local, regeneratable cert, not a public one.
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost", Organization: []string{"FoxByte"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}
	return nil
}

func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	return nil
}
