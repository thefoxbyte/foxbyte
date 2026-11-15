// SPDX-License-Identifier: AGPL-3.0-or-later

package secrets

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The backup encryption key: the key wal-g encrypts the WAL archive and base
// backups with before they leave for a remote bucket (libsodium, client side),
// so a bucket that is read by someone else holds nothing they can use.
//
// It lives in a file of its own beside secrets.json rather than inside it. The
// engine and the gateway both rewrite secrets.json when a field is missing, and
// each keeps what it read in memory; a key added there could be replaced by a
// process that generated a different one at the same moment, and a backup
// encrypted with a key nobody kept is a backup lost. This file is created once,
// exclusively, and never rewritten except by an explicit import.
//
// Losing this file loses every encrypted backup: the key is not in the bucket,
// by design. `fox backup key export` prints it so it can be kept somewhere
// that is neither this machine nor the bucket.

const backupKeyFile = "backup-encryption.key"

// backupKeyBytes is what wal-g's libsodium crypter wants: exactly 32 bytes,
// given to it hex-encoded (WALG_LIBSODIUM_KEY_TRANSFORM=hex).
const backupKeyBytes = 32

// ErrNoBackupKey is the key file not being there.
var ErrNoBackupKey = errors.New("no backup encryption key on this machine")

// BackupKeyPath is where the key is kept (0600).
func BackupKeyPath() string { return filepath.Join(configDir(), backupKeyFile) }

// BackupKey reads the key, hex-encoded. It is never generated here: a reader
// that made up a fresh key would encrypt new backups with a key the old ones
// do not open.
func BackupKey() (string, error) {
	b, err := os.ReadFile(BackupKeyPath())
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNoBackupKey
	}
	if err != nil {
		return "", err
	}
	k := strings.TrimSpace(string(b))
	if err := CheckBackupKey(k); err != nil {
		return "", fmt.Errorf("%s: %w", BackupKeyPath(), err)
	}
	return k, nil
}

// EnsureBackupKey returns the key, making it the first time. The file is
// created exclusively, so two processes that race to make it end up with the
// one that won, never with one each.
func EnsureBackupKey() (string, error) {
	if k, err := BackupKey(); !errors.Is(err, ErrNoBackupKey) {
		return k, err
	}
	b := make([]byte, backupKeyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating the backup key: %w", err)
	}
	if err := writeKeyExclusive(hex.EncodeToString(b)); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	return BackupKey()
}

// ImportBackupKey installs a key exported from another machine (or kept from
// this one), for restoring after the original was lost. It replaces a key
// already here only when replace is set: that key may be the only one that
// opens backups taken since.
func ImportBackupKey(key string, replace bool) error {
	key = strings.TrimSpace(key)
	if err := CheckBackupKey(key); err != nil {
		return err
	}
	cur, err := BackupKey()
	switch {
	case err == nil && cur == key:
		return nil
	case err == nil && !replace:
		return fmt.Errorf("a different backup key is already at %s (key id %s); it may be the only key for backups taken since — pass --replace only once it is kept somewhere else",
			BackupKeyPath(), BackupKeyID(cur))
	case err != nil && !errors.Is(err, ErrNoBackupKey) && !replace:
		return err
	}
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(configDir(), "."+backupKeyFile+"-*")
	if err != nil {
		return err
	}
	_, werr := tmp.WriteString(key + "\n")
	cerr := tmp.Close()
	if werr == nil && cerr == nil {
		if err := os.Chmod(tmp.Name(), 0o600); err == nil {
			if err := os.Rename(tmp.Name(), BackupKeyPath()); err == nil {
				return nil
			}
		}
	}
	_ = os.Remove(tmp.Name())
	return errors.Join(werr, cerr, fmt.Errorf("could not write %s", BackupKeyPath()))
}

func writeKeyExclusive(key string) error {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(BackupKeyPath(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(key + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		// A half-written key must not stay behind to be read as the key.
		_ = os.Remove(BackupKeyPath())
	}
	return werr
}

// CheckBackupKey checks a key's form: 32 bytes, hex-encoded.
func CheckBackupKey(k string) error {
	b, err := hex.DecodeString(k)
	if err != nil || len(b) != backupKeyBytes {
		return fmt.Errorf("a backup key is %d hex characters", 2*backupKeyBytes)
	}
	return nil
}

// BackupKeyID names a key without revealing it, so the backup target can
// record which key its archive was written with and a different one is
// noticed before it is used.
func BackupKeyID(k string) string {
	sum := sha256.Sum256([]byte("foxbyte backup key id\x00" + k))
	return hex.EncodeToString(sum[:8])
}
