//go:build enterprise && cgo && linux

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package hsm

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/pkcs11"
)

// Token is a logged-in PKCS#11 token with a pool of sessions. Every call takes
// a session for itself, so calls run in parallel up to the pool's size.
type Token struct {
	ctx   *pkcs11.Ctx
	slot  uint
	info  pkcs11.TokenInfo
	pool  chan pkcs11.SessionHandle
	delay time.Duration

	mu   sync.Mutex
	keys map[string]*key
}

type key struct {
	h pkcs11.ObjectHandle
	// in is held for reading by every call that uses the key, and for writing
	// by Destroy, so a key is never destroyed under a call in flight.
	in   sync.RWMutex
	uses atomic.Int64
	gone bool
}

// Info is the token as it describes itself.
type Info struct {
	Label, Maker, Model, Serial string
}

// Software reports whether the token is FoxByte's own software one, which no
// kind requiring an HSM may call compliant.
func (i Info) Software() bool { return strings.Contains(strings.ToLower(i.Maker), "softhsm") }

// Attrs are a key's protections as the token reports them back.
type Attrs struct {
	Sensitive, Extractable, AlwaysSensitive, NeverExtractable, Local bool
}

// ErrNotVerified is a ciphertext the token would not decrypt: changed, or
// under another kind or reference key. Tokens differ in the code they give
// (SoftHSM2 answers CKR_GENERAL_ERROR), so any decrypt failure is this.
var ErrNotVerified = errors.New("did not verify")

// Open loads lib, finds the token labelled label, logs in with pin, and opens
// sessions sessions. delay, for the prototype only, is added before every
// call to the token, to stand for a network HSM's round trip.
func Open(lib, label, pin string, sessions int, delay time.Duration) (*Token, error) {
	ctx := pkcs11.New(lib)
	if ctx == nil {
		return nil, fmt.Errorf("could not load the PKCS#11 library %s", lib)
	}
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("initialising %s: %w", lib, err)
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, err
	}
	t := &Token{ctx: ctx, delay: delay, keys: map[string]*key{}}
	found := false
	for _, s := range slots {
		ti, err := ctx.GetTokenInfo(s)
		if err == nil && strings.TrimSpace(ti.Label) == label {
			t.slot, t.info, found = s, ti, true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("no token labelled %q", label)
	}
	if sessions < 1 {
		sessions = 1
	}
	t.pool = make(chan pkcs11.SessionHandle, sessions)
	for i := 0; i < sessions; i++ {
		sh, err := ctx.OpenSession(t.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return nil, fmt.Errorf("opening session %d: %w", i+1, err)
		}
		if i == 0 {
			// Logging in is the token's, not the session's: every session opened
			// by this process is logged in with it.
			if err := ctx.Login(sh, pkcs11.CKU_USER, pin); err != nil && !isAlreadyLoggedIn(err) {
				return nil, fmt.Errorf("logging in to %q: %w", label, err)
			}
		}
		t.pool <- sh
	}
	return t, nil
}

func isAlreadyLoggedIn(err error) bool {
	var e pkcs11.Error
	return errors.As(err, &e) && e == pkcs11.CKR_USER_ALREADY_LOGGED_IN
}

// Info describes the token.
func (t *Token) Info() Info {
	return Info{
		Label:  strings.TrimSpace(t.info.Label),
		Maker:  strings.TrimSpace(t.info.ManufacturerID),
		Model:  strings.TrimSpace(t.info.Model),
		Serial: strings.TrimSpace(t.info.SerialNumber),
	}
}

func (t *Token) with(fn func(pkcs11.SessionHandle) error) error {
	sh := <-t.pool
	defer func() { t.pool <- sh }()
	if t.delay > 0 {
		time.Sleep(t.delay)
	}
	return fn(sh)
}

// Find looks up a secret key by label, and remembers its handle.
func (t *Token) Find(label string) (bool, error) {
	var hs []pkcs11.ObjectHandle
	err := t.with(func(sh pkcs11.SessionHandle) error {
		if err := t.ctx.FindObjectsInit(sh, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		}); err != nil {
			return err
		}
		var err error
		hs, _, err = t.ctx.FindObjects(sh, 2)
		if ferr := t.ctx.FindObjectsFinal(sh); err == nil {
			err = ferr
		}
		return err
	})
	if err != nil {
		return false, err
	}
	switch len(hs) {
	case 0:
		return false, nil
	case 1:
		t.remember(label, hs[0])
		return true, nil
	}
	return false, fmt.Errorf("two keys are labelled %q", label)
}

func (t *Token) remember(label string, h pkcs11.ObjectHandle) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if k, ok := t.keys[label]; ok {
		k.h, k.gone = h, false
		return
	}
	t.keys[label] = &key{h: h}
}

func (t *Token) key(label string) (*key, error) {
	t.mu.Lock()
	k, ok := t.keys[label]
	t.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no key %q", label)
	}
	return k, nil
}

// MakeAES makes a 256-bit AES key inside the token that can never leave it.
func (t *Token) MakeAES(label string) error {
	return t.make(label, pkcs11.CKM_AES_KEY_GEN, pkcs11.CKK_AES,
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true), pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true))
}

// MakeHMAC makes a 256-bit HMAC key inside the token that can never leave it.
func (t *Token) MakeHMAC(label string) error {
	return t.make(label, pkcs11.CKM_GENERIC_SECRET_KEY_GEN, pkcs11.CKK_GENERIC_SECRET,
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true), pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true))
}

func (t *Token) make(label string, mech, keyType uint, use ...*pkcs11.Attribute) error {
	tmpl := append([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}, use...)
	var h pkcs11.ObjectHandle
	err := t.with(func(sh pkcs11.SessionHandle) error {
		var err error
		h, err = t.ctx.GenerateKey(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}, tmpl)
		return err
	})
	if err != nil {
		return fmt.Errorf("making key %q: %w", label, err)
	}
	t.remember(label, h)
	return nil
}

// Attrs reads a key's protections back from the token.
func (t *Token) Attrs(label string) (Attrs, error) {
	k, err := t.key(label)
	if err != nil {
		return Attrs{}, err
	}
	k.in.RLock()
	defer k.in.RUnlock()
	if k.gone {
		return Attrs{}, nil
	}
	var a []*pkcs11.Attribute
	err = t.with(func(sh pkcs11.SessionHandle) error {
		var err error
		a, err = t.ctx.GetAttributeValue(sh, k.h, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_SENSITIVE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_NEVER_EXTRACTABLE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LOCAL, nil),
		})
		return err
	})
	if err != nil {
		return Attrs{}, err
	}
	b := func(i int) bool { return len(a[i].Value) == 1 && a[i].Value[0] != 0 }
	return Attrs{Sensitive: b(0), Extractable: b(1), AlwaysSensitive: b(2), NeverExtractable: b(3), Local: b(4)}, nil
}

// Random draws n bytes from the token's generator.
func (t *Token) Random(n int) ([]byte, error) {
	var b []byte
	err := t.with(func(sh pkcs11.SessionHandle) error {
		var err error
		b, err = t.ctx.GenerateRandom(sh, n)
		return err
	})
	return b, err
}

// Encrypt encrypts plain with AES-256-GCM under the key labelled label, with
// aad as associated data and a 96-bit nonce from the token. It returns the
// nonce the token used (some tokens choose their own) and the ciphertext with
// its 128-bit tag.
func (t *Token) Encrypt(label string, aad, plain []byte) (nonce, ct []byte, err error) {
	k, err := t.key(label)
	if err != nil {
		return nil, nil, err
	}
	k.in.RLock()
	defer k.in.RUnlock()
	if k.gone {
		return nil, nil, fmt.Errorf("key %q was destroyed", label)
	}
	iv, err := t.Random(12)
	if err != nil {
		return nil, nil, err
	}
	err = t.with(func(sh pkcs11.SessionHandle) error {
		p := pkcs11.NewGCMParams(iv, aad, 128)
		defer p.Free()
		if err := t.ctx.EncryptInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, p)}, k.h); err != nil {
			return err
		}
		var err error
		if ct, err = t.ctx.Encrypt(sh, plain); err != nil {
			return err
		}
		if used := p.IV(); len(used) == 12 {
			nonce = used
		} else {
			nonce = iv
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("encrypting under %q: %w", label, err)
	}
	k.uses.Add(1)
	return nonce, ct, nil
}

// Decrypt reverses Encrypt; any failure of the tag is ErrNotVerified.
func (t *Token) Decrypt(label string, nonce, aad, ct []byte) ([]byte, error) {
	k, err := t.key(label)
	if err != nil {
		return nil, err
	}
	k.in.RLock()
	defer k.in.RUnlock()
	if k.gone {
		return nil, fmt.Errorf("key %q was destroyed", label)
	}
	var plain []byte
	err = t.with(func(sh pkcs11.SessionHandle) error {
		p := pkcs11.NewGCMParams(nonce, aad, 128)
		defer p.Free()
		if err := t.ctx.DecryptInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, p)}, k.h); err != nil {
			return err
		}
		var err error
		plain, err = t.ctx.Decrypt(sh, ct)
		if err != nil {
			return ErrNotVerified
		}
		return nil
	})
	return plain, err
}

// HMAC is HMAC-SHA-256 of data under the key labelled label.
func (t *Token) HMAC(label string, data []byte) ([]byte, error) {
	k, err := t.key(label)
	if err != nil {
		return nil, err
	}
	k.in.RLock()
	defer k.in.RUnlock()
	if k.gone {
		return nil, fmt.Errorf("key %q was destroyed", label)
	}
	var mac []byte
	err = t.with(func(sh pkcs11.SessionHandle) error {
		if err := t.ctx.SignInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_HMAC, nil)}, k.h); err != nil {
			return err
		}
		var err error
		mac, err = t.ctx.Sign(sh, data)
		return err
	})
	return mac, err
}

// Uses is how many times the key has encrypted since this process began,
// added to base by the caller.
func (t *Token) Uses(label string) int64 {
	k, err := t.key(label)
	if err != nil {
		return 0
	}
	return k.uses.Load()
}

// Destroy destroys the key in the token once no call is using it.
func (t *Token) Destroy(label string) error {
	k, err := t.key(label)
	if err != nil {
		return err
	}
	k.in.Lock()
	defer k.in.Unlock()
	if k.gone {
		return nil
	}
	if err := t.with(func(sh pkcs11.SessionHandle) error { return t.ctx.DestroyObject(sh, k.h) }); err != nil {
		return fmt.Errorf("destroying %q: %w", label, err)
	}
	k.gone = true
	return nil
}

// Close logs out and closes every session.
func (t *Token) Close() {
	for i := 0; i < cap(t.pool); i++ {
		sh := <-t.pool
		if i == 0 {
			_ = t.ctx.Logout(sh)
		}
		_ = t.ctx.CloseSession(sh)
	}
	_ = t.ctx.Finalize()
	t.ctx.Destroy()
}

// ErrTokenExists is a token already labelled so.
var ErrTokenExists = errors.New("a token with that label exists already")

// InitToken makes a token: it initialises the first slot holding no token
// yet, labels it, and sets its security officer's and user's PINs. It is how
// FoxByte's own software token is made, so the PINs come from files and never
// reach a command line.
func InitToken(lib, label, soPin, pin string) error {
	ctx := pkcs11.New(lib)
	if ctx == nil {
		return fmt.Errorf("could not load the PKCS#11 library %s", lib)
	}
	if err := ctx.Initialize(); err != nil {
		return err
	}
	defer func() { _ = ctx.Finalize(); ctx.Destroy() }()
	slots, err := ctx.GetSlotList(false)
	if err != nil {
		return err
	}
	free, found := uint(0), false
	for _, s := range slots {
		ti, err := ctx.GetTokenInfo(s)
		if err != nil {
			continue
		}
		inited := ti.Flags&pkcs11.CKF_TOKEN_INITIALIZED != 0
		if inited && strings.TrimSpace(ti.Label) == label {
			return ErrTokenExists
		}
		if !inited && !found {
			free, found = s, true
		}
	}
	if !found {
		return errors.New("the PKCS#11 library offers no free slot")
	}
	if err := ctx.InitToken(free, soPin, label); err != nil {
		return fmt.Errorf("initialising the token: %w", err)
	}
	// A software token moves to a slot of its own once initialised: find it
	// again by its label.
	if slots, err = ctx.GetSlotList(true); err != nil {
		return err
	}
	for _, s := range slots {
		ti, err := ctx.GetTokenInfo(s)
		if err != nil || strings.TrimSpace(ti.Label) != label {
			continue
		}
		sh, err := ctx.OpenSession(s, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return err
		}
		defer func() { _ = ctx.CloseSession(sh) }()
		if err := ctx.Login(sh, pkcs11.CKU_SO, soPin); err != nil {
			return fmt.Errorf("logging in as the security officer: %w", err)
		}
		if err := ctx.InitPIN(sh, pin); err != nil {
			return fmt.Errorf("setting the user's PIN: %w", err)
		}
		return ctx.Logout(sh)
	}
	return errors.New("the token was initialised but cannot be found by its label")
}
