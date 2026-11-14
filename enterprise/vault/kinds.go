//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package vault

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/thefoxbyte/foxbyte/enterprise/idcheck"
)

// A Kind is what a value is (design, section 2). The vault's machinery is the
// same for every kind; what differs is here. A kind is code, not
// configuration: its check and its legacy format decide what is safe to store
// and what can never be mistaken for a real value.
type Kind struct {
	// Name is how callers name the kind: "aadhaar", "text".
	Name string
	// Prefix starts every opaque reference key of the kind: two capitals.
	Prefix string
	// Normal is the value written the one way it is indexed, so the same value
	// is found again; false when it cannot be read as the kind at all.
	Normal func(string) (string, bool)
	// Check reports whether a value, in its normal form, is one of the kind;
	// nil when the kind has no check (text).
	Check func(string) bool
	// Legacy makes a reference key shaped like the kind's values that can never
	// pass Check, for columns that hold nothing else; nil when the kind has no
	// check, and so no legacy format.
	Legacy func(Random) (string, error)
	// IsLegacy reports whether s has the legacy format's shape.
	IsLegacy func(string) bool
	// HSMRequired is whether the kind's rules require an HSM, so that a software
	// token holding it is shown as not compliant.
	HSMRequired bool
	// Rules names the regulation the kind's evidence is checked against; "" when
	// none is mapped.
	Rules string
	// Display shows a value to someone allowed to see it, before they choose to
	// reveal it.
	Display func(string) string
	// MaxLen is the longest value accepted, in bytes, in normal form.
	MaxLen int
	// Describe says what Check accepts, and LegacyDescribe what Legacy
	// makes, in a sentence a person reads.
	Describe, LegacyDescribe string
}

// Random is a source of random bytes: the HSM's generator in the service.
type Random func(n int) ([]byte, error)

// Formats of reference key.
const (
	FormatOpaque = "opaque"
	FormatLegacy = "legacy"
)

var kinds = map[string]*Kind{
	"aadhaar": {
		Name:   "aadhaar",
		Prefix: "AR",
		Normal: func(s string) (string, bool) {
			d, ok := idcheck.Digits(s)
			return d, ok && len(d) == 12
		},
		Check:       idcheck.IsAadhaar,
		Legacy:      aadhaarLegacy,
		IsLegacy:    isAadhaarLegacy,
		HSMRequired: true,
		Rules:       "UIDAI Circular No. 14 of 2025",
		Display: func(s string) string {
			if len(s) < 4 {
				return "****"
			}
			return "XXXX XXXX " + s[len(s)-4:]
		},
		MaxLen:         12,
		Describe:       "12 digits, the first 2 to 9, passing the Verhoeff check (spaces and hyphens allowed)",
		LegacyDescribe: "12 digits starting with 1, which no Aadhaar number does",
	},
	"text": {
		Name:   "text",
		Prefix: "TX",
		Normal: func(s string) (string, bool) {
			return s, s != "" && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
		},
		Display: func(s string) string {
			n := utf8.RuneCountInString(s)
			return fmt.Sprintf("(%d characters)", n)
		},
		MaxLen:   4096,
		Describe: "any text, up to 4,096 bytes, kept exactly as given",
	},
}

// KindOf returns the kind named name.
func KindOf(name string) (*Kind, bool) {
	k, ok := kinds[name]
	return k, ok
}

// Kinds returns every kind, by name.
func Kinds() []*Kind {
	out := make([]*Kind, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ErrRefused is a value the kind does not accept.
var ErrRefused = errors.New("refused")

// Accept returns the value's normal form, or ErrRefused with the reason.
func (k *Kind) Accept(v string) (string, error) {
	n, ok := k.Normal(v)
	if !ok {
		return "", fmt.Errorf("%w: not a %s value", ErrRefused, k.Name)
	}
	if len(n) > k.MaxLen {
		return "", fmt.Errorf("%w: longer than %d bytes", ErrRefused, k.MaxLen)
	}
	if k.Check != nil && !k.Check(n) {
		return "", fmt.Errorf("%w: fails the %s check", ErrRefused, k.Name)
	}
	return n, nil
}

// NewRef makes a reference key of the kind, in format.
func (k *Kind) NewRef(format string, rnd Random) (string, error) {
	switch format {
	case "", FormatOpaque:
		return opaqueRef(k.Prefix, rnd)
	case FormatLegacy:
		if k.Legacy == nil {
			return "", fmt.Errorf("%w: the %s kind has no legacy format", ErrRefused, k.Name)
		}
		return k.Legacy(rnd)
	}
	return "", fmt.Errorf("%w: no format %q (opaque or legacy)", ErrRefused, format)
}

// IsRef reports whether s is shaped like a reference key of the kind.
func (k *Kind) IsRef(s string) bool {
	if isOpaque(k.Prefix, s) {
		return true
	}
	return k.IsLegacy != nil && k.IsLegacy(s)
}

// AAD is the associated data a value is encrypted under: its kind and its
// reference key, so a ciphertext decrypts nowhere else.
func AAD(kind, ref string) []byte { return []byte(kind + "\x00" + ref) }

// --- reference keys ---------------------------------------------------------

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// opaqueChars is how many base32 characters follow an opaque reference key's
// prefix: 26, so 130 random bits.
const opaqueChars = 26

func opaqueRef(prefix string, rnd Random) (string, error) {
	b, err := rnd(17) // 136 bits; the first 130 are used
	if err != nil {
		return "", err
	}
	if len(b) != 17 {
		return "", fmt.Errorf("the random source gave %d bytes, not 17", len(b))
	}
	var sb strings.Builder
	sb.WriteString(prefix)
	acc, bits := uint(0), 0
	for _, x := range b {
		acc = acc<<8 | uint(x)
		bits += 8
		for bits >= 5 && sb.Len() < len(prefix)+opaqueChars {
			bits -= 5
			sb.WriteByte(crockford[(acc>>uint(bits))&31])
		}
		acc &= (1 << uint(bits)) - 1
	}
	return sb.String(), nil
}

func isOpaque(prefix, s string) bool {
	if len(s) != len(prefix)+opaqueChars || !strings.HasPrefix(s, prefix) {
		return false
	}
	for i := len(prefix); i < len(s); i++ {
		if strings.IndexByte(crockford, s[i]) < 0 {
			return false
		}
	}
	return true
}

// aadhaarLegacy is 12 digits starting with 1: an Aadhaar number never starts
// with 0 or 1, so it never passes the check, and starting with 1 rather than 0
// keeps all 12 digits in a bigint. The 11 digits after it are uniform, drawn by
// rejection from 40 random bits at a time.
func aadhaarLegacy(rnd Random) (string, error) {
	const space = 100_000_000_000 // 10^11
	const limit = (1 << 40) / space * space
	for try := 0; try < 64; try++ {
		b, err := rnd(5)
		if err != nil {
			return "", err
		}
		if len(b) != 5 {
			return "", fmt.Errorf("the random source gave %d bytes, not 5", len(b))
		}
		v := uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
		if v >= limit {
			continue
		}
		return fmt.Sprintf("1%011d", v%space), nil
	}
	return "", errors.New("the random source kept giving values out of range")
}

func isAadhaarLegacy(s string) bool {
	if len(s) != 12 || s[0] != '1' {
		return false
	}
	for i := 1; i < 12; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// SyntheticAadhaar makes a number that passes the Aadhaar check from 11
// random digits' worth of bytes, for tests and the prototype's load: it is
// nobody's, but it is shaped and checked like a real one.
func SyntheticAadhaar(rnd Random) (string, error) {
	b, err := rnd(11)
	if err != nil {
		return "", err
	}
	d := make([]byte, 11)
	d[0] = '2' + b[0]%8
	for i := 1; i < 11; i++ {
		d[i] = '0' + b[i]%10
	}
	return string(d) + string(idcheck.VerhoeffDigit(string(d))), nil
}
