//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// The access log (design, section 10): one row per call, hash-chained as the
// Blackbox is, and never a value in it.

// Entry is one row of the access log.
type Entry struct {
	Seq     int64    `json:"seq"`
	AtMicro int64    `json:"at_us"`
	Actor   string   `json:"actor"`
	Action  string   `json:"action"`
	Kind    string   `json:"kind"`
	Refs    []string `json:"refs"`
	N       int      `json:"n"`
	Purpose string   `json:"purpose"`
	Result  string   `json:"result"`
	Prev    []byte   `json:"prev"`
	Hash    []byte   `json:"hash"`
}

// Genesis is the hash the first entry chains from.
var Genesis = make([]byte, sha256.Size)

// Sum is the entry's hash: SHA-256 of the previous hash and every field, each
// length-prefixed so no two different entries write the same bytes.
func (e *Entry) Sum(prev []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	num := func(v int64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v))
		h.Write(b[:])
	}
	str := func(s string) {
		num(int64(len(s)))
		h.Write([]byte(s))
	}
	num(e.Seq)
	num(e.AtMicro)
	str(e.Actor)
	str(e.Action)
	str(e.Kind)
	num(int64(len(e.Refs)))
	for _, r := range e.Refs {
		str(r)
	}
	num(int64(e.N))
	str(e.Purpose)
	str(e.Result)
	return h.Sum(nil)
}

// Verify walks entries in order and returns the sequence number of the first
// one that does not chain, or 0 when all do.
func Verify(entries []Entry) int64 {
	prev := Genesis
	var want int64 = 1
	for i := range entries {
		e := &entries[i]
		if e.Seq != want || !bytes.Equal(e.Prev, prev) || !bytes.Equal(e.Hash, e.Sum(prev)) {
			return e.Seq
		}
		prev = e.Hash
		want++
	}
	return 0
}
