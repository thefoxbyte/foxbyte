// SPDX-License-Identifier: AGPL-3.0-or-later

// Command mint makes the keys and tokens the F1 prototype's tests use
// (scripts/integration_f1.sh). A test tool, not part of fox: an application
// mints its own tokens with any JWT library that does EdDSA.
//
//	mint keygen <dir> <name>       write <name>.seed (private) and print the public key, hex
//	mint token  <seed file> [flags]
//	    -kid k1  -iss shop  -sub alice  -aud fox-test  -tenant t  -branch b
//	    -iat -0  -exp 300   seconds from now (iat may be negative or positive)
//	    -header '{"alg":"HS256",...}'   replace the header (for refusals)
//	    -flip                           change one bit of the signature
//	    -nosig                          leave the signature empty
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		if len(os.Args) != 4 {
			usage()
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		check(err)
		check(os.WriteFile(filepath.Join(os.Args[2], os.Args[3]+".seed"), priv.Seed(), 0o600))
		fmt.Println(hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	case "token":
		if len(os.Args) < 3 {
			usage()
		}
		seed, err := os.ReadFile(os.Args[2])
		check(err)
		fs := flag.NewFlagSet("token", flag.ExitOnError)
		kid := fs.String("kid", "k1", "")
		iss := fs.String("iss", "shop", "")
		sub := fs.String("sub", "alice", "")
		aud := fs.String("aud", "fox-test", "")
		tenant := fs.String("tenant", "", "")
		branch := fs.String("branch", "", "")
		iat := fs.Int64("iat", 0, "")
		exp := fs.Int64("exp", 300, "")
		header := fs.String("header", "", "")
		flip := fs.Bool("flip", false, "")
		nosig := fs.Bool("nosig", false, "")
		check(fs.Parse(os.Args[3:]))
		fmt.Println(token(ed25519.NewKeyFromSeed(seed), *kid, *iss, *sub, *aud, *tenant, *branch, *iat, *exp, *header, *flip, *nosig))
	default:
		usage()
	}
}

func token(priv ed25519.PrivateKey, kid, iss, sub, aud, tenant, branch string, iat, exp int64, header string, flip, nosig bool) string {
	now := time.Now().Unix()
	h := header
	if h == "" {
		b, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
		h = string(b)
	}
	claims := map[string]any{"iss": iss, "sub": sub, "aud": aud, "iat": now + iat, "exp": now + exp}
	if tenant != "" {
		claims["tenant"] = tenant
	}
	if branch != "" {
		claims["branch"] = branch
	}
	c, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString([]byte(h)) + "." + enc.EncodeToString(c)
	sig := ed25519.Sign(priv, []byte(signing))
	if flip {
		sig[10] ^= 0x01
	}
	if nosig {
		return signing + "."
	}
	return signing + "." + enc.EncodeToString(sig)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mint keygen <dir> <name> | mint token <seed file> [-kid -iss -sub -aud -tenant -branch -iat -exp -header -flip -nosig]")
	os.Exit(2)
}
