//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package engine

import (
	"errors"

	"github.com/thefoxbyte/foxbyte/enterprise/vault"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

func init() {
	branch.SetVaulter(&branch.Vaulter{
		Call: func(socket, secret, actor, path string, body []byte) ([]byte, string, int, error) {
			return vault.NewClient(socket, secret, actor).CallRaw(path, body)
		},
		Status: func(socket, secret string) ([]byte, error) {
			return vault.NewClient(socket, secret, "engine").StatusRaw()
		},
		LogAt: func(socket, secret string, seq int64) (string, bool, error) {
			h, err := vault.NewClient(socket, secret, "engine").LogAt(seq)
			if errors.Is(err, vault.ErrNoEntry) {
				return "", false, nil
			}
			return h, err == nil, err
		},
		Kinds: kinds,
	})
}

func kinds() []branch.VaultKind {
	var out []branch.VaultKind
	for _, k := range vault.Kinds() {
		out = append(out, branch.VaultKind{
			Name: k.Name, Prefix: k.Prefix, Check: k.Describe, Legacy: k.LegacyDescribe,
			Rules: k.Rules, HSMRequired: k.HSMRequired,
		})
	}
	return out
}
