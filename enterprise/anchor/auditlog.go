//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package anchor

import (
	"time"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// The audit log's anchors (F6 Gate 1, step 6): the chain's head, signed and
// kept outside the store. Checking them is in internal/branch, free.

func init() { branch.SetAuditAnchorWriter(writeAudit) }

// writeAudit anchors the records since the last anchor. The store is held by
// the caller (branch.CheckpointAuditLog), which copies the anchor off this
// machine afterwards.
func writeAudit() (*ledger.Anchor, error) {
	b, err := branch.AuditAnchorFrom()
	if err != nil {
		return nil, err
	}
	if b.Seq <= b.LastTo {
		return nil, nil
	}
	a := ledger.Anchor{Format: branch.AuditAnchorFormat, Algorithm: branch.AuditAnchorAlgorithm, Branch: "_audit-log",
		CheckpointID: b.Seq, FromID: b.LastTo + 1, ToID: b.Seq, EntryCount: int(b.Seq - b.LastTo),
		LastRowHash: b.Hash, MerkleRoot: b.Hash, PrevRoot: b.Prev, CreatedAt: time.Now().UTC()}
	key, err := ledger.LoadOrCreateSigningKey(branch.AnchorKeyPath())
	if err != nil {
		return nil, err
	}
	ledger.SignAnchor(&a, key)
	if _, err := ledger.WriteAnchor(branch.AuditAnchorDir(), a); err != nil {
		return nil, err
	}
	return &a, nil
}
