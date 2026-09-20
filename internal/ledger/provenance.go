// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import _ "embed"

// SchemaProvenance is the idempotent SQL for Blackbox agent provenance
// (bb.agent_sessions). Apply it after Schema, SchemaV2 and SchemaPolicy.
//
//go:embed provenance.sql
var SchemaProvenance string
