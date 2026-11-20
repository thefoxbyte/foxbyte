# Compared with Neon, Xata, and Supabase

Checked against their public docs on **20 Nov 2026**. The other columns are
their claims and docs, not a benchmark we ran. FoxByte's own limits are in
the first column on purpose. Short version:
[README](../README.md#compared-with-neon-xata-and-supabase).

| | Self-hosted | How a branch copies data | Hash-chained DDL ledger | Masking | Change feed | ETL |
| --- | --- | --- | --- | --- | --- | --- |
| **FoxByte** | Yes, on one machine you run. macOS uses a Lima VM. Windows uses a dedicated WSL2 distro. HA here is a single-VM demonstration. | ZFS snapshot + clone, or a btrfs subvolume snapshot on Windows, then a Postgres container. The clone is O(1) in data size. Documented as seconds. `fox branch create` prints the elapsed time for that run. | Yes, in Standard (the Blackbox). Writing signed anchors is Enterprise. Checking them is free. | Enterprise and opt-in (`fox pii scan`, `fox mask`). A branch is unmasked unless you mask it, and FoxByte warns. | Enterprise. Logical decoding of a branch on this install, as server-sent events. Resume with `?since=<lsn>`. Enable and subscribe wake a suspended branch. Not a feed of some other server's database. | Enterprise, experimental. Extract with the import sources, SQL models, then tests, on a branch the run replaces. No schedule, no incremental models. |
| **Neon** | The product people use is hosted. The storage engine is open source and can branch by creating a pageserver timeline. Neon does not publish a supported one-command self-hosted install. | Copy-on-write timeline: a new pageserver timeline from an ancestor timeline. | Not described in the docs checked. | Not described as a first-party column-masking feature in the docs checked. | Not described in the docs checked for this table. | Not described in the docs checked for this table. |
| **Xata** | Hosted. On 9 Nov 2026 Xata announced it is joining ClickHouse and is still accepting sign-ups. Instant branching was not yet part of ClickHouse Managed Postgres. | Their 9 Nov 2026 post: a copy-on-write branch in around 3 seconds, including for large databases. Their figure, not ours. | Not described in the docs checked. | They document anonymized production data on branches. | Not in their 9 Nov 2026 announcement. | Not in their 9 Nov 2026 announcement. |
| **Supabase** | The platform can be self-hosted. Branching, as documented, is a cloud feature. | Schema comes from migrations, not from a storage clone. Data is absent by default. "Include data" (dashboard, requires their PITR add-on) copies production data. Their setup waits up to 2 minutes for the branch to be healthy. | Not described in the docs checked. | No documented dynamic column masking. Keeping production rows off the branch is the default. Row Level Security and Vault are different controls. | They document Postgres Changes over a WebSocket, including on a self-hosted Realtime server. Replay there is a broadcast timestamp, not a Postgres LSN. | Not described as an extract-transform-test pipeline in the docs checked. |

Sources: [Neon pageserver timeline API](https://github.com/neondatabase/neon/discussions/3413),
[Xata joining ClickHouse](https://xata.io/blog/xata-is-joining-clickhouse),
[Supabase branching](https://supabase.com/docs/guides/deployment/branching),
[Supabase Postgres Changes](https://supabase.com/docs/guides/realtime/postgres-changes).
The Neon and Xata change-feed and ETL cells are "not described" in those
pages, not a claim that no such feature exists anywhere else.

FoxByte did not invent copy-on-write Postgres branches. That idea is
[postgres.ai / Database Lab](https://postgres.ai)'s, and the products above
ship branching of their own. What this repository adds on top of a branch is
the Blackbox, the attribution, and the policy gate, on a Postgres you run.
