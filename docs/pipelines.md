# ETL pipelines

Experimental, and Enterprise. Summary: [README](../README.md#etl-pipelines).

The feature catalogue still titles it experimental: a run works, and several
things a warehouse tool would have are absent. There is no schedule, no
incremental model, and no dependency graph — models run in the order listed.
A run deletes and recreates its target branch. If a test fails, the data is
left there and `fox pipeline run` exits 1. The API does not return a stored
run log, and a run whose process dies can stay marked `running`.

## Sources

There is no separate connector catalogue. Extract is the import path: a
`postgres://`, `mysql://`, `mariadb://`, or `mongodb://` source, and from the
CLI a local `.sql`, `.csv`, or `.json` file. Through the API the source has to
be a connection string. A path would be read on the server, with the engine's
permissions.

## A pipeline

`shop.json`:

```json
{
  "source": "postgres://user:password@db.example/shop",
  "models": [
    {
      "name": "active_users",
      "materialized": "table",
      "sql": "SELECT id, email FROM {{ source('users') }} WHERE email IS NOT NULL"
    }
  ],
  "tests": [
    {"name": "email present", "type": "not_null", "model": "active_users", "column": "email"}
  ]
}
```

```bash
fox pipeline run shop.json --as shop-etl
```

That branch is new. Raw tables land in schema `raw` (`{{ source('users') }}`
is `raw.users`). Models land in `public` (`{{ ref('active_users') }}` is
`public.active_users`). `materialized` is `table` or `view`. Tests are
`not_null`, `unique`, `accepted_values`, `row_count_min`, and `custom` (a
query that must return zero rows). Omit `--as` and the branch is named
`pl-shop`. The console has a pipeline editor; `POST /api/pipelines` stores a
spec and `POST /api/pipelines/{id}/run` streams the log.

## See also

- [Import & migration](reference.md#import--migration) — the same sources, without the models and tests.
- [Reference](reference.md) — every command.
