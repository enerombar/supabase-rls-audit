# supabase-rls-audit

Find **Row Level Security** gaps in Supabase projects before someone else does.

In Supabase, every table in the `public` schema is reachable through the REST API with the
anon key that ships inside your frontend. Row Level Security is the only thing deciding who can
read or write each row, so one missing `enable row level security`, one `using (true)` or one
view created without `security_invoker` is a data leak.

The tool has two modes:

- **`static`**: replays your `supabase/migrations/*.sql` in order and audits the resulting
  tables, policies, views, functions and grants. No network, safe to run in CI.
- **`live`**: probes a running project the way an attacker would, using only the anon key and
  two ordinary test accounts, to confirm whether one user can actually see or change another
  user's rows.

No dependencies beyond the Python standard library.

> **Only run `live` against projects you own or are authorised to test.** The config must say
> `"i_own_this_project": true`. Prefer a staging project with test accounts.

## Static checks

| Rule | Severity | Finds |
|------|----------|-------|
| `RLS001-rls-disabled` | critical | Exposed table that never had RLS enabled, or had it disabled later |
| `RLS002-no-policies` | info | RLS on but no policies (API fully locked out – often intended) |
| `RLS003-permissive-policy` | medium → critical | `using (true)` / `with check (true)`; critical for writes open to `anon`/`public` |
| `RLS004-user-metadata` | high | Policies trusting `user_metadata`, which users can edit themselves |
| `RLS005-secdef-search-path` | medium | `security definer` functions without a pinned `search_path` |
| `RLS006-view-bypasses-rls` | high | Views in exposed schemas without `security_invoker = true` |
| `RLS007-anon-write-grant` | medium | Explicit `insert`/`update`/`delete` grants to `anon` |
| `RLS008-update-without-check` | low | Owner-scoped UPDATE policies with no explicit `WITH CHECK` |

The parser handles comments, quoted strings and dollar-quoted function bodies, and follows
`drop table`, `rename to`, `drop policy` and later `disable row level security`.

```bash
pip install git+https://github.com/enerombar/supabase-rls-audit
supabase-rls-audit static                         # defaults to supabase/migrations
supabase-rls-audit static path/to/migrations --schema public --schema api
supabase-rls-audit static -f json --fail-on critical
```

Example on the test fixture (`tests/fixtures/migrations`, deliberately broken):

```
[CRITICAL] RLS001-rls-disabled  public.notes (20260101000000_init.sql:12)
[CRITICAL] RLS003-permissive-policy  public.orders (20260101000000_init.sql:20)
    Policy 'anyone can insert orders' on public.orders allows INSERT on every row for anyone ...
[HIGH] RLS004-user-metadata  public.documents (20260201000000_more.sql:3)
[HIGH] RLS006-view-bypasses-rls  public.order_totals (20260201000000_more.sql:17)
```

## Live checks

| Rule | Severity | Finds |
|------|----------|-------|
| `LIVE001-anon-read` | high | Rows readable with the anon key alone (unless marked `public_read`) |
| `LIVE002-cross-user-read` | critical | User A can read rows owned by user B |
| `LIVE003-cross-user-write` | critical | User A can update rows owned by user B (`--write-probe`) |

How it works: it signs in as two test users, confirms user B can see at least one of their own
rows, then asks for those same rows as user A and as an anonymous client. With `--write-probe`
it sends an UPDATE as user A that sets B's owner column to the value it already has: if the API
returns the row, the write would have succeeded, but no data changes. It never sends DELETE.
Tables exposed by the API but missing from the config are discovered automatically and checked
for anonymous reads.

1. Create two test users in the project and at least one row per table as user B.
2. Copy `rlsaudit.example.json` to `rlsaudit.json` (git-ignored) and list each table with its
   owner column.
3. Put secrets in the environment, never in the file:

```bash
export SUPABASE_ANON_KEY=...  RLS_AUDIT_PASSWORD_A=...  RLS_AUDIT_PASSWORD_B=...
supabase-rls-audit live -c rlsaudit.json --write-probe -v
```

Exit codes: `0` nothing at or above `--fail-on` (default `high`), `1` findings at or above it,
`2` configuration or input error.

## Limitations

- Static mode is regex-based, not a full SQL parser; unusual DDL may be missed. Treat it as a
  reviewer's checklist, and use `live` to confirm.
- Live mode assumes ownership is expressed as a column holding the user's id. Multi-tenant
  schemes (organisation membership tables) need one test user per tenant.
- It checks the REST API, not Storage buckets, Realtime or Edge Functions.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
