from pathlib import Path

from rlsaudit.cli import main
from rlsaudit.model import Severity
from rlsaudit.static import analyze, analyze_path, split_sql

FIX = Path(__file__).parent / "fixtures" / "migrations"


def by_rule(findings):
    out = {}
    for f in findings:
        out.setdefault(f.rule, []).append(f)
    return out


def targets(fs):
    return sorted(f.target.split(" ")[0] for f in fs)


def test_split_respects_comments_quotes_and_dollar_quotes():
    sql = "select ';'; -- x; y\ncreate function f() returns int as $$ select 1; $$; select $t$a;b$t$;"
    stmts = split_sql(sql)
    assert len(stmts) == 3
    assert stmts[1].sql.startswith("create function")
    assert stmts[1].line == 2


def test_fixture_findings():
    findings, n = analyze_path(FIX)
    assert n == 2
    r = by_rule(findings)

    # RLS never enabled, or disabled later; non-public schema ignored; dropped table ignored
    assert targets(r["RLS001-rls-disabled"]) == ["public.legacy", "public.notes"]
    assert all(f.severity == Severity.CRITICAL for f in r["RLS001-rls-disabled"])

    assert targets(r["RLS002-no-policies"]) == ["public.admin_only"]

    perm = {f.target.split(" ")[0]: f.severity for f in r["RLS003-permissive-policy"]}
    assert perm == {"public.orders": Severity.CRITICAL, "public.profiles": Severity.MEDIUM}

    assert targets(r["RLS004-user-metadata"]) == ["public.documents"]
    assert targets(r["RLS005-secdef-search-path"]) == ["public.is_admin"]
    assert targets(r["RLS006-view-bypasses-rls"]) == ["public.order_totals"]
    assert len(r["RLS007-anon-write-grant"]) == 1
    assert targets(r["RLS008-update-without-check"]) == ["public.profiles"]


def test_owner_scoped_policies_are_clean():
    sql = """
    create table public.todos (id int, user_id uuid);
    alter table public.todos enable row level security;
    create policy "own" on public.todos for all to authenticated
      using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
    """
    assert analyze(split_sql(sql)) == []


def test_drop_policy_removes_it():
    sql = """
    create table public.t (id int);
    alter table public.t enable row level security;
    create policy "open" on public.t for delete using (true);
    drop policy if exists "open" on public.t;
    create policy "closed" on public.t for delete to authenticated using (false);
    """
    assert [f.rule for f in analyze(split_sql(sql))] == []


def test_rename_table_keeps_state():
    sql = """
    create table public.a (id int);
    alter table public.a enable row level security;
    alter table public.a rename to b;
    create policy "p" on public.b for select to authenticated using (auth.uid() is not null);
    """
    assert analyze(split_sql(sql)) == []


def test_extra_schema_option():
    sql = "create table api.items (id int);"
    assert analyze(split_sql(sql)) == []
    assert [f.rule for f in analyze(split_sql(sql), ("public", "api"))] == ["RLS001-rls-disabled"]


def test_cli_static(capsys):
    assert main(["static", str(FIX)]) == 1
    out = capsys.readouterr().out
    assert "RLS001-rls-disabled" in out
    assert main(["static", str(FIX), "--fail-on", "critical", "-f", "json"]) == 1


def test_cli_missing_path(capsys):
    assert main(["static", "/nonexistent/dir"]) == 2
