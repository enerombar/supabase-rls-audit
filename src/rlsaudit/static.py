"""Static analysis of Supabase SQL migrations for Row Level Security gaps.

Replays the migrations in filename order (as the Supabase CLI does) to build the
final state of each table in the exposed schemas, then reports on it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .model import Finding, Severity


@dataclass
class Statement:
    sql: str
    file: str
    line: int


def split_sql(text: str, file: str = "") -> list[Statement]:
    """Split SQL into statements, respecting quotes, dollar-quoting and comments."""
    out: list[Statement] = []
    buf: list[str] = []
    i, n, line, start_line = 0, len(text), 1, 1
    started = False
    while i < n:
        c = text[i]
        if c == "-" and text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            i = j
            continue
        if c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            line += text.count("\n", i, j)
            i = j
            continue
        if not started and not c.isspace():
            started, start_line = True, line
        if c == "'":
            j = i + 1
            while j < n:
                if text[j] == "'" and text.startswith("''", j):
                    j += 2
                    continue
                if text[j] == "'":
                    break
                j += 1
            buf.append(text[i:j + 1])
            line += text.count("\n", i, j + 1)
            i = j + 1
            continue
        if c == "$":
            m = re.match(r"\$[A-Za-z_]*\$", text[i:])
            if m:
                tag = m.group(0)
                j = text.find(tag, i + len(tag))
                j = n if j == -1 else j + len(tag)
                buf.append(text[i:j])
                line += text.count("\n", i, j)
                i = j
                continue
        if c == ";":
            stmt = "".join(buf).strip()
            if stmt:
                out.append(Statement(stmt, file, start_line))
            buf, started = [], False
            i += 1
            continue
        if c == "\n":
            line += 1
        buf.append(c)
        i += 1
    stmt = "".join(buf).strip()
    if stmt:
        out.append(Statement(stmt, file, start_line))
    return out


NAME = r'(?P<name>(?:"[^"]+"|[\w]+)(?:\s*\.\s*(?:"[^"]+"|[\w]+))?)'


def norm_name(raw: str) -> tuple[str, str]:
    parts = [p.strip().strip('"') for p in raw.split(".")]
    if len(parts) == 1:
        return "public", parts[0].lower() if not raw.strip().startswith('"') else parts[0]
    return parts[0], parts[1]


def _ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


RE_CREATE_TABLE = re.compile(r"^create\s+(?:(?:global\s+|local\s+)?(?:temp|temporary|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?" + NAME, re.I)
RE_DROP_TABLE = re.compile(r"^drop\s+table\s+(?:if\s+exists\s+)?(?P<names>[^;]+?)(?:\s+(?:cascade|restrict))?$", re.I)
RE_RENAME = re.compile(r"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?" + NAME + r"\s+rename\s+to\s+(?P<new>\"[^\"]+\"|\w+)$", re.I)
RE_RLS = re.compile(r"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?" + NAME + r"\s+(?P<act>enable|disable|force|no\s+force)\s+row\s+level\s+security", re.I)
RE_POLICY = re.compile(r"^create\s+policy\s+(?P<pname>\"[^\"]+\"|\w+)\s+on\s+" + NAME + r"(?P<rest>.*)$", re.I | re.S)
RE_DROP_POLICY = re.compile(r"^drop\s+policy\s+(?:if\s+exists\s+)?(?P<pname>\"[^\"]+\"|\w+)\s+on\s+" + NAME, re.I)
RE_FUNCTION = re.compile(r"^create\s+(?:or\s+replace\s+)?function\s+" + NAME, re.I)
RE_VIEW = re.compile(r"^create\s+(?:or\s+replace\s+)?(?:materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?" + NAME + r"(?P<rest>.*)$", re.I | re.S)
RE_GRANT = re.compile(r"^grant\s+(?P<privs>.+?)\s+on\s+(?:table\s+)?(?P<objs>.+?)\s+to\s+(?P<roles>.+)$", re.I | re.S)


@dataclass
class Policy:
    name: str
    command: str  # all/select/insert/update/delete
    roles: list[str]
    using: str | None
    check: str | None
    where: str


@dataclass
class Table:
    schema: str
    name: str
    where: str
    rls: bool = False
    policies: dict[str, Policy] = field(default_factory=dict)

    @property
    def fq(self) -> str:
        return f"{self.schema}.{self.name}"


def _paren_expr(rest: str, keyword: str) -> str | None:
    m = re.search(keyword + r"\s*\(", rest, re.I)
    if not m:
        return None
    depth, i = 1, m.end()
    while i < len(rest) and depth:
        depth += {"(": 1, ")": -1}.get(rest[i], 0)
        i += 1
    return _ws(rest[m.end():i - 1])


def _parse_policy(pname: str, rest: str, where: str) -> Policy:
    head = rest.split("using", 1)[0] if re.search(r"\busing\b", rest, re.I) else rest
    head = re.split(r"\bwith\s+check\b", head, flags=re.I)[0]
    cmd = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", head, re.I)
    roles = re.search(r"\bto\s+(.+)$", _ws(head), re.I)
    role_list = [r.strip().strip('"').lower() for r in roles.group(1).split(",")] if roles else ["public"]
    return Policy(
        name=pname.strip('"'),
        command=cmd.group(1).lower() if cmd else "all",
        roles=role_list,
        using=_paren_expr(rest, r"\busing"),
        check=_paren_expr(rest, r"\bwith\s+check"),
        where=where,
    )


TRUE_EXPR = re.compile(r"^\(*\s*true\s*\)*$", re.I)
METADATA = re.compile(r"user_metadata|raw_user_meta_data", re.I)


def analyze(statements: list[Statement], schemas: tuple[str, ...] = ("public",)) -> list[Finding]:
    tables: dict[tuple[str, str], Table] = {}
    findings: list[Finding] = []
    secdef_funcs: dict[str, tuple[str, bool]] = {}
    views: dict[str, tuple[str, bool]] = {}
    anon_grants: dict[str, tuple[str, str]] = {}

    for st in statements:
        sql = st.sql
        where = f"{st.file}:{st.line}"
        if m := RE_CREATE_TABLE.match(sql):
            key = norm_name(m.group("name"))
            tables[key] = Table(*key, where=where)
        elif m := RE_DROP_TABLE.match(sql):
            for raw in m.group("names").split(","):
                tables.pop(norm_name(raw), None)
        elif m := RE_RENAME.match(sql):
            key = norm_name(m.group("name"))
            if key in tables:
                t = tables.pop(key)
                t.name = m.group("new").strip('"')
                tables[(t.schema, t.name)] = t
        elif m := RE_RLS.match(sql):
            key = norm_name(m.group("name"))
            t = tables.setdefault(key, Table(*key, where=where))
            act = m.group("act").lower()
            if act == "enable":
                t.rls = True
            elif act == "disable":
                t.rls = False
                t.where = where
        elif m := RE_POLICY.match(sql):
            key = norm_name(m.group("name"))
            t = tables.setdefault(key, Table(*key, where=where))
            p = _parse_policy(m.group("pname"), m.group("rest"), where)
            t.policies[p.name] = p
        elif m := RE_DROP_POLICY.match(sql):
            key = norm_name(m.group("name"))
            if key in tables:
                tables[key].policies.pop(m.group("pname").strip('"'), None)
        elif m := RE_FUNCTION.match(sql):
            schema, name = norm_name(m.group("name"))
            low = sql.lower()
            if "security definer" in low:
                secdef_funcs[f"{schema}.{name}"] = (where, "search_path" in low)
            else:
                secdef_funcs.pop(f"{schema}.{name}", None)
        elif m := RE_VIEW.match(sql):
            schema, name = norm_name(m.group("name"))
            if schema in schemas:
                invoker = bool(re.search(r"security_invoker\s*=\s*(true|on|1)", m.group("rest"), re.I))
                views[f"{schema}.{name}"] = (where, invoker)
        elif m := RE_GRANT.match(sql):
            roles = [r.strip().strip('"').lower() for r in re.split(r"[,\s]+", m.group("roles"))]
            privs = _ws(m.group("privs")).lower()
            if "anon" in roles and any(p in privs for p in ("all", "insert", "update", "delete", "truncate")):
                anon_grants[_ws(m.group("objs"))] = (where, privs)

    for t in tables.values():
        if t.schema not in schemas:
            continue
        if not t.rls:
            findings.append(Finding(
                "RLS001-rls-disabled", Severity.CRITICAL, f"{t.fq} ({t.where})",
                f"Table {t.fq} is in an API-exposed schema without Row Level Security: anyone "
                "with the anon key can read and modify every row.",
                f"alter table {t.fq} enable row level security; then add policies.",
            ))
            continue
        if not t.policies:
            findings.append(Finding(
                "RLS002-no-policies", Severity.INFO, f"{t.fq} ({t.where})",
                f"Table {t.fq} has RLS enabled but no policies, so the API can't read or write it. "
                "Fine if only the service role should touch it.", "",
            ))
        for p in t.policies.values():
            public = any(r in ("public", "anon") for r in p.roles)
            for kind, expr in (("using", p.using), ("with check", p.check)):
                if expr is None or not TRUE_EXPR.match(expr):
                    continue
                if p.command == "select":
                    sev = Severity.MEDIUM if public else Severity.LOW
                    msg = (f"Policy '{p.name}' on {t.fq} lets {'anyone' if public else 'every signed-in user'} "
                           "read every row.")
                    fix = "Confirm the data is meant to be public, or scope it (e.g. using (auth.uid() = user_id))."
                else:
                    sev = Severity.CRITICAL if public else Severity.HIGH
                    msg = (f"Policy '{p.name}' on {t.fq} allows {p.command.upper()} on every row for "
                           f"{'anyone' if public else 'every signed-in user'} ({kind} (true)).")
                    fix = "Restrict writes to the row owner, e.g. using (auth.uid() = user_id) with check (auth.uid() = user_id)."
                findings.append(Finding("RLS003-permissive-policy", sev, f"{t.fq} ({p.where})", msg, fix))
            if p.command in ("update", "all") and p.using and p.check is None and "auth.uid()" in p.using:
                findings.append(Finding(
                    "RLS008-update-without-check", Severity.LOW, f"{t.fq} ({p.where})",
                    f"Policy '{p.name}' on {t.fq} restricts which rows can be updated but has no WITH CHECK; "
                    "Postgres then reuses USING, which is usually fine, but verify a user can't move a row "
                    "to another owner through a different column.",
                    "Add an explicit with check (...) mirroring the ownership condition.",
                ))
            if any(e and METADATA.search(e) for e in (p.using, p.check)):
                findings.append(Finding(
                    "RLS004-user-metadata", Severity.HIGH, f"{t.fq} ({p.where})",
                    f"Policy '{p.name}' on {t.fq} trusts user_metadata, which users can edit themselves "
                    "via auth.updateUser().",
                    "Use app_metadata (only writable server-side) or a roles table for authorization.",
                ))

    for fn, (where, has_path) in secdef_funcs.items():
        if fn.split(".")[0] in schemas and not has_path:
            findings.append(Finding(
                "RLS005-secdef-search-path", Severity.MEDIUM, f"{fn} ({where})",
                f"SECURITY DEFINER function {fn} bypasses RLS and does not pin search_path, so a "
                "caller-controlled schema could hijack the objects it references.",
                "Add `set search_path = ''` and schema-qualify every object, or move it out of the exposed schema.",
            ))
    for v, (where, invoker) in views.items():
        if not invoker:
            findings.append(Finding(
                "RLS006-view-bypasses-rls", Severity.HIGH, f"{v} ({where})",
                f"View {v} runs with its owner's rights, so it ignores the RLS of the tables it reads.",
                f"create view ... with (security_invoker = true), or revoke access from anon/authenticated.",
            ))
    for objs, (where, privs) in anon_grants.items():
        findings.append(Finding(
            "RLS007-anon-write-grant", Severity.MEDIUM, f"{objs} ({where})",
            f"Explicit grant of '{privs}' to anon on {objs}; only RLS policies stand between "
            "unauthenticated users and writes.",
            "Revoke write privileges from anon unless the table is meant to accept anonymous writes.",
        ))

    findings.sort(key=lambda f: (-f.severity, f.target))
    return findings


def analyze_path(path: Path, schemas: tuple[str, ...] = ("public",)) -> tuple[list[Finding], int]:
    files = sorted(path.glob("*.sql")) if path.is_dir() else [path]
    statements: list[Statement] = []
    for f in files:
        statements += split_sql(f.read_text(encoding="utf-8"), f.name)
    return analyze(statements, schemas), len(files)
