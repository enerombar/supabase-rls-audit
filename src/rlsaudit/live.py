"""Live checks against a Supabase project you own, through its public REST API.

Only uses what an attacker would have: the project URL, the anon key and
ordinary user accounts. Read probes are always safe. The optional write probe
is a no-op UPDATE (it sets the owner column to the value it already has), so it
reports whether a cross-user write *would* succeed without changing data.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

from .model import Finding, Severity

# transport(method, url, headers, body) -> (status, parsed_json_or_text)
Transport = Callable[[str, str, dict, bytes | None], tuple[int, object]]


def urllib_transport(method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, object]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode("utf-8")
            status = r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read().decode("utf-8", "replace"), e.code
    try:
        return status, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return status, raw


class ConfigError(Exception):
    pass


@dataclass
class TableSpec:
    name: str
    owner_column: str | None = None
    public_read: bool = False


@dataclass
class LiveConfig:
    url: str
    anon_key: str
    user_a: tuple[str, str]  # email, password
    user_b: tuple[str, str]
    tables: list[TableSpec] = field(default_factory=list)
    auto_discover: bool = True

    @classmethod
    def load(cls, path: str, env=os.environ) -> "LiveConfig":
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("i_own_this_project") is not True:
            raise ConfigError(
                'Set "i_own_this_project": true in the config to confirm you own, or are '
                "authorised to test, this Supabase project."
            )

        def val(key: str) -> str:
            v = data.get(key) or env.get(data.get(f"{key}_env", ""), "")
            if not v:
                raise ConfigError(f"missing '{key}' (or '{key}_env' pointing to a set env var)")
            return v

        def user(key: str) -> tuple[str, str]:
            u = data.get(key) or {}
            email = u.get("email") or env.get(u.get("email_env", ""), "")
            pwd = env.get(u.get("password_env", ""), "")
            if not email or not pwd:
                raise ConfigError(f"'{key}' needs email (or email_env) and password_env set in the environment")
            return email, pwd

        tables = [TableSpec(t["name"], t.get("owner_column"), bool(t.get("public_read", False)))
                  for t in data.get("tables", [])]
        return cls(val("url").rstrip("/"), val("anon_key"), user("user_a"), user("user_b"),
                   tables, bool(data.get("auto_discover", True)))


@dataclass
class Session:
    token: str
    user_id: str


class Client:
    def __init__(self, url: str, anon_key: str, transport: Transport = urllib_transport):
        self.url, self.anon, self.t = url, anon_key, transport

    def _h(self, token: str | None = None, extra: dict | None = None) -> dict:
        h = {"apikey": self.anon, "Authorization": f"Bearer {token or self.anon}",
             "Content-Type": "application/json", "Accept": "application/json"}
        h.update(extra or {})
        return h

    def sign_in(self, email: str, password: str) -> Session:
        status, body = self.t("POST", f"{self.url}/auth/v1/token?grant_type=password", self._h(),
                              json.dumps({"email": email, "password": password}).encode())
        if status != 200 or not isinstance(body, dict) or "access_token" not in body:
            raise ConfigError(f"sign-in failed for {email} (HTTP {status})")
        return Session(body["access_token"], body["user"]["id"])

    def exposed_tables(self) -> list[str]:
        status, body = self.t("GET", f"{self.url}/rest/v1/", self._h(), None)
        if status != 200 or not isinstance(body, dict):
            return []
        return sorted(p.strip("/") for p in body.get("paths", {}) if p.count("/") == 1 and p != "/" and not p.startswith("/rpc"))

    def select(self, table: str, token: str | None, filters: dict | None = None) -> tuple[int, object]:
        q = {"select": "*", "limit": "1", **(filters or {})}
        return self.t("GET", f"{self.url}/rest/v1/{urllib.parse.quote(table)}?{urllib.parse.urlencode(q)}",
                      self._h(token), None)

    def noop_update(self, table: str, token: str, column: str, value: str) -> tuple[int, object]:
        q = urllib.parse.urlencode({column: f"eq.{value}"})
        return self.t("PATCH", f"{self.url}/rest/v1/{urllib.parse.quote(table)}?{q}",
                      self._h(token, {"Prefer": "return=representation"}),
                      json.dumps({column: value}).encode())


def _rows(body) -> int:
    return len(body) if isinstance(body, list) else 0


def run_live(cfg: LiveConfig, write_probe: bool = False, transport: Transport = urllib_transport,
             log: Callable[[str], None] = lambda s: None) -> list[Finding]:
    c = Client(cfg.url, cfg.anon_key, transport)
    a = c.sign_in(*cfg.user_a)
    b = c.sign_in(*cfg.user_b)
    if a.user_id == b.user_id:
        raise ConfigError("user_a and user_b must be different accounts")

    specs = {t.name: t for t in cfg.tables}
    if cfg.auto_discover:
        for name in c.exposed_tables():
            specs.setdefault(name, TableSpec(name))
    findings: list[Finding] = []

    for name, spec in sorted(specs.items()):
        log(f"probing {name}")
        status, body = c.select(name, None)
        if status == 200 and _rows(body) and not spec.public_read:
            findings.append(Finding(
                "LIVE001-anon-read", Severity.HIGH, name,
                f"Unauthenticated requests with the anon key can read rows from '{name}'.",
                "Add RLS policies scoped to authenticated users, or mark the table public_read in the "
                "config if this is intended.",
            ))
        if not spec.owner_column:
            continue
        col = spec.owner_column
        status, body = c.select(name, b.token, {col: f"eq.{b.user_id}"})
        if status != 200:
            findings.append(Finding(
                "LIVE000-probe-error", Severity.INFO, name,
                f"Could not read '{name}' as user_b (HTTP {status}); check the owner_column name.", "",
            ))
            continue
        if not _rows(body):
            findings.append(Finding(
                "LIVE000-no-baseline", Severity.INFO, name,
                f"user_b owns no visible rows in '{name}', so cross-user access could not be tested. "
                "Create at least one row as user_b.", "",
            ))
            continue
        status, body = c.select(name, a.token, {col: f"eq.{b.user_id}"})
        if status == 200 and _rows(body):
            findings.append(Finding(
                "LIVE002-cross-user-read", Severity.CRITICAL, name,
                f"user_a can read rows of '{name}' that belong to user_b.",
                f"Use using (auth.uid() = {col}) in the SELECT policy.",
            ))
        if write_probe:
            status, body = c.noop_update(name, a.token, col, b.user_id)
            if status in (200, 204) and _rows(body):
                findings.append(Finding(
                    "LIVE003-cross-user-write", Severity.CRITICAL, name,
                    f"user_a can UPDATE rows of '{name}' that belong to user_b (probe was a no-op).",
                    f"Use using (auth.uid() = {col}) with check (auth.uid() = {col}) in the UPDATE policy.",
                ))

    findings.sort(key=lambda f: (-f.severity, f.target))
    return findings
