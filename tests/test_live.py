import json
from urllib.parse import parse_qs, urlparse

import pytest

from rlsaudit.live import ConfigError, LiveConfig, TableSpec, run_live

URL = "https://proj.supabase.co"
A, B = "uid-a", "uid-b"


class FakeSupabase:
    """Minimal PostgREST/GoTrue double with configurable (mis)policies."""

    def __init__(self, leaky_read=(), leaky_write=(), anon_readable=()):
        self.rows = {
            "notes": [{"id": 1, "user_id": A}, {"id": 2, "user_id": B}],
            "orders": [{"id": 1, "owner": B}],
            "posts": [{"id": 1, "author": B}],
        }
        self.leaky_read, self.leaky_write, self.anon_readable = set(leaky_read), set(leaky_write), set(anon_readable)
        self.calls = []

    def _who(self, headers):
        tok = headers["Authorization"].split()[-1]
        return {"tok-a": A, "tok-b": B}.get(tok)

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url))
        u = urlparse(url)
        if u.path == "/auth/v1/token":
            email = json.loads(body)["email"]
            uid = A if email.startswith("a") else B
            return 200, {"access_token": "tok-" + uid[-1], "user": {"id": uid}}
        if u.path == "/rest/v1/":
            return 200, {"paths": {"/": {}, "/notes": {}, "/orders": {}, "/posts": {}, "/rpc/fn": {}}}
        table = u.path.split("/")[-1]
        who = self._who(headers)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        rows = self.rows[table]
        for col, cond in q.items():
            if col not in ("select", "limit"):
                rows = [r for r in rows if str(r.get(col)) == cond.removeprefix("eq.")]
        owner_col = {"notes": "user_id", "orders": "owner", "posts": "author"}[table]
        if who is None:
            visible = rows if table in self.anon_readable else []
        elif table in (self.leaky_write if method == "PATCH" else self.leaky_read):
            visible = rows
        else:
            visible = [r for r in rows if r[owner_col] == who]
        return 200, visible[:1] if method == "GET" else visible


def cfg(tables, discover=False):
    return LiveConfig(URL, "anon", ("a@x.io", "pw"), ("b@x.io", "pw"), tables, discover)


TABLES = [TableSpec("notes", "user_id"), TableSpec("orders", "owner")]


def rules(fs):
    return sorted((f.rule, f.target) for f in fs)


def test_secure_project_is_clean():
    assert run_live(cfg(TABLES), write_probe=True, transport=FakeSupabase()) == []


def test_cross_user_read_and_write():
    fake = FakeSupabase(leaky_read={"orders"}, leaky_write={"notes"})
    f = run_live(cfg(TABLES), write_probe=True, transport=fake)
    assert rules(f) == [("LIVE002-cross-user-read", "orders"), ("LIVE003-cross-user-write", "notes")]


def test_write_probe_is_opt_in_and_noop():
    fake = FakeSupabase(leaky_write={"notes"})
    assert run_live(cfg(TABLES), transport=fake) == []
    assert not any(m == "PATCH" for m, _ in fake.calls)
    run_live(cfg(TABLES), write_probe=True, transport=fake)
    assert all(m in ("GET", "POST", "PATCH") for m, _ in fake.calls)  # never DELETE


def test_anon_read_and_public_read_exemption():
    fake = FakeSupabase(anon_readable={"notes", "posts"})
    f = run_live(cfg(TABLES + [TableSpec("posts", public_read=True)]), transport=fake)
    assert rules(f) == [("LIVE001-anon-read", "notes")]


def test_auto_discovery_includes_unlisted_tables():
    fake = FakeSupabase(anon_readable={"posts"})
    f = run_live(cfg(TABLES, discover=True), transport=fake)
    assert ("LIVE001-anon-read", "posts") in rules(f)


def test_no_baseline_rows_reported():
    fake = FakeSupabase()
    fake.rows["notes"] = [{"id": 1, "user_id": A}]
    f = run_live(cfg(TABLES), transport=fake)
    assert rules(f) == [("LIVE000-no-baseline", "notes")]


def test_config_requires_ownership_confirmation(tmp_path):
    p = tmp_path / "rlsaudit.json"
    p.write_text(json.dumps({"url": URL, "anon_key": "k"}))
    with pytest.raises(ConfigError, match="i_own_this_project"):
        LiveConfig.load(str(p))


def test_config_reads_passwords_from_env(tmp_path):
    p = tmp_path / "rlsaudit.json"
    p.write_text(json.dumps({
        "i_own_this_project": True, "url": URL + "/", "anon_key_env": "ANON",
        "user_a": {"email": "a@x.io", "password_env": "PA"},
        "user_b": {"email": "b@x.io", "password_env": "PB"},
        "tables": [{"name": "notes", "owner_column": "user_id"}],
    }))
    c = LiveConfig.load(str(p), env={"ANON": "k", "PA": "1", "PB": "2"})
    assert c.url == URL and c.anon_key == "k" and c.user_a == ("a@x.io", "1")
    with pytest.raises(ConfigError, match="password_env"):
        LiveConfig.load(str(p), env={"ANON": "k", "PA": "1"})
