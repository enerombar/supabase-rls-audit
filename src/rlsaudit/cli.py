from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .live import ConfigError, LiveConfig, run_live
from .model import Finding, Severity
from .static import analyze_path


def _print(findings: list[Finding], fmt: str, scope: str) -> None:
    if fmt == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return
    if not findings:
        print(f"No findings ({scope}).")
        return
    for f in findings:
        print(f"[{f.severity.name}] {f.rule}  {f.target}")
        print(f"    {f.message}")
        if f.remediation:
            print(f"    fix: {f.remediation}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    summary = ", ".join(f"{n} {s.name.lower()}" for s, n in sorted(counts.items(), reverse=True) if n)
    print(f"\n{len(findings)} finding(s) ({scope}): {summary}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="supabase-rls-audit",
                                description="Find Row Level Security gaps in Supabase projects you own.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("static", help="analyse SQL migrations (no network)")
    s.add_argument("path", nargs="?", type=Path, default=Path("supabase/migrations"))
    s.add_argument("--schema", action="append", help="exposed schema to audit (default: public)")

    l = sub.add_parser("live", help="probe a running project through its REST API")
    l.add_argument("-c", "--config", default="rlsaudit.json")
    l.add_argument("--write-probe", action="store_true",
                   help="also test cross-user UPDATE with a no-op request")
    l.add_argument("-v", "--verbose", action="store_true")

    for sp in (s, l):
        sp.add_argument("-f", "--format", choices=["text", "json"], default="text")
        sp.add_argument("--fail-on", default="high")

    args = p.parse_args(argv)
    try:
        threshold = Severity.parse(args.fail_on)
    except ValueError as exc:
        p.error(str(exc))

    if args.cmd == "static":
        if not args.path.exists():
            print(f"error: {args.path} not found", file=sys.stderr)
            return 2
        findings, n = analyze_path(args.path, tuple(args.schema or ["public"]))
        _print(findings, args.format, f"{n} migration file(s)")
    else:
        try:
            cfg = LiveConfig.load(args.config)
            log = (lambda m: print(m, file=sys.stderr)) if args.verbose else (lambda m: None)
            findings = run_live(cfg, write_probe=args.write_probe, log=log)
        except (ConfigError, OSError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        _print(findings, args.format, cfg.url)

    return 1 if any(f.severity >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
