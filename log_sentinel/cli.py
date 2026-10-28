"""Command-line interface: python -m log_sentinel --auth auth.log --access access.log"""
import argparse
import json
import sys
from collections import Counter

from .detectors import run_all
from .parsers import parse_file


def to_markdown(findings, meta):
    lines = ["# Log Sentinel Detection Report", "",
             f"- Auth events parsed: **{meta['auth']}**",
             f"- Web requests parsed: **{meta['access']}**",
             f"- Findings: **{len(findings)}**", ""]
    sev = Counter(f.severity for f in findings)
    lines.append("Severity breakdown: " + ", ".join(f"{k}={v}" for k, v in sev.items()) + "\n")
    lines += ["| Severity | Rule | Source IP | Count | First seen | Description |",
              "|---|---|---|---|---|---|"]
    for f in findings:
        lines.append(f"| {f.severity.upper()} | {f.rule} | {f.source_ip} | {f.count} | "
                     f"{f.first_seen} | {f.description} |")
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(prog="log_sentinel",
                                description="Detect brute force, spraying and web attacks in logs.")
    p.add_argument("--auth", help="sshd auth log file")
    p.add_argument("--access", help="web access log (Common/Combined format)")
    p.add_argument("--year", type=int, help="year for syslog timestamps (default: current)")
    p.add_argument("--json", dest="json_out", help="write findings to JSON file")
    p.add_argument("--markdown", dest="md_out", help="write report to Markdown file")
    p.add_argument("--blocklist", help="write recommended IPs to block (high/critical) to a file")
    args = p.parse_args(argv)
    if not (args.auth or args.access):
        p.error("provide --auth and/or --access")

    auth = parse_file(args.auth, "auth", args.year) if args.auth else []
    access = parse_file(args.access, "access") if args.access else []
    findings = run_all(auth, access)
    meta = {"auth": len(auth), "access": len(access)}

    for f in findings:
        print(f"[{f.severity.upper():8}] {f.rule:28} {f.source_ip:16} {f.description}")
    print(f"\n{len(findings)} finding(s) from {meta['auth']} auth events, {meta['access']} web requests.")

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump({"meta": meta, "findings": [f.to_dict() for f in findings]}, fh, indent=2)
    if args.md_out:
        with open(args.md_out, "w") as fh:
            fh.write(to_markdown(findings, meta))
    if args.blocklist:
        ips = sorted({f.source_ip for f in findings if f.severity in ("high", "critical")})
        with open(args.blocklist, "w") as fh:
            fh.write("\n".join(ips) + "\n")
    # Non-zero exit when serious issues exist, so it can gate CI/cron alerts.
    return 1 if any(f.severity in ("high", "critical") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
