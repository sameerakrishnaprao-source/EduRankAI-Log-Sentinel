"""Parsers for SSH auth logs (syslog format) and web access logs (Common/Combined)."""
import re
from datetime import datetime
from typing import Optional

AUTH_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s(?P<host>\S+)\ssshd\[\d+\]:\s"
    r"(?P<result>Failed|Accepted)\s(?P<method>\w+(?:-\w+)*)\sfor\s"
    r"(?:invalid user\s)?(?P<user>\S+)\sfrom\s(?P<ip>[0-9a-fA-F.:]+)\sport\s(?P<port>\d+)"
)

ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s\S+\s\S+\s\[(?P<ts>[^\]]+)\]\s'
    r'"(?P<method>[A-Z]+)\s(?P<path>\S+)(?:\s(?P<proto>[^"]*))?"\s'
    r'(?P<status>\d{3})\s(?P<size>\S+)'
    r'(?:\s"(?P<ref>[^"]*)"\s"(?P<ua>[^"]*)")?'
)


def parse_auth_line(line: str, year: int) -> Optional[dict]:
    """Parse one sshd log line. Returns None for lines we do not care about."""
    m = AUTH_RE.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(f"{year} {' '.join(m['ts'].split())}", "%Y %b %d %H:%M:%S")
    return {
        "time": ts,
        "host": m["host"],
        "success": m["result"] == "Accepted",
        "method": m["method"],
        "user": m["user"],
        "ip": m["ip"],
    }


def parse_access_line(line: str) -> Optional[dict]:
    """Parse one Common/Combined-format web access log line."""
    m = ACCESS_RE.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    return {
        "time": ts,
        "ip": m["ip"],
        "method": m["method"],
        "path": m["path"],
        "status": int(m["status"]),
        "ua": m["ua"] or "",
    }


def parse_file(path: str, kind: str, year: int = None) -> list:
    """Parse a whole file. kind is 'auth' or 'access'. Malformed lines are skipped."""
    year = year or datetime.now().year
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ev = parse_auth_line(line, year) if kind == "auth" else parse_access_line(line)
            if ev:
                events.append(ev)
    events.sort(key=lambda e: e["time"])
    return events
