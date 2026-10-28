"""Detection rules. Each detector takes parsed events and returns a list of Finding."""
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import timedelta
from urllib.parse import unquote_plus

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    source_ip: str
    description: str
    count: int
    first_seen: str
    last_seen: str
    mitre: str = ""
    evidence: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def _iso(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def max_in_window(times, window_seconds):
    """Sliding window over sorted datetimes -> (max_count, window_start, window_end)."""
    best = (0, None, None)
    left = 0
    delta = timedelta(seconds=window_seconds)
    for right in range(len(times)):
        while times[right] - times[left] > delta:
            left += 1
        count = right - left + 1
        if count > best[0]:
            best = (count, times[left], times[right])
    return best


# --------------------------------------------------------------------- SSH rules
def detect_bruteforce(events, threshold=10, window=300):
    """Many failed logins from one IP in a short window (T1110.001)."""
    fails = defaultdict(list)
    for e in events:
        if not e["success"]:
            fails[e["ip"]].append(e)
    out = []
    for ip, evs in fails.items():
        times = [e["time"] for e in evs]
        count, start, end = max_in_window(times, window)
        if count >= threshold:
            users = sorted({e["user"] for e in evs})
            out.append(Finding(
                "SSH_BRUTE_FORCE", "high" if count >= 30 else "medium", ip,
                f"{count} failed SSH logins within {window}s", count,
                _iso(start), _iso(end), "T1110.001",
                [f"targeted users: {', '.join(users[:5])}"]))
    return out


def detect_password_spray(events, min_users=5, window=600):
    """One IP trying many different usernames in a window (T1110.003)."""
    fails = defaultdict(list)
    for e in events:
        if not e["success"]:
            fails[e["ip"]].append(e)
    out = []
    for ip, evs in fails.items():
        left = 0
        best = (0, None, None)
        delta = timedelta(seconds=window)
        for right in range(len(evs)):
            while evs[right]["time"] - evs[left]["time"] > delta:
                left += 1
            users = {e["user"] for e in evs[left:right + 1]}
            if len(users) > best[0]:
                best = (len(users), evs[left]["time"], evs[right]["time"])
        if best[0] >= min_users:
            out.append(Finding(
                "SSH_PASSWORD_SPRAY", "high", ip,
                f"{best[0]} distinct usernames tried within {window}s", best[0],
                _iso(best[1]), _iso(best[2]), "T1110.003"))
    return out


def detect_success_after_failures(events, min_failures=5, window=600):
    """A successful login right after a burst of failures from the same IP."""
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)
    out = []
    for ip, evs in by_ip.items():
        for i, e in enumerate(evs):
            if not e["success"]:
                continue
            prior = [p for p in evs[:i]
                     if not p["success"] and 0 <= (e["time"] - p["time"]).total_seconds() <= window]
            if len(prior) >= min_failures:
                out.append(Finding(
                    "SSH_SUCCESS_AFTER_FAILURES", "critical", ip,
                    f"Login to '{e['user']}' succeeded after {len(prior)} recent failures "
                    "- possible account compromise",
                    len(prior), _iso(prior[0]["time"]), _iso(e["time"]), "T1078",
                    [f"successful user: {e['user']} via {e['method']}"]))
                break
    return out


# --------------------------------------------------------------------- Web rules
WEB_SIGNATURES = {
    "WEB_SQL_INJECTION": ("high", "T1190", re.compile(
        r"(\bunion\b.+\bselect\b|\bor\b\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+|'\s*or\s*'"
        r"|sleep\(\d+\)|information_schema|;\s*drop\s+table|benchmark\()", re.I)),
    "WEB_XSS": ("medium", "T1189", re.compile(
        r"(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*on\w+\s*=)", re.I)),
    "WEB_PATH_TRAVERSAL": ("high", "T1190", re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|\x00)", re.I)),
    "WEB_COMMAND_INJECTION": ("high", "T1190", re.compile(
        r"(;|\||`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b", re.I)),
}
SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|acunetix|nessus)", re.I)


def _decode(path, rounds=2):
    for _ in range(rounds):
        path = unquote_plus(path)
    return path


def detect_web_attacks(entries):
    """Signature matching on request paths and scanner user-agents (aggregated per IP+rule)."""
    hits = defaultdict(list)
    for e in entries:
        decoded = _decode(e["path"])
        for rule, (_, _, rx) in WEB_SIGNATURES.items():
            if rx.search(decoded):
                hits[(rule, e["ip"])].append(e)
        if SCANNER_UA.search(e["ua"]):
            hits[("WEB_SCANNER_USER_AGENT", e["ip"])].append(e)
    out = []
    for (rule, ip), evs in hits.items():
        if rule == "WEB_SCANNER_USER_AGENT":
            sev, mitre, desc = "medium", "T1595", f"Known attack-tool user-agent: {evs[0]['ua'][:40]}"
        else:
            sev, mitre, _ = WEB_SIGNATURES[rule]
            desc = f"{len(evs)} request(s) matching {rule.replace('WEB_', '').lower()} patterns"
        out.append(Finding(rule, sev, ip, desc, len(evs), _iso(evs[0]["time"]),
                           _iso(evs[-1]["time"]), mitre, [e["path"][:100] for e in evs[:3]]))
    return out


def detect_404_scan(entries, threshold=20, window=60):
    """Burst of 404s from one IP: directory/file enumeration (T1595.003)."""
    by_ip = defaultdict(list)
    for e in entries:
        if e["status"] == 404:
            by_ip[e["ip"]].append(e["time"])
    out = []
    for ip, times in by_ip.items():
        count, start, end = max_in_window(times, window)
        if count >= threshold:
            out.append(Finding("WEB_404_ENUMERATION", "medium", ip,
                               f"{count} HTTP 404 responses within {window}s", count,
                               _iso(start), _iso(end), "T1595.003"))
    return out


def run_all(auth_events=None, access_entries=None):
    findings = []
    if auth_events:
        findings += detect_bruteforce(auth_events)
        findings += detect_password_spray(auth_events)
        findings += detect_success_after_failures(auth_events)
    if access_entries:
        findings += detect_web_attacks(access_entries)
        findings += detect_404_scan(access_entries)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.source_ip, f.rule))
    return findings
