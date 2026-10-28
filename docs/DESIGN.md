# Design Document

## 1. Problem
Small teams often run SSH and web servers but lack a SIEM. Attacks such as brute forcing,
password spraying and injection probing are visible in ordinary logs but buried in volume.
Log Sentinel turns raw logs into a short, prioritized list of suspicious sources.

## 2. Architecture
```
 auth.log / access.log
        |
   parsers.py  ->  normalized event dicts (time, ip, user/path, status ...)
        |
  detectors.py ->  rules -> Finding objects (rule, severity, ip, count, window, MITRE ID, evidence)
        |
     cli.py    ->  console summary, JSON, Markdown report, recommended blocklist
```
* **parsers.py** - regex parsers for sshd syslog lines and Common/Combined access logs.
  Unparseable lines are skipped, never crash the run.
* **detectors.py** - each rule is an independent pure function (events in, findings out),
  which makes it easy to unit test and extend.
* **cli.py** - argparse front-end; exit code 1 on high/critical findings.

## 3. Detection Logic
* **Sliding window** (`max_in_window`): two-pointer scan over sorted timestamps gives the
  densest burst per IP in O(n) - used for brute force and 404 enumeration.
* **Spray**: sliding window counting *distinct usernames*, so slow-and-wide attacks that stay
  under a per-user threshold are still caught.
* **Success after failures**: for every successful login, count same-IP failures in the
  preceding window. This is the highest-value alert (the attacker may have gotten in).
* **Web signatures**: request path is URL-decoded twice (defeats `%2e%2e%2f` and
  `%2520` double encoding) then matched against SQLi/XSS/traversal/command-injection patterns.
  Alerts are aggregated per (rule, IP) to avoid flooding.

## 4. Testing Strategy (26 tests)
* Parser tests: valid, invalid-user, accepted, garbage, malformed-file lines.
* Boundary tests: exactly at threshold, one below, spread outside window, multiple IPs.
* **False-positive tests:** single typo then login, repeated same-user failure, benign
  searches containing words like "union"/"select", few 404s.
* Evasion test: double-encoded SQLi.
* End-to-end: all 9 planted behaviours detected, zero alerts for internal 10.0.0.x hosts,
  CLI outputs and exit code.

## 5. Limitations & Future Work
* Signature rules are heuristic: obfuscated payloads (comments, case/whitespace tricks,
  POST bodies) can evade; legitimate requests that resemble attacks may alert.
* Per-IP logic misses distributed attacks from many IPs and attackers behind shared NAT.
* Only IPv4/IPv6 text addresses; no GeoIP or reputation enrichment.
* Syslog timestamps have no year (provided via `--year`).
* Future: streaming/tail mode, config file for thresholds, allow-list for trusted IPs,
  automatic fail2ban/iptables integration (with human approval), more log sources.

## 6. Safety
Read-only analysis. No network activity, no payload generation, no automatic blocking.
Sample logs are synthetic and use RFC 5737 documentation IP ranges.
