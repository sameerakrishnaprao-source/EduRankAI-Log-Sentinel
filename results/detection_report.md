# Log Sentinel Detection Report

- Auth events parsed: **57**
- Web requests parsed: **53**
- Findings: **10**

Severity breakdown: critical=1, high=5, medium=4

| Severity | Rule | Source IP | Count | First seen | Description |
|---|---|---|---|---|---|
| CRITICAL | SSH_SUCCESS_AFTER_FAILURES | 192.0.2.44 | 8 | 2026-10-27 05:00:00 | Login to 'admin' succeeded after 8 recent failures - possible account compromise |
| HIGH | WEB_COMMAND_INJECTION | 192.0.2.150 | 1 | 2026-10-27 10:02:00 | 1 request(s) matching command_injection patterns |
| HIGH | SSH_BRUTE_FORCE | 198.51.100.7 | 30 | 2026-10-27 03:00:00 | 30 failed SSH logins within 300s |
| HIGH | WEB_SQL_INJECTION | 198.51.100.77 | 4 | 2026-10-27 10:00:00 | 4 request(s) matching sql_injection patterns |
| HIGH | SSH_PASSWORD_SPRAY | 203.0.113.50 | 12 | 2026-10-27 04:00:00 | 12 distinct usernames tried within 600s |
| HIGH | WEB_PATH_TRAVERSAL | 203.0.113.99 | 2 | 2026-10-27 10:01:05 | 2 request(s) matching path_traversal patterns |
| MEDIUM | WEB_404_ENUMERATION | 192.0.2.200 | 40 | 2026-10-27 10:03:00 | 40 HTTP 404 responses within 60s |
| MEDIUM | WEB_SCANNER_USER_AGENT | 198.51.100.77 | 4 | 2026-10-27 10:00:00 | Known attack-tool user-agent: sqlmap/1.7.2#stable |
| MEDIUM | SSH_BRUTE_FORCE | 203.0.113.50 | 11 | 2026-10-27 04:00:00 | 11 failed SSH logins within 300s |
| MEDIUM | WEB_XSS | 203.0.113.99 | 1 | 2026-10-27 10:01:00 | 1 request(s) matching xss patterns |
