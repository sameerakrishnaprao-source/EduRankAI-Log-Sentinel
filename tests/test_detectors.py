import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_sentinel.parsers import parse_auth_line, parse_access_line, parse_file
from log_sentinel import detectors as d
from log_sentinel.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T0 = datetime(2026, 10, 27, 3, 0, 0)


def fail(sec, user="root", ip="198.51.100.1"):
    return {"time": T0 + timedelta(seconds=sec), "success": False, "user": user, "ip": ip, "method": "password"}


def ok(sec, user="root", ip="198.51.100.1"):
    return {"time": T0 + timedelta(seconds=sec), "success": True, "user": user, "ip": ip, "method": "password"}


def web(path, ip="198.51.100.2", status=200, ua="Mozilla/5.0", sec=0):
    return {"time": T0 + timedelta(seconds=sec), "ip": ip, "method": "GET", "path": path, "status": status, "ua": ua}


class TestParsers(unittest.TestCase):
    def test_failed_invalid_user(self):
        ev = parse_auth_line("Oct  5 03:12:01 h sshd[9]: Failed password for invalid user bob from 203.0.113.5 port 22 ssh2", 2026)
        self.assertEqual((ev["user"], ev["ip"], ev["success"]), ("bob", "203.0.113.5", False))
        self.assertEqual(ev["time"], datetime(2026, 10, 5, 3, 12, 1))

    def test_accepted(self):
        ev = parse_auth_line("Oct 27 03:12:01 h sshd[9]: Accepted publickey for alice from 10.0.0.1 port 5000 ssh2", 2026)
        self.assertTrue(ev["success"])

    def test_irrelevant_and_garbage_lines(self):
        self.assertIsNone(parse_auth_line("Oct 27 03:12:01 h cron[1]: job done", 2026))
        self.assertIsNone(parse_auth_line("", 2026))
        self.assertIsNone(parse_access_line("not a log line"))

    def test_access_line(self):
        ev = parse_access_line('1.2.3.4 - - [27/Oct/2026:10:00:00 +0000] "GET /a?b=1 HTTP/1.1" 404 12 "-" "curl/8"')
        self.assertEqual((ev["ip"], ev["status"], ev["ua"], ev["path"]), ("1.2.3.4", 404, "curl/8", "/a?b=1"))

    def test_parse_file_skips_malformed(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
            fh.write("garbage\nOct 27 03:00:00 h sshd[1]: Failed password for root from 1.1.1.1 port 1 ssh2\n")
        try:
            self.assertEqual(len(parse_file(fh.name, "auth", 2026)), 1)
        finally:
            os.unlink(fh.name)


class TestSSHRules(unittest.TestCase):
    def test_bruteforce_at_threshold(self):
        self.assertEqual(len(d.detect_bruteforce([fail(i) for i in range(10)])), 1)

    def test_bruteforce_below_threshold(self):
        self.assertEqual(d.detect_bruteforce([fail(i) for i in range(9)]), [])

    def test_bruteforce_spread_outside_window(self):
        self.assertEqual(d.detect_bruteforce([fail(i * 100) for i in range(10)]), [])  # 1 per 100s

    def test_bruteforce_separate_ips_not_combined(self):
        evs = [fail(i, ip=f"198.51.100.{i % 2}") for i in range(12)]  # 6 each
        self.assertEqual(d.detect_bruteforce(evs), [])

    def test_spray_detected(self):
        evs = [fail(i * 10, user=f"user{i}") for i in range(6)]
        f = d.detect_password_spray(evs)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].count, 6)

    def test_spray_same_user_not_spray(self):
        self.assertEqual(d.detect_password_spray([fail(i, user="root") for i in range(20)]), [])

    def test_success_after_failures_critical(self):
        f = d.detect_success_after_failures([fail(i) for i in range(6)] + [ok(60)])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")

    def test_single_typo_then_success_is_benign(self):
        self.assertEqual(d.detect_success_after_failures([fail(0), ok(20)]), [])

    def test_old_failures_ignored(self):
        evs = [fail(i) for i in range(6)] + [ok(5000)]
        self.assertEqual(d.detect_success_after_failures(evs), [])


class TestWebRules(unittest.TestCase):
    def rules(self, path, **kw):
        return {f.rule for f in d.detect_web_attacks([web(path, **kw)])}

    def test_sqli_variants(self):
        self.assertIn("WEB_SQL_INJECTION", self.rules("/i?id=1%27%20OR%20%271%27=%271"))
        self.assertIn("WEB_SQL_INJECTION", self.rules("/i?id=1+UNION+SELECT+1,2"))
        self.assertIn("WEB_SQL_INJECTION", self.rules("/i?id=1%20or%201=1"))

    def test_double_encoded_sqli(self):
        self.assertIn("WEB_SQL_INJECTION", self.rules("/i?id=1%2520UNION%2520SELECT%25201"))

    def test_xss(self):
        self.assertIn("WEB_XSS", self.rules("/s?q=%3Cscript%3Ealert(1)%3C/script%3E"))

    def test_traversal_encoded(self):
        self.assertIn("WEB_PATH_TRAVERSAL", self.rules("/d?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd"))

    def test_command_injection(self):
        self.assertIn("WEB_COMMAND_INJECTION", self.rules("/p?h=1.1.1.1;cat%20/etc/hosts"))

    def test_scanner_user_agent(self):
        self.assertIn("WEB_SCANNER_USER_AGENT", self.rules("/", ua="Nikto/2.5"))

    def test_benign_requests_no_alerts(self):
        for p in ["/index.html", "/search?q=credit+union+news", "/products?cat=books&sort=price",
                  "/blog/how-to-select-a-union-rep", "/about?lang=en"]:
            self.assertEqual(self.rules(p), set(), msg=p)

    def test_404_burst(self):
        evs = [web(f"/x{i}", status=404, sec=i) for i in range(20)]
        self.assertEqual(len(d.detect_404_scan(evs)), 1)

    def test_few_404s_benign(self):
        evs = [web(f"/x{i}", status=404, sec=i * 30) for i in range(10)]
        self.assertEqual(d.detect_404_scan(evs), [])


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.auth = parse_file(os.path.join(ROOT, "samples", "auth.log"), "auth", 2026)
        self.access = parse_file(os.path.join(ROOT, "samples", "access.log"), "access")
        self.findings = d.run_all(self.auth, self.access)

    def test_expected_detections(self):
        got = {(f.rule, f.source_ip) for f in self.findings}
        expected = {
            ("SSH_BRUTE_FORCE", "198.51.100.7"), ("SSH_PASSWORD_SPRAY", "203.0.113.50"),
            ("SSH_SUCCESS_AFTER_FAILURES", "192.0.2.44"), ("WEB_SQL_INJECTION", "198.51.100.77"),
            ("WEB_SCANNER_USER_AGENT", "198.51.100.77"), ("WEB_XSS", "203.0.113.99"),
            ("WEB_PATH_TRAVERSAL", "203.0.113.99"), ("WEB_COMMAND_INJECTION", "192.0.2.150"),
            ("WEB_404_ENUMERATION", "192.0.2.200"),
        }
        self.assertTrue(expected <= got, msg=expected - got)

    def test_no_false_positives_on_internal_hosts(self):
        self.assertFalse([f for f in self.findings if f.source_ip.startswith("10.0.0.")])

    def test_cli_writes_outputs_and_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            j, bl = os.path.join(tmp, "o.json"), os.path.join(tmp, "bl.txt")
            code = main(["--auth", os.path.join(ROOT, "samples", "auth.log"), "--year", "2026",
                         "--json", j, "--blocklist", bl])
            self.assertEqual(code, 1)
            self.assertTrue(os.path.getsize(j) > 0)
            with open(bl) as fh:
                self.assertIn("198.51.100.7", fh.read())


if __name__ == "__main__":
    unittest.main()
