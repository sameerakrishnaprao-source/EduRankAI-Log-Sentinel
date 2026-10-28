"""Generate deterministic synthetic logs (documentation-range IPs only, no real data)."""
from datetime import datetime, timedelta
import os

HERE = os.path.dirname(os.path.abspath(__file__))
auth, web = [], []

def a(t, ok, user, ip, invalid=False):
    ts = f"{t.strftime('%b')} {t.day:2d} {t.strftime('%H:%M:%S')}"
    if ok:
        msg = f"Accepted password for {user} from {ip} port {40000 + t.second}"
    else:
        msg = f"Failed password for {'invalid user ' if invalid else ''}{user} from {ip} port {40000 + t.second}"
    auth.append((t, f"{ts} web01 sshd[{2000 + len(auth)}]: {msg} ssh2"))

base = datetime(2026, 10, 27, 3, 0, 0)
# 1. Brute force: 30 failures on root in ~2 minutes, never succeeds
for i in range(30):
    a(base + timedelta(seconds=4 * i), False, "root", "198.51.100.7")
# 2. Password spray: 12 usernames, one attempt each, 30s apart
for i, u in enumerate(["admin", "test", "oracle", "postgres", "ubuntu", "guest",
                       "deploy", "git", "jenkins", "ftpuser", "pi", "user"]):
    a(base + timedelta(hours=1, seconds=30 * i), False, u, "203.0.113.50", invalid=True)
# 3. Compromise: 8 failures then success for admin
for i in range(8):
    a(base + timedelta(hours=2, seconds=10 * i), False, "admin", "192.0.2.44")
a(base + timedelta(hours=2, seconds=95), True, "admin", "192.0.2.44")
# Benign traffic (should NOT alert)
a(base + timedelta(hours=3), True, "alice", "10.0.0.5")
a(base + timedelta(hours=3, minutes=5), False, "bob", "10.0.0.8")       # typo
a(base + timedelta(hours=3, minutes=5, seconds=20), True, "bob", "10.0.0.8")
a(base + timedelta(hours=4), False, "carol", "10.0.0.9")
a(base + timedelta(hours=5), False, "carol", "10.0.0.9")
a(base + timedelta(hours=5, minutes=1), True, "carol", "10.0.0.9")

def w(t, ip, path, status=200, ua="Mozilla/5.0 (X11; Linux x86_64)", method="GET"):
    web.append((t, f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
                   f'"{method} {path} HTTP/1.1" {status} 512 "-" "{ua}"'))

wb = datetime(2026, 10, 27, 10, 0, 0)
# SQLi + sqlmap
for i, p in enumerate(["/item.php?id=1%27%20OR%20%271%27=%271",
                       "/item.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
                       "/item.php?id=1;%20DROP%20TABLE%20users",
                       "/item.php?id=1%20AND%20sleep(5)"]):
    w(wb + timedelta(seconds=i), "198.51.100.77", p, 500, "sqlmap/1.7.2#stable")
# XSS and traversal from another IP
w(wb + timedelta(minutes=1), "203.0.113.99", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200)
w(wb + timedelta(minutes=1, seconds=5), "203.0.113.99", "/download?file=../../../../etc/passwd", 403)
w(wb + timedelta(minutes=1, seconds=9), "203.0.113.99", "/download?file=%2e%2e%2f%2e%2e%2fetc%2fshadow", 403)
# Command injection
w(wb + timedelta(minutes=2), "192.0.2.150", "/ping?host=8.8.8.8;cat%20/etc/hosts", 200)
# 404 enumeration burst: 40 in 40 seconds
for i, name in enumerate(["admin", "backup", "config", "login", "test"] * 8):
    w(wb + timedelta(minutes=3, seconds=i), "192.0.2.200", f"/{name}{i}.php", 404, "curl/8.1")
# Benign traffic (should NOT alert), including tricky look-alikes
w(wb + timedelta(minutes=4), "10.0.0.5", "/index.html")
w(wb + timedelta(minutes=4, seconds=3), "10.0.0.5", "/search?q=credit+union+news")
w(wb + timedelta(minutes=4, seconds=9), "10.0.0.6", "/products?cat=books&sort=price")
w(wb + timedelta(minutes=4, seconds=15), "10.0.0.6", "/about", 404)
w(wb + timedelta(minutes=5), "10.0.0.7", "/blog/how-to-select-a-union-rep")

for name, rows in (("auth.log", auth), ("access.log", web)):
    with open(os.path.join(HERE, name), "w") as fh:
        for _, line in sorted(rows, key=lambda r: r[0]):
            fh.write(line + "\n")
print("samples written:", len(auth), "auth lines,", len(web), "web lines")
