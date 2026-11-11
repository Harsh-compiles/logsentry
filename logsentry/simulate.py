"""Attack simulator: writes realistic log lines so you can demo LogSentry
without any servers.

It produces the same formats real machines write (sshd, sudo, UFW firewall,
nginx access logs), mixes normal background traffic with attack scenarios,
and appends them to log files that the collector tails, so the whole
pipeline runs end to end exactly as it would in production.

Attacker addresses come from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which are reserved and never
belong to a real machine.

This only *writes text to log files*. It never sends traffic anywhere. To run
real attacks against your own lab, see docs/ATTACK_PLAYBOOK.md.
"""

from __future__ import annotations

import os
import random
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone

HOSTS = ["web-01", "web-02", "bastion"]
WEB_HOSTS = ["web-01", "web-02"]
ADMIN_IP = "10.0.1.25"
NORMAL_USERS = ["ubuntu", "harsh", "deploy"]
SPRAY_USERS = ["admin", "root", "test", "oracle", "postgres", "user", "guest", "ftpuser", "pi", "ubnt", "support"]
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]
SITE_PATHS = ["/", "/about", "/login", "/products", "/products/42", "/cart", "/api/v1/items", "/static/app.js",
              "/static/style.css", "/favicon.ico", "/search?q=laptop", "/contact"]
ENUM_WORDS = ["admin", "backup", "old", "test", "dev", "uploads", "config", "db", "private", "tmp", "logs",
              "api/v2", "console", "wp-admin", "cgi-bin", "staging", "dashboard", "secret", "files", "server",
              "install", "panel", "manager", "portal", "shell", "data", "export", "debug", "temp", "includes"]
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 1723, 2049,
                3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017]

Line = tuple[str, str]  # (log kind: "syslog" | "web", text)


def rand_attacker() -> str:
    return random.choice([f"203.0.113.{random.randint(2, 254)}", f"198.51.100.{random.randint(2, 254)}",
                          f"192.0.2.{random.randint(2, 254)}"])


def rand_visitor() -> str:
    return f"{random.choice([24, 47, 66, 99, 142, 174, 206])}.{random.randint(1, 254)}." \
           f"{random.randint(1, 254)}.{random.randint(1, 254)}"


# ---- line builders ----------------------------------------------------------
def syslog(ts: datetime, host: str, prog: str, msg: str) -> Line:
    pid = random.randint(1000, 65000)
    tag = f"{prog}[{pid}]" if prog != "kernel" else "kernel"
    return "syslog", f"{ts.isoformat(timespec='microseconds')} {host} {tag}: {msg}"


def ssh_fail(ts, host, ip, user, invalid=False) -> Line:
    inv = "invalid user " if invalid else ""
    return syslog(ts, host, "sshd", f"Failed password for {inv}{user} from {ip} port {random.randint(30000, 65000)} ssh2")


def ssh_ok(ts, host, ip, user, method="publickey") -> Line:
    return syslog(ts, host, "sshd", f"Accepted {method} for {user} from {ip} port {random.randint(30000, 65000)} ssh2")


def sudo(ts, host, user, cmd, denied=False, pwd="/home") -> Line:
    d = "user NOT in sudoers ; " if denied else ""
    return syslog(ts, host, "sudo", f"   {user} : {d}TTY=pts/0 ; PWD={pwd} ; USER=root ; COMMAND={cmd}")


def fw_block(ts, host, ip, port, proto="TCP") -> Line:
    return syslog(ts, host, "kernel",
                  f"[{random.randint(10000, 99999)}.{random.randint(100000, 999999)}] [UFW BLOCK] IN=eth0 OUT= "
                  f"MAC=0a:1b:2c:3d:4e:5f SRC={ip} DST=10.0.1.10 LEN=44 TOS=0x00 PREC=0x00 TTL={random.randint(40, 64)} "
                  f"ID={random.randint(1, 65000)} PROTO={proto} SPT={random.randint(30000, 65000)} DPT={port} "
                  f"WINDOW=1024 RES=0x00 SYN URGP=0")


def web(ts, ip, method, path, status, ua, size=None, host=None) -> Line:
    """nginx access log line, forwarded through syslog (as on the AWS lab)."""
    size = size if size is not None else random.randint(200, 15000)
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    combined = f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
    return "syslog", f"{ts.isoformat(timespec='microseconds')} {host or random.choice(WEB_HOSTS)} nginx: {combined}"


# ---- scenarios: each yields (seconds to wait, builder(ts) -> Line) ----------
Step = tuple[float, Callable[[datetime], Line]]


def background() -> Iterator[Step]:
    """Normal traffic: page views, admin logins, internet noise on the firewall."""
    r = random.random()
    if r < 0.80:
        ip, ua, host = rand_visitor(), random.choice(BROWSER_UAS), random.choice(WEB_HOSTS)
        for _ in range(random.randint(1, 4)):
            path = random.choice(SITE_PATHS)
            status = 200 if random.random() > 0.05 else 404
            yield random.uniform(0.05, 0.6), lambda ts, p=path, s=status: web(ts, ip, "GET", p, s, ua, host=host)
    elif r < 0.92:
        port = random.choice([23, 445, 3389, 8080, 5900])
        ip = rand_visitor()
        yield random.uniform(0.1, 1), lambda ts: fw_block(ts, random.choice(HOSTS), ip, port)
    elif r < 0.96:
        user = random.choice(NORMAL_USERS)
        yield random.uniform(0.2, 1), lambda ts: ssh_ok(ts, "bastion", ADMIN_IP, user)
    elif r < 0.999:
        cmd = random.choice(["/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/tail -n 50 /var/log/syslog",
                             "/usr/bin/docker ps"])
        yield random.uniform(0.2, 1), lambda ts: sudo(ts, random.choice(HOSTS), "ubuntu", cmd)
    else:  # someone mistypes their password once; should NOT alert
        yield random.uniform(0.2, 1), lambda ts: ssh_fail(ts, "bastion", ADMIN_IP, "harsh")


def ssh_bruteforce() -> Iterator[Step]:
    ip, host, user = rand_attacker(), random.choice(HOSTS), random.choice(["root", "admin", "ubuntu"])
    for _ in range(random.randint(8, 18)):
        yield random.uniform(0.3, 1.2), lambda ts: ssh_fail(ts, host, ip, user, invalid=user == "admin")


def password_spray() -> Iterator[Step]:
    ip, host = rand_attacker(), random.choice(HOSTS)
    for user in random.sample(SPRAY_USERS, 8):
        yield random.uniform(0.4, 1.5), lambda ts, u=user: ssh_fail(ts, host, ip, u, invalid=u not in ("root",))


def ssh_compromise() -> Iterator[Step]:
    """Brute force that succeeds, followed by the attacker escalating with sudo."""
    ip, host = rand_attacker(), "web-02"
    for _ in range(random.randint(6, 10)):
        yield random.uniform(0.3, 0.9), lambda ts: ssh_fail(ts, host, ip, "deploy")
    yield random.uniform(0.5, 1.5), lambda ts: ssh_ok(ts, host, ip, "deploy", method="password")
    yield random.uniform(3, 6), lambda ts: sudo(ts, host, "deploy", "/usr/bin/cat /etc/shadow", pwd="/home/deploy")
    yield random.uniform(1, 3), lambda ts: sudo(ts, host, "deploy", "/bin/bash", pwd="/home/deploy")


def port_scan() -> Iterator[Step]:
    ip, host = rand_attacker(), random.choice(HOSTS)
    ports = random.sample(COMMON_PORTS, 22) + random.sample(range(1024, 10000), 10)
    for port in ports:
        yield random.uniform(0.02, 0.25), lambda ts, p=port: fw_block(ts, host, ip, p)


def sql_injection() -> Iterator[Step]:
    ip, ua = rand_attacker(), "sqlmap/1.8.11#stable (https://sqlmap.org)"
    host = random.choice(WEB_HOSTS)
    payloads = ["/products?id=42%27", "/products?id=42%27%20OR%20%271%27%3D%271",
                "/products?id=42%20UNION%20SELECT%20username,password%20FROM%20users--",
                "/products?id=42%27%20AND%20SLEEP(5)--", "/search?q=%27%20OR%201%3D1--",
                "/products?id=42%20UNION%20ALL%20SELECT%20NULL,table_name%20FROM%20information_schema.tables--"]
    for p in payloads:
        yield random.uniform(0.2, 0.8), lambda ts, p=p: web(ts, ip, "GET", p, random.choice([200, 500, 500]), ua, host=host)


def xss_probe() -> Iterator[Step]:
    ip, ua = rand_attacker(), random.choice(BROWSER_UAS)
    host = random.choice(WEB_HOSTS)
    for p in ["/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "/contact?name=%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E",
              "/search?q=%3Csvg%20onload%3Dalert(1)%3E"]:
        yield random.uniform(0.5, 2), lambda ts, p=p: web(ts, ip, "GET", p, 200, ua, host=host)


def path_traversal() -> Iterator[Step]:
    ip, ua = rand_attacker(), "curl/8.5.0"
    host = random.choice(WEB_HOSTS)
    for p in ["/static/..%2F..%2F..%2Fetc%2Fpasswd", "/download?file=../../../../etc/passwd",
              "/download?file=..%252F..%252F..%252Fetc%252Fshadow", "/.env", "/.git/config"]:
        yield random.uniform(0.3, 1), lambda ts, p=p: web(ts, ip, "GET", p, random.choice([400, 403, 404]), ua, host=host)


def webshell_chain() -> Iterator[Step]:
    """Command injection in a web app, then the web server account runs sudo."""
    ip, host = rand_attacker(), "web-01"
    ua = "python-requests/2.32.3"
    for p in ["/api/v1/ping?host=127.0.0.1%3Bid", "/api/v1/ping?host=127.0.0.1%3Bwhoami",
              "/api/v1/ping?host=127.0.0.1%7Ccat%20%2Fetc%2Fpasswd"]:
        yield random.uniform(0.4, 1.2), lambda ts, p=p: web(ts, ip, "GET", p, 200, ua, host=host)
    yield random.uniform(2, 4), lambda ts: sudo(ts, host, "www-data", "/bin/bash -i", pwd="/var/www/html")


def dir_enumeration() -> Iterator[Step]:
    ip, ua = rand_attacker(), "gobuster/3.6"
    host = random.choice(WEB_HOSTS)
    for w in random.sample(ENUM_WORDS, 28):
        yield random.uniform(0.03, 0.2), lambda ts, w=w: web(ts, ip, "GET", f"/{w}", random.choice([404] * 9 + [403]), ua, 162, host=host)


def insider_sudo() -> Iterator[Step]:
    host = random.choice(HOSTS)
    yield random.uniform(0.5, 2), lambda ts: sudo(ts, host, "intern", "/usr/bin/cat /etc/shadow", denied=True,
                                                  pwd="/home/intern")


ATTACKS: dict[str, Callable[[], Iterator[Step]]] = {
    "ssh_bruteforce": ssh_bruteforce,
    "password_spray": password_spray,
    "ssh_compromise": ssh_compromise,
    "port_scan": port_scan,
    "sql_injection": sql_injection,
    "xss": xss_probe,
    "path_traversal": path_traversal,
    "webshell": webshell_chain,
    "dir_enumeration": dir_enumeration,
    "insider_sudo": insider_sudo,
}
ATTACK_WEIGHTS = {"ssh_bruteforce": 4, "password_spray": 2, "port_scan": 3, "sql_injection": 2, "dir_enumeration": 2,
                  "path_traversal": 2, "xss": 1, "ssh_compromise": 1, "webshell": 1, "insider_sudo": 1}


class Simulator:
    """Interleaves background traffic with attacks.

    ``realtime=True`` sleeps between lines and stamps them with the current
    time (for live demos). ``realtime=False`` uses a fast synthetic clock
    (for tests and quick replays).
    """

    def __init__(self, attack_every: float = 12.0, realtime: bool = True, start: datetime | None = None,
                 seed: int | None = None):
        self.attack_every = attack_every
        self.realtime = realtime
        self.clock = start or datetime.now(timezone.utc)
        if seed is not None:
            random.seed(seed)

    def _now(self) -> datetime:
        return datetime.now(timezone.utc) if self.realtime else self.clock

    def _wait(self, seconds: float) -> None:
        if self.realtime:
            time.sleep(seconds)
        else:
            self.clock += timedelta(seconds=seconds)

    def stream(self, duration: float | None = None, scenarios: list[str] | None = None) -> Iterator[Line]:
        """Yield log lines forever (or for ``duration`` seconds).

        ``scenarios=[]`` produces normal traffic only (no attacks)."""
        names = list(ATTACKS) if scenarios is None else scenarios
        weights = [ATTACK_WEIGHTS.get(n, 1) for n in names]
        start = self._now()
        next_attack = start + timedelta(seconds=3) if names else None
        pending: list[tuple[datetime, int, Callable, Iterator[Step], bool]] = []
        seq = 0

        def schedule(it: Iterator[Step], is_bg: bool) -> None:
            nonlocal seq
            try:
                delay, fn = next(it)
            except StopIteration:
                if is_bg:  # background traffic never stops
                    schedule(background(), True)
                return
            seq += 1
            pending.append((self._now() + timedelta(seconds=delay), seq, fn, it, is_bg))

        schedule(background(), True)
        while duration is None or (self._now() - start).total_seconds() < duration:
            if next_attack and self._now() >= next_attack:
                schedule(ATTACKS[random.choices(names, weights)[0]](), False)
                next_attack = self._now() + timedelta(seconds=random.uniform(0.5, 1.5) * self.attack_every)
            pending.sort(key=lambda p: (p[0], p[1]))
            due = pending[0][0]
            target = due if next_attack is None else min(due, next_attack)
            self._wait(max(0.0, (target - self._now()).total_seconds()))
            if next_attack and due > next_attack:
                continue  # time to launch the next attack first
            _, _, fn, it, is_bg = pending.pop(0)
            yield fn(self._now())
            schedule(it, is_bg)

    def run_scenario(self, name: str) -> list[Line]:
        """All lines of one attack scenario (synthetic clock)."""
        lines = []
        for delay, fn in ATTACKS[name]():
            self._wait(delay)
            lines.append(fn(self._now()))
        return lines


def write_stream(log_dir: str, attack_every: float = 12.0, duration: float | None = None) -> str:
    """Append simulated logs to <log_dir>/remote.log, the same single file the
    central rsyslog server writes on the AWS lab. Returns the file path."""
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, "remote.log")
    with open(path, "a", buffering=1) as f:
        for _kind, text in Simulator(attack_every=attack_every).stream(duration):
            f.write(text + "\n")
    return path
