"""Detection rules.

Each rule looks at one event at a time, keeps whatever short-term memory it
needs (sliding time windows), and returns an ``Alert`` when something
suspicious happens. Rules are deliberately transparent: every alert says
exactly which threshold was crossed and shows the log lines that crossed it.

Thresholds are set in ``RuleConfig`` so they can be tuned per environment.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .parsers import Event

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str                   # low | medium | high | critical
    description: str
    event_ts: datetime              # timestamp of the log line that triggered it
    src_ip: str | None = None
    host: str | None = None
    user: str | None = None
    count: int = 1
    mitre: str = ""                 # MITRE ATT&CK technique, e.g. "T1110.001"
    evidence: list[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    @property
    def latency_ms(self) -> float:
        """Time from the log line being written to the alert firing."""
        return max(0.0, (self.detected_at - self.event_ts).total_seconds() * 1000)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "event_ts": self.event_ts.isoformat(),
            "detected_at": self.detected_at.isoformat(),
            "latency_ms": round(self.latency_ms, 1),
            "src_ip": self.src_ip,
            "host": self.host,
            "user": self.user,
            "count": self.count,
            "mitre": self.mitre,
            "evidence": self.evidence,
        }


@dataclass
class RuleConfig:
    ssh_bruteforce_threshold: int = 5          # failed logins ...
    ssh_bruteforce_window: int = 60            # ... within this many seconds
    compromise_lookback: int = 600             # success after brute force within 10 min
    portscan_ports: int = 15                   # distinct blocked ports ...
    portscan_window: int = 60                  # ... within this many seconds
    web_enum_threshold: int = 20               # 4xx responses ...
    web_enum_window: int = 60                  # ... within this many seconds
    cooldown: int = 300                        # don't repeat the same alert for 5 min
    service_accounts: tuple[str, ...] = ("www-data", "nginx", "apache", "nobody", "daemon", "postgres", "mysql")


class SlidingWindow:
    """Per-key time window of recent items (e.g. failed logins per IP)."""

    def __init__(self, seconds: int):
        self.span = timedelta(seconds=seconds)
        self.items: dict[str, deque] = defaultdict(deque)

    def add(self, key: str, ts: datetime, value) -> deque:
        q = self.items[key]
        q.append((ts, value))
        while q and ts - q[0][0] > self.span:
            q.popleft()
        return q

    def get(self, key: str, now: datetime) -> deque:
        q = self.items.get(key, deque())
        while q and now - q[0][0] > self.span:
            q.popleft()
        return q

    def clear(self, key: str) -> None:
        self.items.pop(key, None)


class Rule:
    rule_id = "base"

    def __init__(self, cfg: RuleConfig):
        self.cfg = cfg

    def process(self, ev: Event) -> list[Alert]:  # pragma: no cover - interface
        raise NotImplementedError


# -----------------------------------------------------------------------------
class SSHBruteForce(Rule):
    """Many failed SSH logins from one IP in a short window (T1110)."""

    rule_id = "ssh_bruteforce"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.window = SlidingWindow(cfg.ssh_bruteforce_window)

    def process(self, ev):
        if ev.kind != "ssh_failed" or not ev.src_ip:
            return []
        q = self.window.add(ev.src_ip, ev.ts, ev)
        if len(q) < self.cfg.ssh_bruteforce_threshold:
            return []
        events = [e for _, e in q]
        users = sorted({e.user for e in events if e.user})
        self.window.clear(ev.src_ip)  # start counting again for the next burst
        spraying = len(users) > 3
        return [Alert(
            rule_id=self.rule_id,
            title="SSH password spraying" if spraying else "SSH brute-force attack",
            severity="high",
            description=(
                f"{len(events)} failed SSH logins from {ev.src_ip} in under "
                f"{self.cfg.ssh_bruteforce_window}s against {len(users)} account(s): {', '.join(users[:6])}"
            ),
            event_ts=ev.ts, src_ip=ev.src_ip, host=ev.host, count=len(events),
            mitre="T1110.003" if spraying else "T1110.001",
            evidence=[e.raw for e in events[-5:]],
        )]


class CompromiseAfterBruteForce(Rule):
    """Successful SSH login from an IP that was recently brute-forcing (T1078).

    Only a real burst counts (the same threshold as the brute-force rule), so
    an admin who mistypes their password a few times over an hour is ignored.
    """

    rule_id = "ssh_compromise"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.burst = SlidingWindow(cfg.ssh_bruteforce_window)
        self.attackers: dict[str, tuple[datetime, list[Event]]] = {}  # ip -> (last burst time, failures)

    def process(self, ev):
        if ev.source != "ssh" or not ev.src_ip:
            return []
        if ev.kind == "ssh_failed":
            q = self.burst.add(ev.src_ip, ev.ts, ev)
            prev = self.attackers.get(ev.src_ip)
            if prev and (ev.ts - prev[0]).total_seconds() <= self.cfg.compromise_lookback:
                self.attackers[ev.src_ip] = (ev.ts, (prev[1] + [ev])[-20:])
            elif len(q) >= self.cfg.ssh_bruteforce_threshold:
                self.attackers[ev.src_ip] = (ev.ts, [e for _, e in q])
            return []
        if ev.kind != "ssh_accepted":
            return []
        flagged = self.attackers.pop(ev.src_ip, None)
        if not flagged or (ev.ts - flagged[0]).total_seconds() > self.cfg.compromise_lookback:
            return []
        failures = flagged[1]
        return [Alert(
            rule_id=self.rule_id,
            title="Likely account compromise via SSH",
            severity="critical",
            description=(
                f"User '{ev.user}' logged in from {ev.src_ip} right after {len(failures)} failed attempts "
                f"from the same IP. Treat as compromised: lock the account and investigate."
            ),
            event_ts=ev.ts, src_ip=ev.src_ip, host=ev.host, user=ev.user, count=len(failures) + 1,
            mitre="T1078", evidence=[e.raw for e in failures[-4:]] + [ev.raw],
        )]


class PortScan(Rule):
    """One IP probing many different ports, seen as firewall blocks (T1046)."""

    rule_id = "port_scan"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.window = SlidingWindow(cfg.portscan_window)

    def process(self, ev):
        if ev.kind != "fw_block" or not ev.src_ip or ev.fields.get("dst_port") is None:
            return []
        q = self.window.add(ev.src_ip, ev.ts, ev)
        ports = {e.fields["dst_port"] for _, e in q}
        if len(ports) < self.cfg.portscan_ports:
            return []
        events = [e for _, e in q]
        self.window.clear(ev.src_ip)
        sample = ", ".join(str(p) for p in sorted(ports)[:10])
        return [Alert(
            rule_id=self.rule_id,
            title="Port scan detected",
            severity="medium",
            description=f"{ev.src_ip} probed {len(ports)} distinct ports in under "
                        f"{self.cfg.portscan_window}s (e.g. {sample}...)",
            event_ts=ev.ts, src_ip=ev.src_ip, host=ev.host, count=len(ports),
            mitre="T1046", evidence=[e.raw for e in events[-5:]],
        )]


# Signatures for common web attack payloads (checked against the URL-decoded path).
WEB_SIGNATURES: list[tuple[str, str, re.Pattern]] = [
    ("sqli", "SQL injection attempt", re.compile(
        r"(\bunion\b.{0,20}\bselect\b|'\s*or\s*'?\d+'?\s*=\s*'?\d+|'\s*or\s+'[^']*'\s*=\s*'|"
        r"\bor\s+1\s*=\s*1\b|sleep\(\s*\d+\s*\)|benchmark\(|information_schema|"
        r";\s*drop\s+table|'--|\bwaitfor\s+delay\b)", re.I)),
    ("xss", "Cross-site scripting attempt", re.compile(
        r"(<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*svg[^>]*on\w+\s*=|alert\s*\(|document\.cookie)", re.I)),
    ("traversal", "Path traversal attempt", re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|c:\\windows|boot\.ini|/proc/self/environ)", re.I)),
    ("cmdi", "Command injection attempt", re.compile(
        r"(;\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b|\|\s*(cat|id|whoami|nc|bash|sh)\b|"
        r"`[^`]+`|\$\([^)]+\))", re.I)),
    ("sensitive", "Sensitive file probe", re.compile(
        r"(/\.env\b|/\.git/|/wp-config\.php|/\.aws/credentials|/server-status|/phpmyadmin)", re.I)),
]
SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|hydra|acunetix)", re.I)
WEB_MITRE = {"sqli": "T1190", "xss": "T1190", "traversal": "T1083", "cmdi": "T1059", "sensitive": "T1552.001"}
WEB_SEVERITY = {"sqli": "high", "xss": "medium", "traversal": "high", "cmdi": "critical", "sensitive": "medium"}


class WebAttack(Rule):
    """Known attack payloads in HTTP requests (T1190)."""

    rule_id = "web_attack"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.last_fired: dict[tuple, datetime] = {}
        self.hits = SlidingWindow(cfg.cooldown)

    def process(self, ev):
        if ev.kind != "http_request" or not ev.src_ip:
            return []
        target = ev.fields.get("decoded_path", "")
        alerts = []
        for cat, title, pattern in WEB_SIGNATURES:
            if not pattern.search(target):
                continue
            key = (ev.src_ip, cat)
            q = self.hits.add(f"{ev.src_ip}|{cat}", ev.ts, ev)
            last = self.last_fired.get(key)
            if last and (ev.ts - last).total_seconds() < self.cfg.cooldown:
                continue  # already alerted on this IP + attack type recently
            self.last_fired[key] = ev.ts
            ua = ev.fields.get("user_agent", "")
            tool = SCANNER_UA.search(ua)
            status = ev.fields.get("status")
            succeeded = isinstance(status, int) and 200 <= status < 300
            alerts.append(Alert(
                rule_id=f"{self.rule_id}.{cat}",
                title=title,
                severity=WEB_SEVERITY[cat],
                description=(
                    f"{ev.fields.get('method')} {ev.fields.get('path')[:120]} from {ev.src_ip} "
                    f"(HTTP {status}{', server returned success - check the app' if succeeded else ''})"
                    + (f". Automated tool detected: {tool.group(1)}" if tool else "")
                ),
                event_ts=ev.ts, src_ip=ev.src_ip, host=ev.host, count=len(q),
                mitre=WEB_MITRE[cat], evidence=[e.raw for _, e in list(q)[-5:]],
            ))
        return alerts


class WebEnumeration(Rule):
    """Directory brute-forcing: a burst of 404/403 responses from one IP (T1595.003)."""

    rule_id = "web_enumeration"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.window = SlidingWindow(cfg.web_enum_window)

    def process(self, ev):
        if ev.kind != "http_request" or not ev.src_ip:
            return []
        status = ev.fields.get("status", 0)
        if not (400 <= status < 500):
            return []
        q = self.window.add(ev.src_ip, ev.ts, ev)
        if len(q) < self.cfg.web_enum_threshold:
            return []
        events = [e for _, e in q]
        self.window.clear(ev.src_ip)
        tool = SCANNER_UA.search(ev.fields.get("user_agent", ""))
        return [Alert(
            rule_id=self.rule_id,
            title="Web directory enumeration",
            severity="medium",
            description=f"{len(events)} client-error responses (404/403) to {ev.src_ip} in under "
                        f"{self.cfg.web_enum_window}s - likely a content discovery scan"
                        + (f" using {tool.group(1)}" if tool else ""),
            event_ts=ev.ts, src_ip=ev.src_ip, host=ev.host, count=len(events),
            mitre="T1595.003", evidence=[e.raw for e in events[-5:]],
        )]


SHELL_CMDS = re.compile(
    r"(/bin/(ba|z|da)?sh\b|\bsu\b|/usr/bin/python\d*\s*-c|\bchmod\s+[0-7]*s|visudo|/etc/sudoers|/etc/shadow|useradd|passwd)"
)


class SudoAbuse(Rule):
    """Privilege escalation signals in sudo logs (T1548.003)."""

    rule_id = "sudo_abuse"

    def process(self, ev):
        if ev.source != "sudo":
            return []
        cmd = ev.fields.get("command", "")
        if ev.kind == "sudo_denied":
            return [Alert(
                rule_id=f"{self.rule_id}.denied", title="Unauthorized sudo attempt", severity="medium",
                description=f"User '{ev.user}' tried to run '{cmd[:100]}' as {ev.fields.get('target_user')} "
                            f"but is not allowed to use sudo",
                event_ts=ev.ts, host=ev.host, user=ev.user, mitre="T1548.003", evidence=[ev.raw],
            )]
        if ev.user in self.cfg.service_accounts:
            return [Alert(
                rule_id=f"{self.rule_id}.service_account", title="Service account used sudo", severity="critical",
                description=f"Service account '{ev.user}' ran '{cmd[:100]}' as root. Web/database accounts "
                            f"should never do this - possible web shell or exploited service.",
                event_ts=ev.ts, host=ev.host, user=ev.user, mitre="T1548.003", evidence=[ev.raw],
            )]
        if SHELL_CMDS.search(cmd):
            return [Alert(
                rule_id=f"{self.rule_id}.root_shell", title="Root shell or sensitive file access via sudo", severity="low",
                description=f"User '{ev.user}' ran '{cmd[:100]}' as root. Often legitimate admin work - "
                            f"verify it was expected.",
                event_ts=ev.ts, host=ev.host, user=ev.user, mitre="T1548.003", evidence=[ev.raw],
            )]
        return []


ALL_RULES = [SSHBruteForce, CompromiseAfterBruteForce, PortScan, WebAttack, WebEnumeration, SudoAbuse]

# Human-readable catalogue (used by the dashboard and README).
RULE_CATALOG = [
    {"id": "ssh_bruteforce", "name": "SSH brute force / password spraying", "mitre": "T1110", "severity": "high"},
    {"id": "ssh_compromise", "name": "Login success after brute force", "mitre": "T1078", "severity": "critical"},
    {"id": "port_scan", "name": "Port scan (firewall blocks)", "mitre": "T1046", "severity": "medium"},
    {"id": "web_attack", "name": "Web payloads: SQLi, XSS, traversal, command injection", "mitre": "T1190", "severity": "high"},
    {"id": "web_enumeration", "name": "Directory enumeration (404 burst)", "mitre": "T1595.003", "severity": "medium"},
    {"id": "sudo_abuse", "name": "sudo abuse / privilege escalation", "mitre": "T1548.003", "severity": "medium"},
]
