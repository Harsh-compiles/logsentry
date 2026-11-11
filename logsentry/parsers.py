"""Log line parsers.

Turns raw log lines into structured ``Event`` objects. A single entry point,
``parse_line``, auto-detects the format so one collector can read a mixed
stream (for example, everything forwarded to a central rsyslog server).

Supported formats:
  * OpenSSH (sshd) authentication logs
  * sudo logs
  * UFW / iptables firewall logs (kernel)
  * nginx / Apache "combined" access logs (plain or wrapped in a syslog header)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote_plus


@dataclass
class Event:
    ts: datetime                 # when the event happened (UTC)
    host: str                    # machine that produced the log
    source: str                  # ssh | sudo | firewall | web
    kind: str                    # e.g. ssh_failed, fw_block, http_request
    src_ip: str | None = None
    user: str | None = None
    fields: dict = field(default_factory=dict)
    raw: str = ""


# --- syslog header -----------------------------------------------------------
# "Nov 11 10:15:02 web-01 sshd[1234]: message"  (RFC 3164 / traditional format)
# "2026-11-11T10:15:02.123456+00:00 web-01 sshd[1234]: message" (RFC 5424-ish)
SYSLOG_RE = re.compile(
    r"^(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
    r"|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w\-./]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)

# --- sshd ----------------------------------------------------------------------
SSH_FAILED_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
)
SSH_INVALID_RE = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)")
# On key-only servers (the secure default) attackers never get to "Failed password":
# each attempt ends with one of these instead, so they count as failed logins too.
SSH_PREAUTH_RE = re.compile(
    r"(?:Connection closed|Disconnected) by (?:(?P<invalid>invalid) |authenticating )?user (?P<user>\S*) "
    r"(?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+) \[preauth\]"
)

# --- sudo ----------------------------------------------------------------------
SUDO_CMD_RE = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<denied>user NOT in sudoers|command not allowed) ; )?"
    r"TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.+)$"
)

# --- firewall (UFW / iptables LOG target) -------------------------------------
FW_RE = re.compile(r"\[UFW (?P<action>BLOCK|ALLOW|AUDIT)\]|IPTABLES-(?P<ipt>DROP|ACCEPT)")
KV_RE = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT)=(\S+)")

# --- web access log (combined format) ----------------------------------------
WEB_RE = re.compile(
    r'^(?P<ip>[\d.:a-fA-F]+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[\d.]+)?" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)


def _parse_syslog_ts(value: str, now: datetime | None = None) -> datetime:
    if value[:4].isdigit():  # ISO timestamp
        # Python 3.10's fromisoformat only accepts 3 or 6 fractional digits,
        # so pad/trim the fraction to 6 (rsyslog and others vary).
        value = re.sub(r"\.(\d+)", lambda m: "." + m[1][:6].ljust(6, "0"), value.replace("Z", "+00:00"), count=1)
        ts = datetime.fromisoformat(value)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)
    # Traditional syslog has no year, so infer it: if the date would be more
    # than a day in the future, the line must be from last year.
    now = now or datetime.now(timezone.utc)
    ts = datetime.strptime(f"{now.year} {value}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    if ts - now > timedelta(days=1):
        ts = ts.replace(year=now.year - 1)
    return ts


def _parse_web(line: str, host: str, fallback_ts: datetime | None = None) -> Event | None:
    m = WEB_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        ts = fallback_ts or datetime.now(timezone.utc)
    path = m["path"]
    return Event(
        ts=ts,
        host=host,
        source="web",
        kind="http_request",
        src_ip=m["ip"],
        user=None if m["user"] == "-" else m["user"],
        fields={
            "method": m["method"],
            "path": path,
            "decoded_path": unquote_plus(unquote_plus(path)),  # attackers double-encode
            "status": int(m["status"]),
            "user_agent": m["ua"] or "",
        },
        raw=line,
    )


def parse_line(line: str, default_host: str = "local", now: datetime | None = None) -> Event | None:
    """Parse one log line. Returns ``None`` for lines we don't care about."""
    line = line.rstrip("\r\n")
    if not line.strip():
        return None

    # Plain web access log (no syslog header).
    if not SYSLOG_RE.match(line):
        return _parse_web(line, default_host)

    m = SYSLOG_RE.match(line)
    ts = _parse_syslog_ts(m["ts"], now)
    host, prog, msg = m["host"], m["prog"], m["msg"]

    if prog == "sshd":
        if fm := SSH_FAILED_RE.search(msg):
            return Event(ts, host, "ssh", "ssh_failed", fm["ip"], fm["user"],
                         {"invalid_user": bool(fm["invalid"]), "port": int(fm["port"])}, line)
        if am := SSH_ACCEPTED_RE.search(msg):
            return Event(ts, host, "ssh", "ssh_accepted", am["ip"], am["user"],
                         {"method": am["method"], "port": int(am["port"])}, line)
        if pm := SSH_PREAUTH_RE.search(msg):
            return Event(ts, host, "ssh", "ssh_failed", pm["ip"], pm["user"] or "",
                         {"invalid_user": bool(pm["invalid"]), "port": int(pm["port"]), "preauth": True}, line)
        if im := SSH_INVALID_RE.search(msg):
            return Event(ts, host, "ssh", "ssh_invalid_user", im["ip"], im["user"] or "", {}, line)
        return None

    if prog == "sudo":
        if sm := SUDO_CMD_RE.match(msg):
            kind = "sudo_denied" if sm["denied"] else "sudo_cmd"
            return Event(ts, host, "sudo", kind, None, sm["user"],
                         {"target_user": sm["target"], "command": sm["cmd"].strip(), "pwd": sm["pwd"]}, line)
        return None

    if prog == "kernel":
        if fw := FW_RE.search(msg):
            kv = dict(KV_RE.findall(msg))
            action = (fw["action"] or fw["ipt"] or "").upper()
            kind = "fw_block" if action in ("BLOCK", "DROP") else "fw_allow"
            return Event(ts, host, "firewall", kind, kv.get("SRC"), None, {
                "dst_ip": kv.get("DST"),
                "proto": kv.get("PROTO"),
                "dst_port": int(kv["DPT"]) if kv.get("DPT", "").isdigit() else None,
            }, line)
        return None

    if prog in ("nginx", "apache2", "httpd"):
        ev = _parse_web(msg, host, fallback_ts=ts)
        if ev:
            ev.ts = ts  # the syslog header is more precise than nginx's 1-second timestamps
            ev.raw = line
        return ev

    return None
