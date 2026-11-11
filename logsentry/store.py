"""SQLite storage for events and alerts, plus the stats the dashboard shows."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from .parsers import Event
from .rules import Alert

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    host    TEXT,
    source  TEXT,
    kind    TEXT,
    src_ip  TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    description TEXT,
    event_ts    TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    latency_ms  REAL,
    src_ip      TEXT,
    host        TEXT,
    user        TEXT,
    count       INTEGER,
    mitre       TEXT,
    evidence    TEXT,
    status      TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_alerts_detected ON alerts(detected_at);
"""


class Store:
    def __init__(self, path: str = "logsentry.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.executescript(SCHEMA)
            self.conn.execute("PRAGMA journal_mode=WAL")

    # ---- writes ------------------------------------------------------------
    def add_event(self, ev: Event) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO events (ts, host, source, kind, src_ip) VALUES (?,?,?,?,?)",
                (ev.ts.isoformat(), ev.host, ev.source, ev.kind, ev.src_ip),
            )
            self.conn.commit()

    def upsert_alert(self, a: Alert) -> None:
        d = a.to_dict()
        with self.lock:
            self.conn.execute(
                """INSERT INTO alerts (id, rule_id, title, severity, description, event_ts, detected_at,
                                       latency_ms, src_ip, host, user, count, mitre, evidence)
                   VALUES (:id,:rule_id,:title,:severity,:description,:event_ts,:detected_at,
                           :latency_ms,:src_ip,:host,:user,:count,:mitre,:evidence)
                   ON CONFLICT(id) DO UPDATE SET count=excluded.count, description=excluded.description,
                       evidence=excluded.evidence, severity=excluded.severity, title=excluded.title""",
                {**d, "evidence": json.dumps(d["evidence"])},
            )
            self.conn.commit()

    def set_status(self, alert_id: str, status: str) -> bool:
        with self.lock:
            cur = self.conn.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
            self.conn.commit()
            return cur.rowcount > 0

    def prune(self, keep_hours: int = 48) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=keep_hours)).isoformat()
        with self.lock:
            self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self.conn.commit()

    # ---- reads -------------------------------------------------------------
    def alerts(self, limit: int = 200, severity: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM alerts", []
        if severity:
            sql += " WHERE severity = ?"
            args.append(severity)
        sql += " ORDER BY detected_at DESC LIMIT ?"
        args.append(limit)
        with self.lock:
            rows = self.conn.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["evidence"] = json.loads(d["evidence"] or "[]")
            out.append(d)
        return out

    def stats(self, minutes: int = 60) -> dict:
        now = datetime.now(timezone.utc)
        since = (now - timedelta(minutes=minutes)).isoformat()
        q = self.conn.execute
        with self.lock:
            total_events = q("SELECT COUNT(*) FROM events").fetchone()[0]
            by_source = dict(q("SELECT source, COUNT(*) FROM events GROUP BY source").fetchall())
            sev = dict(q("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall())
            by_rule = [dict(r) for r in q(
                "SELECT title, COUNT(*) AS n FROM alerts GROUP BY title ORDER BY n DESC LIMIT 8").fetchall()]
            top_ips = [dict(r) for r in q(
                """SELECT src_ip AS ip, COUNT(*) AS alerts, SUM(count) AS events,
                          MAX(CASE severity WHEN 'critical' THEN 3 WHEN 'high' THEN 2
                                            WHEN 'medium' THEN 1 ELSE 0 END) AS worst
                   FROM alerts WHERE src_ip IS NOT NULL GROUP BY src_ip
                   ORDER BY worst DESC, alerts DESC LIMIT 8""").fetchall()]
            lat = q("SELECT AVG(latency_ms), MAX(latency_ms) FROM alerts").fetchone()
            attackers = q("SELECT COUNT(DISTINCT src_ip) FROM alerts WHERE src_ip IS NOT NULL").fetchone()[0]
            open_alerts = q("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
            hosts = [r[0] for r in q("SELECT DISTINCT host FROM events WHERE host IS NOT NULL").fetchall()]
            ev_rows = q("SELECT substr(ts,1,16) AS m, COUNT(*) FROM events WHERE ts >= ? GROUP BY m",
                        (since,)).fetchall()
            al_rows = q("SELECT substr(event_ts,1,16) AS m, COUNT(*) FROM alerts WHERE event_ts >= ? GROUP BY m",
                        (since,)).fetchall()

        # Fill a continuous per-minute timeline (empty minutes = 0).
        ev_map, al_map = dict(ev_rows), dict(al_rows)
        timeline = []
        start = (now - timedelta(minutes=minutes - 1)).replace(second=0, microsecond=0)
        for i in range(minutes):
            t = start + timedelta(minutes=i)
            key = t.isoformat()[:16]
            timeline.append({"t": key, "events": ev_map.get(key, 0), "alerts": al_map.get(key, 0)})

        return {
            "generated_at": now.isoformat(),
            "total_events": total_events,
            "events_by_source": by_source,
            "alerts_by_severity": {s: sev.get(s, 0) for s in ("critical", "high", "medium", "low")},
            "total_alerts": sum(sev.values()),
            "open_alerts": open_alerts,
            "alerts_by_rule": by_rule,
            "top_attackers": top_ips,
            "unique_attackers": attackers,
            "avg_latency_ms": round(lat[0], 1) if lat[0] is not None else None,
            "max_latency_ms": round(lat[1], 1) if lat[1] is not None else None,
            "hosts": hosts,
            "timeline": timeline,
        }
