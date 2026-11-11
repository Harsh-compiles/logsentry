"""Detection engine: runs every event through every rule.

It also de-duplicates alerts. If the same rule fires again for the same
attacker while an alert is still "fresh" (within the cooldown), the existing
alert is updated (count and evidence) instead of flooding the feed with copies.
"""

from __future__ import annotations

from datetime import datetime

from .notifier import Notifier
from .parsers import Event, parse_line
from .rules import ALL_RULES, SEVERITY_ORDER, Alert, RuleConfig
from .store import Store


class Engine:
    def __init__(self, store: Store | None = None, notifier: Notifier | None = None,
                 config: RuleConfig | None = None):
        self.cfg = config or RuleConfig()
        self.rules = [r(self.cfg) for r in ALL_RULES]
        self.store = store
        self.notifier = notifier
        self.active: dict[tuple, tuple[Alert, datetime]] = {}  # dedup key -> (alert, last seen)
        self.events_seen = 0
        self.lines_seen = 0

    def process_line(self, line: str, default_host: str = "local") -> list[Alert]:
        self.lines_seen += 1
        ev = parse_line(line, default_host)
        return self.process_event(ev) if ev else []

    def process_event(self, ev: Event) -> list[Alert]:
        self.events_seen += 1
        if self.store:
            self.store.add_event(ev)
        new_alerts = []
        for rule in self.rules:
            for alert in rule.process(ev):
                if self._merge_duplicate(alert):
                    continue
                new_alerts.append(alert)
                if self.store:
                    self.store.upsert_alert(alert)
                if self.notifier:
                    self.notifier.send(alert)
        return new_alerts

    def _merge_duplicate(self, alert: Alert) -> bool:
        """Fold a repeat alert into the open one. Returns True if it was merged."""
        key = (alert.rule_id, alert.src_ip or alert.user, alert.host)
        existing = self.active.get(key)
        if existing:
            prev, last_seen = existing
            if (alert.event_ts - last_seen).total_seconds() < self.cfg.cooldown:
                prev.count += alert.count
                prev.evidence = (prev.evidence + alert.evidence)[-5:]
                if SEVERITY_ORDER[alert.severity] > SEVERITY_ORDER[prev.severity]:
                    prev.severity = alert.severity
                self.active[key] = (prev, alert.event_ts)
                if self.store:
                    self.store.upsert_alert(prev)
                return True
        self.active[key] = (alert, alert.event_ts)
        return False
