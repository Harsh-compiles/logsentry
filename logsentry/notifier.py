"""Alert delivery: console output and Discord / Slack webhooks.

Uses only the standard library so there is nothing extra to install.
Webhook failures are logged and never crash the detection pipeline.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.request

from .rules import SEVERITY_ORDER, Alert

log = logging.getLogger("logsentry.notify")

COLORS = {"critical": 0xE5484D, "high": 0xF76B15, "medium": 0xFFC53D, "low": 0x8B8D98}
ANSI = {"critical": "\033[1;91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[90m"}


class Notifier:
    def __init__(self, webhook_url: str | None = None, min_severity: str = "high", console: bool = True):
        self.webhook_url = webhook_url
        self.min_level = SEVERITY_ORDER.get(min_severity, 2)
        self.console = console

    def send(self, alert: Alert) -> None:
        if self.console:
            color = ANSI.get(alert.severity, "")
            print(f"{color}[{alert.severity.upper():8}]\033[0m {alert.title} | "
                  f"{alert.src_ip or alert.user or '-'} @ {alert.host} | {alert.description}", flush=True)
        if self.webhook_url and SEVERITY_ORDER[alert.severity] >= self.min_level:
            # Send in the background so a slow webhook never delays detection.
            threading.Thread(target=self._post, args=(alert,), daemon=True).start()

    def _payload(self, a: Alert) -> dict:
        if "hooks.slack.com" in (self.webhook_url or ""):
            return {"text": f"*[{a.severity.upper()}] {a.title}*\n{a.description}\n"
                            f"Host: `{a.host}`  Source: `{a.src_ip or '-'}`  MITRE: {a.mitre}"}
        return {  # Discord embed
            "username": "LogSentry",
            "embeds": [{
                "title": f"{a.severity.upper()}: {a.title}",
                "description": a.description[:1500],
                "color": COLORS.get(a.severity, 0),
                "fields": [
                    {"name": "Host", "value": a.host or "-", "inline": True},
                    {"name": "Source IP", "value": a.src_ip or "-", "inline": True},
                    {"name": "MITRE ATT&CK", "value": a.mitre or "-", "inline": True},
                    {"name": "Evidence", "value": "```" + "\n".join(a.evidence[-3:])[:900] + "```"},
                ],
                "timestamp": a.event_ts.isoformat(),
            }],
        }

    def _post(self, alert: Alert) -> None:
        try:
            req = urllib.request.Request(
                self.webhook_url, data=json.dumps(self._payload(alert)).encode(),
                headers={"Content-Type": "application/json", "User-Agent": "LogSentry/1.0"}, method="POST",
            )
            urllib.request.urlopen(req, timeout=5).close()
        except Exception as exc:  # noqa: BLE001 - never let alerting crash detection
            log.warning("webhook delivery failed: %s", exc)
