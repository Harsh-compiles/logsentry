"""REST API and dashboard web server (Flask)."""

from __future__ import annotations

import hmac
import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory

from . import __version__
from .rules import RULE_CATALOG
from .store import Store

DASHBOARD_DIR = Path(os.environ.get("LOGSENTRY_DASHBOARD_DIR", Path(__file__).resolve().parent.parent / "dashboard"))
VALID_STATUS = {"open", "acknowledged", "resolved", "false_positive"}


def create_app(store: Store, engine=None, mode: str = "live") -> Flask:
    app = Flask(__name__, static_folder=None)
    api_token = os.environ.get("LOGSENTRY_API_TOKEN")
    started = datetime.now(timezone.utc)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; script-src 'self'"
        )
        return resp

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", version=__version__, mode=mode,
                       uptime_s=int((datetime.now(timezone.utc) - started).total_seconds()))

    @app.get("/api/dashboard")
    def dashboard():
        limit = min(int(request.args.get("limit", 100)), 500)
        return jsonify(
            mode=mode,
            version=__version__,
            started_at=started.isoformat(),
            lines_seen=engine.lines_seen if engine else None,
            stats=store.stats(minutes=int(request.args.get("minutes", 30))),
            alerts=store.alerts(limit=limit),
            rules=RULE_CATALOG,
        )

    @app.get("/api/alerts")
    def alerts():
        severity = request.args.get("severity")
        limit = min(int(request.args.get("limit", 100)), 1000)
        return jsonify(store.alerts(limit=limit, severity=severity))

    @app.post("/api/alerts/<alert_id>/status")
    def set_status(alert_id):
        # Changing data requires a token when one is configured.
        if api_token:
            supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
            if not hmac.compare_digest(supplied, api_token):
                abort(401)
        status = (request.get_json(silent=True) or {}).get("status")
        if status not in VALID_STATUS:
            abort(400, description=f"status must be one of {sorted(VALID_STATUS)}")
        if not store.set_status(alert_id, status):
            abort(404)
        return jsonify(id=alert_id, status=status)

    @app.get("/")
    def index():
        return send_from_directory(DASHBOARD_DIR, "index.html")

    @app.get("/<path:filename>")
    def static_files(filename):
        if filename == "demo-data.json":
            abort(404)  # the live server always serves real data
        return send_from_directory(DASHBOARD_DIR, filename)

    return app
