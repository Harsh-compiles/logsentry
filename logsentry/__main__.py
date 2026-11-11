"""Command-line interface.

    python -m logsentry demo                      # everything on one machine, simulated attacks
    python -m logsentry run --logs /var/log/auth.log /var/log/nginx/access.log
    python -m logsentry replay samples/*.log      # analyse existing log files and exit
    python -m logsentry simulate --out ./lab-logs # only generate attack logs
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

from .collector import Collector
from .engine import Engine
from .notifier import Notifier
from .rules import RULE_CATALOG, SEVERITY_ORDER
from .simulate import write_stream
from .store import Store


def env_list(name: str) -> list[str]:
    return [p for p in os.environ.get(name, "").split(",") if p]


def build_engine(args) -> tuple[Engine, Store]:
    store = Store(args.db)
    notifier = Notifier(webhook_url=args.webhook, min_severity=args.alert_level, console=not args.quiet)
    return Engine(store=store, notifier=notifier), store


def serve(engine: Engine, store: Store, host: str, port: int, mode: str) -> None:
    from .api import create_app  # imported lazily so `replay` works without Flask

    app = create_app(store, engine, mode=mode)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    print(f"\n  LogSentry dashboard -> http://{'localhost' if host == '0.0.0.0' else host}:{port}\n", flush=True)
    app.run(host=host, port=port, threaded=True)


def export_snapshot(store: Store, engine: Engine, path: str) -> None:
    data = {
        "mode": "demo",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "lines_seen": engine.lines_seen,
        "stats": store.stats(minutes=30),
        "alerts": store.alerts(limit=150),
        "rules": RULE_CATALOG,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=1)
    print(f"snapshot written to {path} ({len(data['alerts'])} alerts, {data['stats']['total_events']} events)")


def cmd_run(args) -> None:
    paths = args.logs or env_list("LOGSENTRY_LOGS")
    if not paths:
        sys.exit("no log files given: use --logs or set LOGSENTRY_LOGS")
    engine, store = build_engine(args)
    Collector(engine, paths, from_start=args.from_start).start()
    serve(engine, store, args.host, args.port, mode="live")


def cmd_demo(args) -> None:
    log_dir = tempfile.mkdtemp(prefix="logsentry-demo-")
    if args.db == default_db():
        args.db = os.path.join(log_dir, "demo.db")
    engine, store = build_engine(args)
    threading.Thread(target=write_stream, args=(log_dir, args.attack_every, args.duration), daemon=True).start()
    collector = Collector(engine, [os.path.join(log_dir, "remote.log")], from_start=True, interval=0.1)
    collector.start()
    print(f"simulated logs: {log_dir}", flush=True)
    if args.export:
        time.sleep((args.duration or 600) + 2)
        export_snapshot(store, engine, args.export)
        return
    serve(engine, store, args.host, args.port, mode="demo")


def cmd_replay(args) -> None:
    args.quiet = True
    engine, store = build_engine(args)
    alerts = []
    for path in args.files:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                alerts += engine.process_line(line)
    alerts.sort(key=lambda a: (-SEVERITY_ORDER[a.severity], a.event_ts))
    print(f"\nProcessed {engine.lines_seen} lines ({engine.events_seen} security events) -> {len(alerts)} alerts\n")
    for a in alerts:
        print(f"  [{a.severity.upper():8}] {a.event_ts:%Y-%m-%d %H:%M:%S}  {a.title:46} {a.src_ip or a.user or '-':16} {a.mitre}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump([a.to_dict() for a in alerts], f, indent=1)
        print(f"\nfull details written to {args.json}")


def cmd_simulate(args) -> None:
    print(f"writing simulated logs to {os.path.join(args.out, 'remote.log')} (Ctrl+C to stop)")
    write_stream(args.out, args.attack_every, args.duration)


def default_db() -> str:
    return os.environ.get("LOGSENTRY_DB", "logsentry.db")


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="logsentry", description="Lightweight security monitoring (mini SIEM)")
    p.add_argument("--db", default=default_db(), help="SQLite database path")
    p.add_argument("--webhook", default=os.environ.get("LOGSENTRY_WEBHOOK"), help="Discord or Slack webhook URL")
    p.add_argument("--alert-level", default=os.environ.get("LOGSENTRY_ALERT_LEVEL", "high"),
                   choices=list(SEVERITY_ORDER), help="minimum severity sent to the webhook")
    p.add_argument("--quiet", action="store_true", help="don't print alerts to the console")
    sub = p.add_subparsers(dest="cmd", required=True)

    def web_opts(sp):
        sp.add_argument("--host", default=os.environ.get("LOGSENTRY_HOST", "127.0.0.1"))
        sp.add_argument("--port", type=int, default=int(os.environ.get("LOGSENTRY_PORT", 8080)))

    r = sub.add_parser("run", help="watch real log files and serve the dashboard")
    r.add_argument("--logs", nargs="+", help="log files to follow (or LOGSENTRY_LOGS=a,b)")
    r.add_argument("--from-start", action="store_true", help="also process lines already in the files")
    web_opts(r)
    r.set_defaults(func=cmd_run)

    d = sub.add_parser("demo", help="simulated attacks + live dashboard, no servers needed")
    d.add_argument("--attack-every", type=float, default=10.0, help="average seconds between attacks")
    d.add_argument("--duration", type=float, help="stop simulating after N seconds")
    d.add_argument("--export", help="run for --duration seconds, then save a dashboard snapshot JSON and exit")
    web_opts(d)
    d.set_defaults(func=cmd_demo)

    rp = sub.add_parser("replay", help="analyse existing log files and print the alerts")
    rp.add_argument("files", nargs="+")
    rp.add_argument("--json", help="also write alerts to this JSON file")
    rp.set_defaults(func=cmd_replay, db=":memory:")

    s = sub.add_parser("simulate", help="only write simulated attack logs")
    s.add_argument("--out", default="./lab-logs")
    s.add_argument("--attack-every", type=float, default=10.0)
    s.add_argument("--duration", type=float)
    s.set_defaults(func=cmd_simulate)

    args = p.parse_args(argv)
    if args.cmd == "replay":
        args.db = ":memory:"
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    args.func(args)


if __name__ == "__main__":
    main()
