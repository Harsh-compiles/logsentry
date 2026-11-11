"""Measure detection quality with the simulator.

    python scripts/evaluate.py

* Detection rate: every attack scenario is run many times with different
  random seeds (attacker IPs, timing, usernames, payloads all vary).
* False positives: hours of normal background traffic with no attacks.
* Throughput: how many log lines per second the engine processes.
"""

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logsentry.engine import Engine  # noqa: E402
from logsentry.simulate import ATTACKS, Simulator  # noqa: E402

RUNS = 200
BACKGROUND_HOURS = 24
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def main() -> None:
    print(f"Detection rate ({RUNS} randomized runs per attack)\n")
    print(f"  {'attack':18} {'detected':>9}")
    total_hit = 0
    for name in ATTACKS:
        hits = 0
        for seed in range(RUNS):
            engine = Engine()
            lines = Simulator(realtime=False, seed=seed, start=T0).run_scenario(name)
            if any(engine.process_line(line) for _, line in lines):
                hits += 1
        total_hit += hits
        print(f"  {name:18} {hits / RUNS:>8.1%}")
    print(f"  {'overall':18} {total_hit / (RUNS * len(ATTACKS)):>8.1%}\n")

    # False positives: hours of normal traffic, no attacks at all.
    engine = Engine()
    lines, fps = 0, []
    for _, line in Simulator(realtime=False, seed=99, start=T0).stream(duration=BACKGROUND_HOURS * 3600, scenarios=[]):
        lines += 1
        fps += engine.process_line(line)
    print(f"False positives on {BACKGROUND_HOURS}h of normal traffic ({lines:,} lines): {len(fps)}")
    for a in fps:
        print("   ", a.title, a.src_ip, a.description[:80])

    # Throughput
    sample = [line for _, line in Simulator(realtime=False, seed=5, start=T0, attack_every=5).stream(duration=3600)]
    engine = Engine()
    t = time.perf_counter()
    for line in sample:
        engine.process_line(line)
    rate = len(sample) / (time.perf_counter() - t)
    print(f"Throughput: {rate:,.0f} lines/second (single core, in-memory)\n")


if __name__ == "__main__":
    main()
