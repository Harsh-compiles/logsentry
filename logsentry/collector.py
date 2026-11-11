"""Follows log files like ``tail -F`` and feeds new lines to the engine.

Handles log rotation (file replaced or truncated) and files that don't exist
yet, so it can start before the services it watches.
"""

from __future__ import annotations

import logging
import os
import threading
import time

log = logging.getLogger("logsentry.collector")


class FileTailer:
    def __init__(self, path: str, from_start: bool = False):
        self.path = path
        self.from_start = from_start
        self.fh = None
        self.inode = None
        self.buffer = ""

    def _open(self) -> bool:
        try:
            self.fh = open(self.path, encoding="utf-8", errors="replace")  # noqa: SIM115
        except FileNotFoundError:
            return False
        st = os.fstat(self.fh.fileno())
        self.inode = st.st_ino
        if not self.from_start:
            self.fh.seek(0, os.SEEK_END)
        self.from_start = True  # after a rotation, always read the new file from the start
        log.info("watching %s", self.path)
        return True

    def read_lines(self) -> list[str]:
        if self.fh is None and not self._open():
            return []
        chunk = self.fh.read()
        if not chunk:
            self._check_rotation()
            return []
        self.buffer += chunk
        *lines, self.buffer = self.buffer.split("\n")  # keep a partial last line for next time
        return lines

    def _check_rotation(self) -> None:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return
        if st.st_ino != self.inode or st.st_size < self.fh.tell():
            log.info("%s was rotated, reopening", self.path)
            self.fh.close()
            self.fh = None
            self.buffer = ""


class Collector(threading.Thread):
    def __init__(self, engine, paths: list[str], from_start: bool = False, interval: float = 0.25):
        super().__init__(daemon=True, name="collector")
        self.engine = engine
        self.tailers = [FileTailer(p, from_start) for p in paths]
        self.interval = interval
        self.stop_event = threading.Event()

    def run(self) -> None:
        while not self.stop_event.is_set():
            busy = False
            for t in self.tailers:
                for line in t.read_lines():
                    busy = True
                    try:
                        self.engine.process_line(line)
                    except Exception:  # noqa: BLE001 - one bad line must not stop collection
                        log.exception("failed to process line: %r", line[:200])
            if not busy:
                time.sleep(self.interval)

    def stop(self) -> None:
        self.stop_event.set()
