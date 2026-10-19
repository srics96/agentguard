"""Incident log: every violation the guard acts on is recorded here.

The log is append-only and the guard never trusts the agent's own account of
what it did; the record is written by the guard, from inside the enforcement
path.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Incident:
    kind: str                 # read_redacted | action_denied | leak_blocked | page_denied
    detail: str
    url: str = ""
    data_kinds: list[str] = field(default_factory=list)
    action: str = ""
    killed: bool = False
    ts: float = field(default_factory=time.time)


class IncidentLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.entries: list[Incident] = []

    def record(self, inc: Incident) -> Incident:
        self.entries.append(inc)
        if self.path:
            with self.path.open("a") as fh:
                fh.write(json.dumps(asdict(inc)) + "\n")
        return inc

    def __len__(self) -> int:
        return len(self.entries)
