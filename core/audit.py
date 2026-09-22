"""Append-only operational audit trail for the autonomous lab agent."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

class AuditTrail:
    def __init__(self, workdir: Path):
        self.dir = workdir / "audit"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.events = self.dir / "events.jsonl"

    def record(self, event_type: str, **data: Any) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **data,
        }
        with self.events.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
