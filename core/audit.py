"""Append-only operational audit trail for the autonomous lab agent.

Audit failures must never terminate the autonomous control loop.
"""
from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("AuditTrail")


class AuditTrail:
    def __init__(self, workdir: Path):
        self.dir = workdir / "audit"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.events = self.dir / "events.jsonl"
        legacy = self.dir / "event.jsonl"
        if legacy.exists() and not self.events.exists():
            legacy.replace(self.events)

    def record(self, *args: Any, **data: Any) -> None:
        """Persist one event without allowing metadata collisions to crash the agent.

        Compatible with both:
            record("execution", action="recon")
        and the legacy/collision-prone:
            record(event.get("event_type"), **event)
        """
        positional_type = str(args[0]) if args else None
        payload_type = data.pop("event_type", None)
        event_type = positional_type or payload_type or "event"

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **data,
        }
        if payload_type is not None and positional_type is not None and str(payload_type) != positional_type:
            event["payload_event_type"] = payload_type

        try:
            with self.events.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        except Exception:
            logger.exception("Audit write failed; autonomous execution will continue")
