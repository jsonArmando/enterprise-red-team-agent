"""Structured session lifecycle for authorized HTB/lab access."""
from __future__ import annotations
import json, os
from dataclasses import dataclass
from typing import Any

@dataclass
class SessionState:
    session_id: str | None = None
    session_type: str | None = None
    transport: str | None = None
    user: str | None = None
    host: str | None = None
    connected: bool = False
    privilege: str | None = None
    evidence: str = ""

class SessionManager:
    def __init__(self, target: str, mcp_call):
        self.target = target
        self.mcp_call = mcp_call

    @staticmethod
    def _parse(output: str) -> dict[str, Any]:
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        low = output.lower()
        return {
            "connected": any(x in low for x in ("session_established", "connected", "foothold", "uid=")),
            "session_id": None,
            "session_type": "unknown",
            "evidence": output[:12000],
        }

    def establish(self, access: dict[str, Any]) -> SessionState:
        raw = self.mcp_call(os.getenv("MCP_SESSION_TOOL", "session_manager"), {
            "operation": "establish",
            "target": self.target,
            "access": access,
            "mode": "authorized_lab",
        })
        d = self._parse(raw)
        return SessionState(
            session_id=d.get("session_id") or d.get("id"),
            session_type=d.get("session_type") or d.get("type"),
            transport=d.get("transport"),
            user=d.get("user"),
            host=d.get("host") or self.target,
            connected=bool(d.get("connected") or d.get("session_established") or d.get("access_obtained")),
            privilege=d.get("privilege"),
            evidence=raw[:12000],
        )

    def inspect(self, session: dict[str, Any] | None = None) -> str:
        return self.mcp_call(os.getenv("MCP_SESSION_TOOL", "session_manager"), {
            "operation": "inspect",
            "target": self.target,
            "session": session or {},
            "mode": "authorized_lab",
        })

    def close(self, session_id: str | None) -> str:
        return self.mcp_call(os.getenv("MCP_SESSION_TOOL", "session_manager"), {
            "operation": "close",
            "target": self.target,
            "session_id": session_id,
            "mode": "authorized_lab",
        })
