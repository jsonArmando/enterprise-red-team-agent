"""Dynamic catalog of executables available in the Kali runtime used by the agent."""
from __future__ import annotations
import json, os
from pathlib import Path
from typing import Any

class KaliToolCatalog:
    def __init__(self, target: str, workdir: Path, mcp_call=None):
        self.target = target
        self.workdir = workdir
        self.mcp_call = mcp_call
        self.path = workdir / "kali_tool_catalog.json"

    def discover(self) -> list[dict[str, Any]]:
        entries = {}
        for directory in os.getenv("PATH", "").split(os.pathsep):
            if not directory:
                continue
            try:
                for p in Path(directory).iterdir():
                    try:
                        if p.is_file() and os.access(p, os.X_OK) and not p.name.startswith("."):
                            entries[p.name] = str(p)
                    except OSError:
                        continue
            except OSError:
                continue
        catalog = [{"name": name, "path": entries[name]} for name in sorted(entries)]
        self._write(catalog, "kali_runtime_path")
        return catalog

    def mcp_catalog(self) -> list[dict[str, Any]]:
        if not self.mcp_call:
            return []
        try:
            raw = self.mcp_call(os.getenv("MCP_LIST_TOOLS", "list_kali_tools"), {"mode": "authorized_lab"})
            data = json.loads(raw)
            items = data.get("tools", data) if isinstance(data, dict) else data
            if isinstance(items, list):
                return items
        except Exception:
            pass
        return []

    def discover_all(self) -> list[dict[str, Any]]:
        local = self.discover()
        remote = self.mcp_catalog()
        by_name = {x.get("name"): x for x in local if x.get("name")}
        for item in remote:
            name = item.get("name") if isinstance(item, dict) else str(item)
            if name:
                by_name[name] = {**by_name.get(name, {"name": name}), **(item if isinstance(item, dict) else {})}
        merged = sorted(by_name.values(), key=lambda x: x.get("name", ""))
        self._write(merged, "local+MCP")
        return merged

    def _write(self, tools: list[dict[str, Any]], source: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({
            "target": self.target,
            "source": source,
            "count": len(tools),
            "tools": tools,
        }, indent=2, ensure_ascii=False), encoding="utf-8")
