"""Evidence-driven privilege-escalation hypothesis engine for HTB/lab targets."""
from __future__ import annotations
import re
from typing import Any

PATTERNS = [
    ("sudo_misconfig", r"sudo|sudoers|NOPASSWD|!root", 0.88),
    ("suid_binary", r"\bSUID\b|setuid|-rws|4000", 0.84),
    ("linux_capability", r"cap_[a-z_]+|getcap", 0.82),
    ("cron_timer", r"cron|crontab|systemd timer|scheduled", 0.76),
    ("writable_service", r"writable.*service|service.*writable|init\.d", 0.74),
    ("writable_path", r"world.writable|writable path|777|666", 0.68),
    ("kernel_exposure", r"linux kernel|kernel version|CVE-\d{4}-\d+", 0.64),
    ("credential_material", r"password|passwd|shadow|credential|token|secret", 0.71),
    ("windows_privilege", r"SeImpersonatePrivilege|SeBackupPrivilege|SeDebugPrivilege|AlwaysInstallElevated", 0.91),
    ("windows_service", r"unquoted service path|service binary|weak service|registry run", 0.79),
    ("scheduled_task", r"schtasks|scheduled task", 0.72),
]

class PrivEscEngine:
    def build_hypotheses(self, evidence: str, session: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        text = evidence or ""
        lines = text.splitlines()
        result = []
        for category, pattern, confidence in PATTERNS:
            if not re.search(pattern, text, re.I):
                continue
            evidence_lines = [
                {"line": idx, "text": line[:2000]}
                for idx, line in enumerate(lines, 1)
                if re.search(pattern, line, re.I)
            ]
            result.append({
                "id": f"privesc:{category}",
                "category": category,
                "confidence": confidence,
                "status": "discovered",
                "evidence_lines": evidence_lines[:20],
                "preconditions": [],
                "attempts": [],
                "session": session or {},
            })
        return sorted(result, key=lambda x: x["confidence"], reverse=True)

    def merge(self, existing: list[dict[str, Any]], fresh: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged = {x["id"]: x for x in existing}
        for item in fresh:
            if item["id"] not in merged:
                merged[item["id"]] = item
            else:
                old = merged[item["id"]]
                old["confidence"] = max(old.get("confidence", 0), item.get("confidence", 0))
                old["evidence_lines"] = old.get("evidence_lines", []) + item.get("evidence_lines", [])
        return sorted(merged.values(), key=lambda x: x.get("confidence", 0), reverse=True)
