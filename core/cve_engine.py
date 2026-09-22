"""Normalize scanner vulnerability intelligence into autonomous candidates."""
from __future__ import annotations
import re
from dataclasses import dataclass, asdict
from typing import Any

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

@dataclass
class Vulnerability:
    id: str
    cve: str
    target: str
    service: str
    version: str
    port: int | None
    confidence: float
    source: str
    status: str = "candidate"
    evidence: list[str] | None = None

def extract_cves(text: str) -> list[str]:
    return sorted({m.upper() for m in CVE_RE.findall(text or "")})

def build_inventory(target: str, scan_output: str, source: str = "scanner") -> list[dict[str, Any]]:
    inventory=[]
    for cve in extract_cves(scan_output):
        idx=scan_output.upper().find(cve)
        context=scan_output[max(0,idx-500):idx+800]
        port=None
        match=re.search(r"\b(\d{1,5})/tcp\b", context)
        if match:
            port=int(match.group(1))
        inventory.append(asdict(Vulnerability(
            id=f"{target}:{cve}", cve=cve, target=target,
            service="unknown", version="unknown", port=port,
            confidence=0.70, source=source, evidence=[context.strip()]
        )))
    return inventory

def merge_inventory(existing: list[dict], new_items: list[dict]) -> list[dict]:
    merged={x.get("id"):x for x in existing if x.get("id")}
    for item in new_items:
        old=merged.get(item["id"])
        if old:
            old["confidence"]=max(old.get("confidence",0),item.get("confidence",0))
            old["evidence"]=list(dict.fromkeys((old.get("evidence") or [])+(item.get("evidence") or [])))
        else:
            merged[item["id"]]=item
    return list(merged.values())
