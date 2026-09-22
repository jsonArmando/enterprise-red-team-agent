"""Line-by-line vulnerability analysis for an authorized HTB/lab target."""
from __future__ import annotations
import re
from typing import Any

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
PORT_RE = re.compile(r"\b(\d{1,5})/(tcp|udp)\b", re.I)
VERSION_HINTS = ("version", "product", "service", "open", "running", "vulnerable", "cpe:", "os:")

def analyze_lines(text: str) -> list[dict[str, Any]]:
    records=[]
    lines=(text or "").splitlines()
    for number,line in enumerate(lines,1):
        stripped=line.strip()
        if not stripped:
            continue
        cves=sorted({x.upper() for x in CVE_RE.findall(stripped)})
        ports=[int(m.group(1)) for m in PORT_RE.finditer(stripped)]
        lower=stripped.lower()
        interesting=bool(cves or ports or any(k in lower for k in VERSION_HINTS))
        if interesting:
            records.append({
                "line": number,
                "text": stripped[:2000],
                "cves": cves,
                "ports": ports,
                "interesting": True,
            })
    return records

def correlate_cves(target: str, text: str, source: str) -> list[dict[str, Any]]:
    records=analyze_lines(text)
    by_cve={}
    for rec in records:
        for cve in rec["cves"]:
            item=by_cve.setdefault(cve,{
                "id": f"{target}:{cve}",
                "cve": cve,
                "target": target,
                "status": "discovered",
                "validation": "pending",
                "exploit_status": "pending",
                "confidence": 0.60,
                "source": source,
                "evidence_lines": [],
                "ports": [],
                "service": "unknown",
                "version": "unknown",
                "exploit_references": [],
                "attempts": [],
            })
            item["evidence_lines"].append(rec)
            item["ports"]=sorted(set(item["ports"]+rec["ports"]))
            item["confidence"]=min(0.95,item["confidence"]+0.05)
    return list(by_cve.values())

def merge_candidates(existing: list[dict], new_items: list[dict]) -> list[dict]:
    merged={x.get("id"):x for x in existing if x.get("id")}
    for item in new_items:
        old=merged.get(item["id"])
        if not old:
            merged[item["id"]]=item
            continue
        old["confidence"]=max(old.get("confidence",0),item.get("confidence",0))
        old["evidence_lines"]=old.get("evidence_lines",[])+item.get("evidence_lines",[])
        old["ports"]=sorted(set((old.get("ports") or [])+(item.get("ports") or [])))
        if item.get("service") and old.get("service")=="unknown":
            old["service"]=item["service"]
        if item.get("version") and old.get("version")=="unknown":
            old["version"]=item["version"]
    return list(merged.values())
