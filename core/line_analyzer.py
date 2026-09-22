"""Line-by-line evidence ledger for an authorized HTB/lab target."""
from __future__ import annotations
import re
from typing import Any

CVE_RE=re.compile(r"\bCVE-\d{4}-\d{4,7}\b",re.I)
PORT_RE=re.compile(r"\b(\d{1,5})/(tcp|udp)\b",re.I)

KEYWORDS=(
    "open","filtered","closed","version","product","service","running",
    "cpe:","vulnerable","vulnerability","cve-","domain","hostname",
    "smb","ldap","kerberos","ssh","http","https","rpc"
)

def analyze_all_lines(text:str)->list[dict[str,Any]]:
    ledger=[]
    for number,raw in enumerate((text or "").splitlines(),1):
        line=raw.strip()
        if not line:
            ledger.append({"line":number,"text":"","category":"blank","cves":[],"ports":[]})
            continue
        cves=sorted({x.upper() for x in CVE_RE.findall(line)})
        ports=[int(m.group(1)) for m in PORT_RE.finditer(line)]
        lower=line.lower()
        if cves:
            category="cve"
        elif ports and "open" in lower:
            category="service"
        elif any(k in lower for k in KEYWORDS):
            category="context"
        else:
            category="other"
        ledger.append({
            "line":number,
            "text":line[:2000],
            "category":category,
            "cves":cves,
            "ports":ports,
        })
    return ledger

def analyze_lines(text:str)->list[dict[str,Any]]:
    """Backward-compatible relevant-line view."""
    return [x for x in analyze_all_lines(text) if x["category"] in {"cve","service","context"}]

def correlate_cves(target:str,text:str,source:str)->list[dict[str,Any]]:
    ledger=analyze_all_lines(text)
    by_cve={}
    for rec in ledger:
        for cve in rec["cves"]:
            nearby=[x for x in ledger if max(1,rec["line"]-2)<=x["line"]<=rec["line"]+2]
            item=by_cve.setdefault(cve,{
                "id":f"{target}:{cve}",
                "cve":cve,
                "target":target,
                "status":"discovered",
                "validation":"pending",
                "exploit_status":"pending",
                "confidence":0.60,
                "source":source,
                "evidence_lines":[],
                "ports":[],
                "service":"unknown",
                "version":"unknown",
                "exploit_references":[],
                "attempts":[],
            })
            item["evidence_lines"].extend(nearby)
            item["ports"]=sorted(set(item["ports"]+[p for x in nearby for p in x["ports"]]))
            item["confidence"]=min(0.95,item["confidence"]+0.05)
    for item in by_cve.values():
        seen=set()
        item["evidence_lines"]=[x for x in item["evidence_lines"] if not (x["line"] in seen or seen.add(x["line"]))]
    return list(by_cve.values())

def build_line_ledger(text:str)->list[dict[str,Any]]:
    return analyze_all_lines(text)

def merge_candidates(existing:list[dict],new_items:list[dict])->list[dict]:
    merged={x.get("id"):x for x in existing if x.get("id")}
    for item in new_items:
        old=merged.get(item["id"])
        if not old:
            merged[item["id"]]=item
            continue
        old["confidence"]=max(old.get("confidence",0),item.get("confidence",0))
        old["evidence_lines"]=old.get("evidence_lines",[])+item.get("evidence_lines",[])
        old["ports"]=sorted(set((old.get("ports") or [])+(item.get("ports") or [])))
    return list(merged.values())
