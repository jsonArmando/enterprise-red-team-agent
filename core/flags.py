"""Robust HTB-style flag detection with filename/context validation."""
from __future__ import annotations
import re
from pathlib import Path

FLAG_RE=re.compile(r"\b([a-fA-F0-9]{32})\b")
FLAG_CONTEXT_RE=re.compile(r"(?im)(user\.txt|root\.txt)[^\n]{0,200}?\b([a-fA-F0-9]{32})\b")

def extract_flags(text:str)->list[str]:
    if not text: return []
    return list(dict.fromkeys(x.lower() for x in FLAG_RE.findall(text)))

def extract_named_flags(text:str)->dict[str,list[str]]:
    found={"user":[],"root":[]}
    for match in FLAG_CONTEXT_RE.finditer(text or ""):
        kind=match.group(1).lower().split(".")[0]
        found[kind].append(match.group(2).lower())
    for k in found: found[k]=list(dict.fromkeys(found[k]))
    return found

def flags_from_loot(loot_dir:Path)->dict:
    found={"user":[],"root":[],"unknown":[]}
    if not loot_dir.exists(): return found
    for path in loot_dir.rglob("*"):
        if not path.is_file() or path.stat().st_size>2_000_000: continue
        try: data=path.read_text(errors="ignore")
        except OSError: continue
        name=path.name.lower()
        hits=extract_flags(data)
        if "user.txt" in name: found["user"].extend(hits)
        elif "root.txt" in name: found["root"].extend(hits)
        else:
            named=extract_named_flags(data)
            found["user"].extend(named["user"])
            found["root"].extend(named["root"])
    for k in found: found[k]=list(dict.fromkeys(found[k]))
    return found

def mission_status(outputs:list[str],loot_dir:Path)->dict:
    user=[]; root=[]
    for output in outputs[-20:]:
        named=extract_named_flags(output)
        user.extend(named["user"]); root.extend(named["root"])
    loot=flags_from_loot(loot_dir)
    user += loot["user"]; root += loot["root"]
    user=list(dict.fromkeys(user)); root=list(dict.fromkeys(root))
    return {
        "user_flags":user,
        "root_flags":root,
        "user_ok":bool(user),
        "root_ok":bool(root),
        "complete":bool(user and root),
    }
