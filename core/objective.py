"""Independent objective verification for HTB-style lab missions."""
from __future__ import annotations
from pathlib import Path
from core.flags import extract_flags

def verify_flags(loot_dir: Path, outputs: list[str]) -> dict:
    user=[]; root=[]
    for p in loot_dir.rglob("*"):
        if not p.is_file() or p.stat().st_size > 2_000_000:
            continue
        try: data=p.read_text(errors="ignore")
        except OSError: continue
        hits=extract_flags(data)
        name=p.name.lower()
        if "user.txt" in name: user.extend(hits)
        elif "root.txt" in name: root.extend(hits)
    blob="\n".join(outputs[-10:])
    if "user.txt" in blob.lower(): user.extend(extract_flags(blob))
    if "root.txt" in blob.lower(): root.extend(extract_flags(blob))
    user=list(dict.fromkeys(user)); root=list(dict.fromkeys(root))
    return {"user_flag":user[0] if user else None,"root_flag":root[0] if root else None,
            "user_verified":bool(user),"root_verified":bool(root),"complete":bool(user and root)}

def next_objective(status: dict) -> str:
    if not status["user_verified"]: return "obtain_user_flag"
    if not status["root_verified"]: return "obtain_root_flag"
    return "complete"
