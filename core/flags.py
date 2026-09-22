"""Detect HTB-style flags (32 hex) without treating any mention of user.txt as success."""
from __future__ import annotations

import re
from pathlib import Path

FLAG_RE = re.compile(r"\b([a-fA-F0-9]{32})\b")
NOISE = (
    "no such file",
    "access denied",
    "permission denied",
    "cannot find",
    "file not found",
)


def extract_flags(text: str) -> list[str]:
    if not text:
        return []
    low = text.lower()
    if any(n in low for n in NOISE) and "user.txt" in low and len(text) < 80:
        return []
    seen = []
    for m in FLAG_RE.findall(text):
        h = m.lower()
        if h not in seen:
            seen.append(h)
    return seen


def flags_from_loot(loot_dir: Path) -> dict:
    found = {"user": [], "root": [], "unknown": []}
    if not loot_dir.exists():
        return found
    for path in loot_dir.rglob("*"):
        if not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        try:
            data = path.read_text(errors="ignore")
        except OSError:
            continue
        hits = extract_flags(data)
        name = path.name.lower()
        bucket = "unknown"
        if "user" in name:
            bucket = "user"
        elif "root" in name:
            bucket = "root"
        found[bucket].extend(hits)
    return found


def mission_status(outputs: list[str], loot_dir: Path) -> dict:
    user, root = [], []
    blob = "\n".join(outputs[-12:])
    for h in extract_flags(blob):
        if "root.txt" in blob.lower() and not user:
            root.append(h)
        else:
            user.append(h)
    loot = flags_from_loot(loot_dir)
    user += loot["user"] or loot["unknown"][:1]
    root += loot["root"]
    user = list(dict.fromkeys(user))
    root = list(dict.fromkeys(root))
    return {
        "user_flags": user,
        "root_flags": root,
        "user_ok": bool(user),
        "root_ok": bool(root),
        "complete": bool(user and root),
    }
