"""Extract users, passwords and flags from tool output and downloaded files."""
from __future__ import annotations

import json
import re
from pathlib import Path

USER_LINE = re.compile(r"VALID USERNAME:\s+(\S+)@", re.I)
NXC_OK = re.compile(r"\[\+\]\s+([^\\\s]+)\\([^:\s]+):(\S+)")
USER_TOKEN = re.compile(r"\b(?:user(?:name)?|account)[:\s]+([A-Za-z0-9._-]{2,32})", re.I)
PASS_TOKEN = re.compile(
    r"\b(?:password|passwd|pwd)[:\s]+(\S{4,64})", re.I
)
XML_PASS = re.compile(r"<t[^>]*>([^<]{6,64})</t>")
HEX32 = re.compile(r"\b([a-fA-F0-9]{32})\b")


def _uniq(items: list[str]) -> list[str]:
    out, seen = [], set()
    for x in items:
        x = x.strip().strip("'\"")
        if not x or x.lower() in seen:
            continue
        seen.add(x.lower())
        out.append(x)
    return out


def parse_output(text: str) -> dict:
    users, passwords, creds = [], [], []
    if not text:
        return {"users": [], "passwords": [], "creds": []}
    for m in USER_LINE.finditer(text):
        users.append(m.group(1).split("@")[0])
    for m in NXC_OK.finditer(text):
        creds.append({"username": m.group(2), "password": m.group(3), "domain": m.group(1), "source": "nxc"})
        users.append(m.group(2))
        passwords.append(m.group(3))
    for m in USER_TOKEN.finditer(text):
        users.append(m.group(1))
    for m in PASS_TOKEN.finditer(text):
        p = m.group(1)
        if p.lower() not in {"null", "none", "true", "false"}:
            passwords.append(p)
    return {
        "users": _uniq(users),
        "passwords": _uniq(passwords),
        "creds": creds,
    }


def parse_loot_files(loot: Path) -> dict:
    users, passwords, creds = [], [], []
    if not loot.exists():
        return {"users": [], "passwords": [], "creds": []}
    for path in loot.rglob("*"):
        if not path.is_file() or path.stat().st_size > 5_000_000:
            continue
        if path.suffix.lower() in {".png", ".jpg", ".zip", ".7z", ".exe"}:
            continue
        try:
            data = path.read_text(errors="ignore")
        except OSError:
            continue
        chunk = parse_output(data)
        users += chunk["users"]
        passwords += chunk["passwords"]
        creds += chunk["creds"]
        if path.suffix.lower() in {".xml", ".xlsx", ".txt", ".csv", ".json"}:
            for m in XML_PASS.finditer(data):
                val = m.group(1)
                if any(c.isdigit() for c in val) and any(c.isalpha() for c in val) and " " not in val:
                    passwords.append(val)
    return {
        "users": _uniq(users),
        "passwords": _uniq(passwords),
        "creds": creds,
    }


def merge_intel(state: dict, *chunks: dict) -> dict:
    users = list(state.get("users") or [])
    passwords = list(state.get("passwords") or [])
    creds = list(state.get("credentials") or [])
    for ch in chunks:
        users += ch.get("users") or []
        passwords += ch.get("passwords") or []
        creds += ch.get("creds") or []
    users, passwords = _uniq(users), _uniq(passwords)
    dedup, seen = [], set()
    for c in creds:
        key = (c.get("username", "").lower(), c.get("password", ""))
        if key[0] and key[1] and key not in seen:
            seen.add(key)
            dedup.append(c)
    return {"users": users, "passwords": passwords, "credentials": dedup}


def persist_intel(loot: Path, intel: dict) -> None:
    loot.mkdir(parents=True, exist_ok=True)
    (loot / "users.txt").write_text("\n".join(intel["users"]) + ("\n" if intel["users"] else ""))
    (loot / "passwords.txt").write_text("\n".join(intel["passwords"]) + ("\n" if intel["passwords"] else ""))
    (loot / "credentials.json").write_text(json.dumps(intel["credentials"], indent=2))
