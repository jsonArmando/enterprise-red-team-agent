"""Thin nmap helpers used by the playbook."""
from pathlib import Path


def quick_scan_cmd(ip: str, out: Path) -> str:
    return f"nmap -Pn -T4 --top-ports 200 -sV --open -oN {out} {ip}"


def full_scan_cmd(ip: str, out: Path) -> str:
    return f"nmap -Pn -sC -sV -p- --min-rate 800 -oN {out} {ip}"
