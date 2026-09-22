#!/usr/bin/env python3
"""Authorized-lab Red Team agent. Requires --ip in HTB ranges unless ALLOWED_NETWORKS is set."""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import time
from pathlib import Path

from core.flags import extract_flags, mission_status
from core.playbook import LabPlaybook
from core.policy_engine import evaluate_policy
from core.state_manager import StateManager
from utils.smart_executor import SmartCommandExecutor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("EnterpriseDynamicAgent")

DOMAIN_RE = re.compile(
    r"(\b[a-zA-Z0-9-]+\.(?:htb|lab|local|lan|internal)\b)", re.I
)


def parse_args():
    p = argparse.ArgumentParser(description="HTB-scoped red team agent")
    p.add_argument("ip", nargs="?", help="Target IP (must pass policy)")
    p.add_argument("--user", help="Assume-breach username")
    p.add_argument("--password", help="Assume-breach password")
    p.add_argument("--domain", help="FQDN if already known")
    p.add_argument("--max-steps", type=int, default=20)
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()


def inject_domain(playbook: LabPlaybook, domain: str | None, command: str) -> str:
    if domain:
        return command.replace("detected.htb", domain)
    return command.replace(" -d detected.htb", "").replace("detected.htb/", "/")


def harvest_creds(state: dict, output: str) -> list:
    creds = list(state.get("credentials") or [])
    # nxc success line: [+] domain\\user:pass
    for m in re.finditer(r"\[\+\]\s+\S+\\([^:\s]+):(\S+)", output):
        creds.append({"username": m.group(1), "password": m.group(2), "source": "nxc"})
    return creds


def write_flag_files(loot: Path, status: dict) -> None:
    if status["user_flags"]:
        (loot / "user.flag").write_text(status["user_flags"][0] + "\n")
    if status["root_flags"]:
        (loot / "root.flag").write_text(status["root_flags"][0] + "\n")


def main():
    args = parse_args()
    target = args.ip or os.getenv("TARGET_IP")
    if not target:
        logger.error("Usage: python3 main.py <IP> [--user U --password P]")
        sys.exit(2)

    if not evaluate_policy(target):
        logger.error("Target rejected by policy. Export ALLOWED_NETWORKS if this is your lab.")
        sys.exit(3)

    sm = StateManager(target)
    state = sm.load_state()
    if args.user and args.password:
        state.setdefault("credentials", [])
        state["credentials"].insert(0, {"username": args.user, "password": args.password, "source": "cli"})
    if args.domain:
        state["domain"] = args.domain

    playbook = LabPlaybook(target, sm.state_dir)
    executor = SmartCommandExecutor(timeout_minutes=12, poll_interval=10)
    step = state.get("step_count", 0)

    logger.info("=== authorized lab agent target=%s ===", target)

    while step < args.max_steps:
        step += 1
        status = mission_status(
            [h.get("output", "") for h in state.get("history", [])],
            sm.loot_dir,
        )
        if status["complete"]:
            write_flag_files(sm.loot_dir, status)
            logger.info("[+] MISSION COMPLETE user=%s root=%s", status["user_flags"], status["root_flags"])
            sm.save_state(step, {"command": "stop", "output": "flags"}, phase="done", mission_complete=True, extra=status)
            break

        cmd, phase = playbook.next_action(state)
        domain = state.get("domain") or args.domain
        cmd = inject_domain(playbook, domain, cmd)

        if not evaluate_policy(target):
            logger.error("Policy denied mid-run")
            break

        logger.info("[*] step %s [%s] %s", step, phase, cmd)
        if args.dry_run:
            output = "[dry-run]"
        else:
            result = executor.execute_with_polling(cmd)
            output = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")

        scan_blob = ""
        vs = sm.scans_dir / "version_scan.txt"
        qs = sm.scans_dir / "quick_scan.txt"
        if vs.exists():
            scan_blob = vs.read_text(errors="ignore")
        elif qs.exists():
            scan_blob = qs.read_text(errors="ignore")
        m = DOMAIN_RE.search(scan_blob) or DOMAIN_RE.search(output)
        if m and not state.get("domain"):
            state["domain"] = m.group(1).lower()
            sm.update_etc_hosts(state["domain"])
            logger.info("[+] domain %s", state["domain"])

        state["credentials"] = harvest_creds(state, output)
        flags = extract_flags(output)
        if flags:
            (sm.loot_dir / f"flags_step_{step}.txt").write_text("\n".join(flags) + "\n")
            logger.info("[+] candidate flags: %s", flags)

        entry = {"step": step, "command": cmd, "output": output[-8000:], "phase": phase}
        status = mission_status(
            [h.get("output", "") for h in state.get("history", [])] + [output],
            sm.loot_dir,
        )
        write_flag_files(sm.loot_dir, status)
        sm.save_state(
            step,
            entry,
            phase=phase,
            mission_complete=status["complete"],
            credentials=state.get("credentials"),
            extra={"domain": state.get("domain"), **status},
        )
        state = sm.load_state()
        if status["complete"]:
            logger.info("[+] flags user=%s root=%s", status["user_flags"], status["root_flags"])
            break
        if phase == "idle":
            logger.info("[*] playbook idle — supply --user/--password from enum")
            break
        time.sleep(1)

    else:
        logger.warning("[!] max steps reached")


if __name__ == "__main__":
    main()
