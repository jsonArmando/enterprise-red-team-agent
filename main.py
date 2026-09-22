#!/usr/bin/env python3
"""Automatic authorized-lab agent: python3 main.py 10.129.x.x"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import time
from pathlib import Path

from core.flags import extract_flags, mission_status
from core.intel import merge_intel, parse_loot_files, parse_output, persist_intel
from core.playbook import LabPlaybook
from core.policy_engine import evaluate_policy
from core.state_manager import StateManager
from utils.smart_executor import SmartCommandExecutor

DOMAIN_RE = re.compile(r"(\b[a-zA-Z0-9-]+\.(?:htb|lab|local|lan|internal)\b)", re.I)
logger = logging.getLogger("EnterpriseDynamicAgent")


def setup_logging(log_file: Path) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
    )


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("ip", help="Target IP in lab range")
    p.add_argument("--max-steps", type=int, default=25)
    return p.parse_args()


def inject_domain(domain: str | None, command: str) -> str:
    if domain:
        return command.replace("detected.htb", domain)
    return command.replace(" -d detected.htb", "").replace("detected.htb/", "/")


def write_flags(loot: Path, status: dict) -> None:
    if status.get("user_flags"):
        (loot / "user.flag").write_text(status["user_flags"][0] + "\n")
    if status.get("root_flags"):
        (loot / "root.flag").write_text(status["root_flags"][0] + "\n")
    if status.get("user_flags") or status.get("root_flags"):
        (loot / "flags.json").write_text(
            __import__("json").dumps(
                {"user": status.get("user_flags", []), "root": status.get("root_flags", [])},
                indent=2,
            )
        )


def main():
    args = parse_args()
    target = args.ip
    if not evaluate_policy(target):
        print("[-] IP fuera de alcance HTB/lab", file=sys.stderr)
        sys.exit(3)

    sm = StateManager(target)
    setup_logging(sm.state_dir / "agent.log")
    state = sm.load_state()
    playbook = LabPlaybook(target, sm.state_dir)
    executor = SmartCommandExecutor(timeout_minutes=12, poll_interval=10)
    step = state.get("step_count", 0)

    logger.info("AUTO start target=%s logs=%s", target, sm.state_dir / "agent.log")

    while step < args.max_steps:
        step += 1
        intel = merge_intel(state, parse_loot_files(sm.loot_dir))
        state.update(intel)
        persist_intel(sm.loot_dir, intel)

        status = mission_status([h.get("output", "") for h in state.get("history", [])], sm.loot_dir)
        write_flags(sm.loot_dir, status)
        if status["complete"]:
            logger.info("[+] DONE user=%s root=%s", status["user_flags"], status["root_flags"])
            sm.save_state(step, {"command": "stop", "output": "flags"}, "done", True, credentials=intel["credentials"], extra=status)
            break

        cmd, phase = playbook.next_action(state)
        cmd = inject_domain(state.get("domain"), cmd)
        logger.info("[*] %s [%s] %s", step, phase, cmd)

        result = executor.execute_with_polling(cmd)
        output = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")
        (sm.state_dir / "logs").mkdir(exist_ok=True)
        (sm.state_dir / "logs" / f"step_{step:02d}.log").write_text(output, encoding="utf-8")

        scan = ""
        for n in ("version_scan.txt", "quick_scan.txt"):
            p = sm.scans_dir / n
            if p.exists():
                scan = p.read_text(errors="ignore")
                break
        m = DOMAIN_RE.search(scan) or DOMAIN_RE.search(output)
        if m and not state.get("domain"):
            state["domain"] = m.group(1).lower()
            sm.update_etc_hosts(state["domain"])
            logger.info("[+] domain %s", state["domain"])

        intel = merge_intel(state, parse_output(output), parse_loot_files(sm.loot_dir))
        state.update(intel)
        persist_intel(sm.loot_dir, intel)
        if intel["credentials"]:
            logger.info("[+] creds saved: %s", [c.get("username") for c in intel["credentials"]])
        if intel["passwords"]:
            logger.info("[+] passwords stored: %s", len(intel["passwords"]))

        flags = extract_flags(output)
        if flags:
            (sm.loot_dir / f"flags_step_{step}.txt").write_text("\n".join(flags) + "\n")

        status = mission_status(
            [h.get("output", "") for h in state.get("history", [])] + [output],
            sm.loot_dir,
        )
        write_flags(sm.loot_dir, status)
        sm.save_state(
            step,
            {"step": step, "command": cmd, "output": output[-8000:], "phase": phase},
            phase=phase,
            mission_complete=status["complete"],
            credentials=intel["credentials"],
            extra={
                "domain": state.get("domain"),
                "users": intel["users"],
                "passwords": intel["passwords"],
                **status,
            },
        )
        state = sm.load_state()
        if status["complete"]:
            logger.info("[+] flags user=%s root=%s", status["user_flags"], status["root_flags"])
            break
        if phase == "idle" and not intel["credentials"]:
            logger.info("[*] idle without creds yet; enum artifacts in %s", sm.loot_dir)
            break
        time.sleep(1)


if __name__ == "__main__":
    main()
