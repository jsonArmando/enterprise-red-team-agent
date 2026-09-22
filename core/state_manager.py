import json
import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger("EnterpriseDynamicAgent")


class StateManager:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.state_dir = Path(f"testing/{target_ip}")
        self.scans_dir = self.state_dir / "scans"
        self.loot_dir = self.state_dir / "loot"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "agent_state.json"

    def update_etc_hosts(self, domain_name: str, hostnames: list | None = None):
        if not domain_name:
            return
        if not hostnames:
            hostnames = [domain_name, f"dc.{domain_name}", "dc"]
        line = f"{self.target_ip} {' '.join(hostnames)}"
        try:
            content = Path("/etc/hosts").read_text(encoding="utf-8")
            if self.target_ip in content and domain_name in content:
                return
            sudo_pass = os.getenv("SUDO_PASS")
            if not sudo_pass:
                logger.warning("[!] SUDO_PASS unset; skip /etc/hosts (set env, do not hardcode)")
                return
            cmd = [
                "sudo",
                "-S",
                "tee",
                "-a",
                "/etc/hosts",
            ]
            result = subprocess.run(
                cmd,
                input=f"{sudo_pass}\n{line}\n",
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                logger.info("[+] /etc/hosts += %s", line)
            else:
                logger.error("[-] hosts update failed: %s", result.stderr)
        except Exception as exc:
            logger.error("[-] hosts exception: %s", exc)

    def save_state(
        self,
        step: int,
        history_entry: dict,
        phase: str = "recon",
        mission_complete: bool = False,
        discovered_services: list | None = None,
        vulnerabilities: list | None = None,
        credentials: list | None = None,
        extra: dict | None = None,
    ):
        existing = self.load_state()
        history = (extra or {}).get("history") if extra is not None else None
        if history is None:
            history = list(existing.get("history", []))
            history.append(history_entry)
        data = {
            "target": self.target_ip,
            "phase": phase,
            "step_count": step,
            "mission_complete": mission_complete,
            "last_output": history_entry.get("output", ""),
            "history": history,
            "discovered_services": discovered_services
            if discovered_services is not None
            else existing.get("discovered_services", []),
            "vulnerabilities": vulnerabilities
            if vulnerabilities is not None
            else existing.get("vulnerabilities", []),
            "credentials": credentials
            if credentials is not None
            else existing.get("credentials", []),
        }
        if extra:
            data.update(extra)
        self.state_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("[+] state -> %s", self.state_file)

    def load_state(self) -> dict:
        if self.state_file.exists():
            try:
                return json.loads(self.state_file.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.error("[-] state read: %s", exc)
        return {
            "target": self.target_ip,
            "phase": "recon",
            "step_count": 0,
            "mission_complete": False,
            "last_output": "",
            "history": [],
            "discovered_services": [],
            "vulnerabilities": [],
            "credentials": [],
        }


def get_target_dir(target: str) -> str:
    p = Path(f"testing/{target}")
    p.mkdir(parents=True, exist_ok=True)
    (p / "scans").mkdir(exist_ok=True)
    (p / "loot").mkdir(exist_ok=True)
    return str(p)


def save_persistent_state(state: dict) -> None:
    target = state.get("target") or state.get("mission_target")
    if not target:
        return
    path = Path(get_target_dir(target)) / "agent_state.json"
    path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def save_loot(target: str, name: str, content: str) -> None:
    path = Path(get_target_dir(target)) / "loot" / name
    path.write_text(content, encoding="utf-8")
