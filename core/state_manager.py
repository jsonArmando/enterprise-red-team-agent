import os
import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger("EnterpriseDynamicAgent")

class StateManager:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.state_dir = Path(f"testing/{target_ip}")
        self.scans_dir = self.state_dir / "scans"
        self.loot_dir = self.state_dir / "loot"
        
        # Crear directorios necesarios para la estructura del agente
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        
        self.state_file = self.state_dir / "agent_state.json"

    def update_etc_hosts(self, domain_name: str, hostnames: list = None):
        """
        Agrega o actualiza automáticamente la resolución de DNS local en /etc/hosts
        utilizando la contraseña de sudo de forma automatizada (SUDO_PASS o 'kali' por defecto).
        """
        if not domain_name:
            return

        if not hostnames:
            hostnames = [domain_name, f"dc.{domain_name}", "dc"]
            
        entries_to_add = " ".join(hostnames)
        host_entry_line = f"{self.target_ip} {entries_to_add}"

        try:
            with open("/etc/hosts", "r", encoding="utf-8") as f:
                content = f.read()

            if self.target_ip in content and domain_name in content:
                logger.info(f"[*] [HostsManager] El objetivo {self.target_ip} y dominio '{domain_name}' ya están configurados en /etc/hosts.")
                return

            logger.info(f"[*] [HostsManager] Registrando mapeo estático en /etc/hosts -> {host_entry_line}")
            
            # Obtener contraseña de sudo de variable de entorno o usar 'kali' por defecto
            sudo_pass = os.getenv("SUDO_PASS", "kali")
            
            # Ejecución segura con sudo -S sin bloquear la terminal interactiva
            cmd = f"printf '%s\\n%s\\n' '{sudo_pass}' '{host_entry_line}' | sudo -S tee -a /etc/hosts > /dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"[+] [HostsManager] /etc/hosts actualizado exitosamente para {domain_name}.")
            else:
                logger.error(f"[-] [HostsManager] Error al actualizar /etc/hosts: {result.stderr}")

        except Exception as e:
            logger.error(f"[-] [HostsManager] Excepción crítica al modificar /etc/hosts: {e}")

    def save_state(self, step: int, history_entry: dict, phase: str = "recon", mission_complete: bool = False, discovered_services: list = None, vulnerabilities: list = None, credentials: list = None):
        """
        Guarda y consolida el estado completo del agente en agent_state.json.
        Parámetros obligatorios primero, argumentos opcionales con valores por defecto al final.
        """
        existing_data = self.load_state()
        
        history_list = existing_data.get("history", [])
        history_list.append(history_entry)

        state_data = {
            "target": self.target_ip,
            "phase": phase,
            "step_count": step,
            "mission_complete": mission_complete,
            "last_output": history_entry.get("output", ""),
            "history": history_list,
            "discovered_services": discovered_services if discovered_services is not None else existing_data.get("discovered_services", []),
            "vulnerabilities": vulnerabilities if vulnerabilities is not None else existing_data.get("vulnerabilities", []),
            "credentials": credentials if credentials is not None else existing_data.get("credentials", [])
        }

        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(state_data, f, indent=4, ensure_ascii=False)
            
        logger.info(f"[+] [StateManager] Estado persistido correctamente en {self.state_file}")

    def load_state(self) -> dict:
        """
        Carga el estado actual desde el archivo JSON si existe, de lo contrario retorna un diccionario base.
        """
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"[-] [StateManager] Error al leer el archivo de estado: {e}")
        
        return {
            "target": self.target_ip,
            "phase": "recon",
            "step_count": 0,
            "mission_complete": False,
            "last_output": "",
            "history": [],
            "discovered_services": [],
            "vulnerabilities": [],
            "credentials": []
        }