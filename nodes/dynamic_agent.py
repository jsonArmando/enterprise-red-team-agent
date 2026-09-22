"""
Módulo Enterprise: dynamic_agent.py
Arquitectura de Agente Autónomo Resiliente para Red Team y Pentesting de Entornos Críticos.
Diseñado bajo estándares de Ciberarquitectura Avanzada, con motores de análisis forense pasivo,
extracción automática de credenciales/usuarios, sanitización de comandos y prevención de bloqueos.
"""

import logging
import os
import json
import re
import time
import httpx
from typing import Dict, Any, List, Tuple, Optional

from tools.mcp_router import call_kali_tool
from core.state_manager import save_persistent_state, save_loot, get_target_dir

# Configuración avanzada de Logging Profesional con formato forense
logger = logging.getLogger("EnterpriseDynamicAgent")
logger.setLevel(logging.INFO)

if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] [EnterpriseAgent] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


class CommandSanitizer:
    """
    Motor de saneamiento, validación y corrección sintáctica de comandos destinados
    a las herramientas de Kali Linux ejecutadas a través del router MCP.
    """

    @staticmethod
    def clean(cmd: str) -> str:
        """Elimina comentarios residuales en línea (#), retornos de carro y espacios vacíos."""
        if not cmd:
            return ""
        if "#" in cmd:
            cmd = cmd.split("#")[0]
        return cmd.strip()

    @staticmethod
    def enforce_smb_syntax(cmd: str, target: str) -> str:
        """Neutraliza errores comunes de escape en barras invertidas para protocolos SMB/RPC."""
        if "smbclient" in cmd and ("\\\\" not in cmd or "Not enough '\\' characters" in cmd):
            logger.warning("[!] [Sanitizer] Detectado error potencial en sintaxis SMB. Reestructurando comando...")
            return f"smbclient '\\\\{target}\\Replication' -N -c 'recurse; ls'"
        return cmd

    @staticmethod
    def validate_command_safety(cmd: str) -> bool:
        """Filtra comandos destructivos accidentales para mantener la seguridad operacional (OpSec)."""
        dangerous_patterns = ["rm -rf /", "mkfs", "dd if=/dev/zero", ":(){ :|:& };:"]
        for pattern in dangerous_patterns:
            if pattern in cmd:
                logger.error(f"[!] [ALERTA DE SEGURIDAD] Comando destructivo bloqueado por política: {cmd}")
                return False
        return True


class NetworkAnalyzerAndParser:
    """
    Motor analítico especializado en procesar salidas crudas de Nmap, enum4linux, 
    smbclient y RPC, extrayendo inteligencia táctica y artefactos de valor forense.
    """

    @staticmethod
    def extract_open_ports(nmap_output: str) -> str:
        """Extrae y formatea una lista limpia de puertos abiertos separados por comas para escaneos focalizados."""
        ports = []
        for line in nmap_output.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split("/")
                if parts:
                    port_num = parts[0].strip()
                    if port_num.isdigit():
                        ports.append(port_num)
        extracted = ",".join(ports)
        logger.info(f"[*] [NetworkAnalyzer] Puertos abiertos identificados: {extracted or 'Ninguno'}")
        return extracted

    @staticmethod
    def parse_and_store_loot(target: str, output: str):
        """
        Analiza de forma exhaustiva la salida de las herramientas en busca de:
        - Nombres de usuarios (Accounts / Users)
        - Contraseñas o texto plano (Passwords)
        - Hashes criptográficos (NTLM / Kerberos)
        - Recursos compartidos y políticas de dominio
        Guarda cada hallazgo clasificado en su respectivo archivo dentro de TESTING/<ip>/loot/
        """
        if not output:
            return

        target_dir = get_target_dir(target)
        loot_dir = os.path.join(target_dir, "loot")
        os.makedirs(loot_dir, exist_ok=True)

        # 1. Extracción de Usuarios / Cuentas
        user_matches = re.findall(r'(?:user|account|username)[:\s]+([a-zA-Z0-9_\-\.]+)', output, re.IGNORECASE)
        # Patrones comunes de enum4linux para usuarios
        enum_users = re.findall(r'\[\+\]\s+([a-zA-Z0-9_\-\.]+)\s+\(Sid:', output)
        all_users = list(set(user_matches + enum_users))
        
        if all_users:
            users_file = os.path.join(loot_dir, "extracted_users.txt")
            existing_users = set()
            if os.path.exists(users_file):
                with open(users_file, "r") as f:
                    existing_users = set(f.read().splitlines())
            
            new_users = [u for u in all_users if u not in existing_users]
            if new_users:
                with open(users_file, "a") as f:
                    for u in new_users:
                        f.write(f"{u}\n")
                logger.info(f"[+] [LootManager] Se registraron {len(new_users)} nuevos usuarios en: {users_file}")

        # 2. Extracción de Contraseñas, Hashes o Secretos
        credential_keywords = ["password", "pass", "pwd", "hash", "secret", "credentials", "ntlm", "lmhash"]
        lines = output.splitlines()
        found_secrets = []
        for line in lines:
            lower_line = line.lower()
            if any(kw in lower_line for kw in credential_keywords) and len(line.strip()) > 3:
                found_secrets.append(line.strip())

        if found_secrets:
            creds_file = os.path.join(loot_dir, "extracted_credentials_and_secrets.txt")
            with open(creds_file, "a") as f:
                for secret in found_secrets:
                    f.write(f"{secret}\n")
            logger.info(f"[+] [LootManager] ¡Secretos/Credenciales potenciales detectados y guardados en {creds_file}!")

        # 3. Guardado completo de la salida si contiene información de dominio o recursos valiosos
        if "sysvol" in output.lower() or "replication" in output.lower() or "domain controller" in output.lower():
            domain_info_file = os.path.join(loot_dir, "domain_structure_intelligence.txt")
            with open(domain_info_file, "w") as f:
                f.write(output)
            logger.info(f"[+] [LootManager] Inteligencia de Active Directory guardada en: {domain_info_file}")


class LLMDecisionEngine:
    """
    Motor de Inteligencia Artificial basado en Model Context Protocol (MCP) / OpenAI Compatible API.
    Gestiona el razonamiento táctico del agente autónomo con manejo de reintentos y respaldos.
    """

    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        self.base_url = os.environ.get("OPENAI_API_BASE", "https://api.x.ai/v1").strip()
        self.model_name = os.environ.get("MODEL_NAME", "grok-3").strip()

    def consult_tactical_next_step(self, target: str, history: List[Dict[str, Any]], last_output: str) -> Dict[str, Any]:
        """Consulta al LLM estructurando el contexto operativo actual para definir el siguiente comando."""
        if not self.api_key:
            logger.error("[-] [LLMEngine] OPENAI_API_KEY no se encuentra configurada en el entorno.")
            return {
                "thought": "Error crítico: Falta configurar la clave de API.",
                "command": "",
                "mission_complete": True
            }

        system_prompt = (
            "Eres un operador experto de Red Team de nivel Senior, especializado en auditorías ofensivas de infraestructura "
            "y Active Directory corporativo. Analiza el historial de operaciones y la última salida obtenida de Kali Linux. "
            "Tu objetivo es avanzar paso a paso: Reconocimiento -> Enumeración profunda de servicios (SMB, LDAP, Kerberos, RPC) -> "
            "Identificación de vectores de ataque / extracción de credenciales / explotación -> Post-explotación. "
            "Responde EXCLUSIVAMENTE en un formato JSON válido (sin bloques de código markdown adicionales) con esta estructura exacta:\n"
            "{\n"
            '  "thought": "Análisis táctico detallado justificando el siguiente paso técnico",\n'
            '  "command": "Comando exacto de Kali Linux a ejecutar sin comentarios",\n'
            '  "mission_complete": false\n'
            "}"
            "Regla crítica: mission_complete SOLO puede ser true cuando exista evidencia de una FLAG real en la salida o en testing/<target>/loot. Si no hay flag, debes proponer otra acción; no declares la auditoría completada por falta de vectores inmediatos.\n"
        )

        # Ventana de contexto optimizada para evitar saturación de tokens
        recent_history = history[-6:] if len(history) > 6 else history
        user_content = (
            f"Objetivo actual: {target}\n"
            f"Historial reciente:\n{json.dumps(recent_history, indent=2)}\n\n"
            f"Última salida obtenida de Kali Linux (truncada si es muy extensa):\n{last_output[:3000]}"
        )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            "temperature": 0.2
        }

        try:
            logger.info("[*] [LLMEngine] Consultando al modelo de razonamiento táctico...")
            with httpx.Client(timeout=60) as client:
                response = client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
                if response.status_code == 200:
                    raw_content = response.json()["choices"][0]["message"]["content"]
                    clean_content = raw_content.replace("```json", "").replace("```", "").strip()
                    parsed_json = json.loads(clean_content)
                    return parsed_json
                else:
                    logger.error(f"[-] [LLMEngine] Error HTTP del servidor LLM: {response.status_code} - {response.text}")
        except json.JSONDecodeError:
            logger.error("[-] [LLMEngine] Error: El modelo no retornó un JSON válido. Aplicando recuperación.")
        except Exception as e:
            logger.error(f"[-] [LLMEngine] Excepción de comunicación con el LLM: {str(e)}")

        # Plan de contingencia automático ante fallos de API
        return {
            "thought": "Falla temporal de comunicación con el LLM. Ejecutando sondeo de respaldo SMB.",
            "command": f"smbclient -L \\\\\\\\{target}\\\\\\\\ -N",
            "mission_complete": false
        }


def dynamic_redteam_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Nodo orquestador central del Agente Autónomo Resiliente.
    Administra la máquina de estados, ejecución de fases deterministas de alta velocidad,
    prevención de bucles infinitos, auditoría de herramientas y persistencia de loot.
    """
    target = state.get("target")
    history = state.get("history", [])
    step_count = state.get("step_count", 0) + 1
    last_output = state.get("last_output", "")
    
    target_dir = get_target_dir(target)
    scans_dir = os.path.join(target_dir, "scans")

    logger.info(f"==================================================")
    logger.info(f"[*] [Agente Autónomo - Paso {step_count}] Analizando objetivo: {target}")
    logger.info(f"==================================================")

    command_to_execute = ""
    thought = ""
    mission_complete = False

    # Análisis de bucles de sintaxis recientes
    recent_commands = [h.get("command", "") for h in history[-3:]]
    smb_syntax_error = "Not enough '\\' characters" in last_output or "syntax error" in last_output.lower()
    stuck_in_smb_loop = sum(1 for cmd in recent_commands if "smbclient" in cmd) >= 2 and smb_syntax_error

    # ==========================================
    # FASE 1: Reconocimiento Inicial Rápido (Paso 1)
    # ==========================================
    if step_count == 1 and not any("nmap" in h.get("command", "") for h in history):
        scan_file = os.path.join(scans_dir, "initial_scan.txt")
        command_to_execute = f"nmap -T4 --min-rate 3000 --top-ports 1000 -oN {scan_file} {target}"
        thought = "Fase 1: Escaneo rápido de los 1000 puertos principales para detección instantánea de servicios."
        mission_complete = False

    # ==========================================
    # FASE 2: Escaneo Quirúrgico de Versiones (Paso 2)
    # ==========================================
    elif step_count == 2 and any("nmap" in h.get("command", "") for h in history):
        open_ports = NetworkAnalyzerAndParser.extract_open_ports(last_output)
        scan_file = os.path.join(scans_dir, "version_scan.txt")
        if open_ports:
            command_to_execute = f"nmap -sV -sC -p {open_ports} -oN {scan_file} {target}"
            thought = f"Fase 2: Puertos abiertos identificados ({open_ports}). Ejecutando escaneo profundo de versiones (-sV) y scripts (-sC)."
        else:
            command_to_execute = f"nmap -sV -sC -oN {scan_file} {target}"
            thought = "No se detectaron puertos estructurados en el paso 1. Lanzando escaneo completo de versiones."
        mission_complete = False

    # ==========================================
    # RECUPERACIÓN DE BUCLES DE SINTAXIS
    # ==========================================
    elif stuck_in_smb_loop:
        command_to_execute = CommandSanitizer.enforce_smb_syntax("", target)
        thought = "Intervención del Supervisor: Bucle de sintaxis SMB detectado. Forzando comando de conexión seguro."
        mission_complete = False

    # ==========================================
    # FASE 3+: Razonamiento Autónomo Inteligente (LLM)
    # ==========================================
    else:
        engine = LLMDecisionEngine()
        decision = engine.consult_tactical_next_step(target, history, last_output)
        
        raw_cmd = decision.get("command", "")
        command_to_execute = CommandSanitizer.clean(raw_cmd)
        
        # Validación complementaria de sintaxis SMB generada por el LLM
        if "smbclient" in command_to_execute and "\\\\" not in command_to_execute:
            command_to_execute = f"smbclient '\\\\{target}\\Replication' -N"
            
        thought = decision.get("thought", "Razonamiento autónomo ejecutado con éxito.")
        mission_complete = bool(decision.get("mission_complete", False))
        flag_re = re.compile(r"(?:flag|htb)\\{[^}]{4,200}\\}", re.I)
        flag_evidence = bool(flag_re.search(last_output or ""))
        loot_root = os.path.join(target_dir, "loot")
        if os.path.isdir(loot_root):
            for root_dir, _, files in os.walk(loot_root):
                if any(name.lower() in {"user.txt", "root.txt", "flag.txt", "user.flag", "root.flag", "flags.json"} for name in files):
                    flag_evidence = True
                    break
                for name in files:
                    path = os.path.join(root_dir, name)
                    try:
                        if os.path.getsize(path) <= 2_000_000 and flag_re.search(open(path, encoding="utf-8", errors="ignore").read()):
                            flag_evidence = True
                            break
                    except (OSError, UnicodeError):
                        pass
                if flag_evidence: break
        if mission_complete and not flag_evidence:
            logger.warning("[!] El LLM pidió finalizar sin flag; se ignora mission_complete y se continúa.")
            mission_complete = False

    logger.info(f"[*] [Razonamiento del Agente]: {thought}")
    
    execution_result = last_output
    if command_to_execute and not mission_complete:
        clean_cmd = CommandSanitizer.clean(command_to_execute)
        
        if not CommandSanitizer.validate_command_safety(clean_cmd):
            logger.error("[-] Operación abortada por fallas en validación de seguridad de comandos.")
            updated_state = {**state, "step_count": step_count, "mission_complete": True}
            save_persistent_state(updated_state)
            return updated_state

        parts = clean_cmd.split(" ", 1)
        tool_name = parts[0]
        tool_args = parts[1] if len(parts) > 1 else ""
        
        logger.info(f"[*] [Ejecución Real] Lanzando herramienta Kali: {clean_cmd}")
        logger.info(f"[*] [Nota Operativa] Las herramientas complejas (como enum4linux) pueden tomar varios minutos. Por favor espere...")
        
        # Timeout extendido a 900 segundos (15 minutos) para herramientas de enumeración pesadas en AD
        execution_result = call_kali_tool(tool_name, tool_args, timeout=900)
        
        # Análisis forense pasivo y almacenamiento automático de loot (Usuarios, Contraseñas, Hashes)
        NetworkAnalyzerAndParser.parse_and_store_loot(target, execution_result)

        # Registro en el historial con truncamiento controlado
        history.append({
            "step": step_count,
            "command": clean_cmd,
            "thought": thought,
            "output": execution_result[:4000]
        })

    updated_state = {
        **state,
        "step_count": step_count,
        "mission_complete": mission_complete,
        "last_output": execution_result,
        "history": history
    }

    save_persistent_state(updated_state)
    logger.info(f"[+] [Estado Guardado] Paso {step_count} completado y persistido en {target_dir}/agent_state.json")
    return updated_state