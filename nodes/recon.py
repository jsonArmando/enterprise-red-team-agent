# nodes/recon.py
import logging
from tools.mcp_router import call_mcp_domain

logger = logging.getLogger("ReconNode")

def recon_node(state: dict) -> dict:
    target = state.get("target") or state.get("ip")
    logger.info(f"[*] [Recon Node] Iniciando escaneo profundo de puertos sobre {target}...")
    
    try:
        # Escaneo completo de puertos (-p-) con detección de versiones (-sV)
        recon_output = call_mcp_domain(
            domain="recon",
            tool_name="nmap_scan",
            arguments={"target": target, "options": "-p- -sV -T4 --open"}
        )
    except Exception as e:
        recon_output = f"Error en reconocimiento: {e}"
        
    logger.info("[*] [Recon Node] Escaneo profundo completado.")
    
    return {
        **state,
        "recon_output": recon_output,
        "last_action": "recon"
    }