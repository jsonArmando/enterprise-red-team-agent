from core.state import RedTeamState
from tools.scanner import run_nmap_recon

def recon_node(state: RedTeamState) -> dict:
    """
    Nodo encargado de ejecutar el reconocimiento sobre el objetivo actual.
    """
    # Determinar a qué objetivo apuntar (el principal o el primero de la cola dinámicamente)
    current_target = state.get("target")
    if state["task_queue"]:
        current_target = state["task_queue"].pop(0)

    print(f"\n[+] [Recon Node] Analizando superficie de ataque en: {current_target}")
    
    # Ejecutar la herramienta de Kali
    scan_output = run_nmap_recon(current_target)
    
    # Actualizar estado
    return {
        "completed_targets": [current_target],
        "findings": [{"target": current_target, "type": "nmap_scan", "data": scan_output}],
        "current_phase": "analyze",
        "logs": [f"Reconocimiento completado para {current_target}"]
    }
