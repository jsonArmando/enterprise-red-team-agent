from core.state import RedTeamState

def grow_node(state: RedTeamState) -> dict:
    """
    Nodo de expansión dinámica (Grow): decide si se profundiza en nuevos vectores descubiertos.
    """
    queue = state.get("task_queue", [])
    completed = state.get("completed_targets", [])
    
    # Filtrar tareas pendientes que no hayan sido analizadas
    pending_tasks = [t for t in queue if t not in completed]
    
    if pending_tasks:
        print(f"[🔥] [Grow Node] Superficie expandida. Nuevos objetivos en cola: {pending_tasks}")
        next_phase = "recon" # Volvemos a la fase de recon con el nuevo vector
    else:
        print("[*] [Grow Node] No hay nuevos vectores de expansión. Finalizando ciclo.")
        next_phase = "complete"

    return {
        "current_phase": next_phase,
        "logs": [f"Fase Grow evaluada. Siguiente fase: {next_phase}"]
    }
