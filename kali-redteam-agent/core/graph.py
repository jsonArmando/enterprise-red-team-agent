from langgraph.graph import StateGraph, END
from core.state import RedTeamState
from nodes.recon import recon_node
from nodes.analyzer import analyzer_node
from nodes.grow import grow_node

def should_continue(state: RedTeamState) -> str:
    """
    Función de decisión condicional para el bucle Grow.
    Si el nodo grow determinó continuar y hay tareas, regresa a recon. De lo contrario, termina.
    """
    phase = state.get("current_phase")
    if phase == "recon":
        return "continue_recon"
    return "end"

def build_redteam_graph():
    """
    Construye y compila la máquina de estados del Agente Red Team.
    """
    workflow = StateGraph(RedTeamState)

    # 1. Registrar los nodos cognitivos
    workflow.add_node("recon", recon_node)
    workflow.add_node("analyze", analyzer_node)
    workflow.add_node("grow", grow_node)

    # 2. Definir el flujo secuencial básico
    workflow.set_entry_point("recon")
    workflow.add_edge("recon", "analyze")
    workflow.add_edge("analyze", "grow")

    # 3. Añadir la arista condicional para el bucle de expansión (Grow Loop)
    workflow.add_conditional_edges(
        "grow",
        should_continue,
        {
            "continue_recon": "recon",
            "end": END
        }
    )

    return workflow.compile()
