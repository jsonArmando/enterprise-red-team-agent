# core/graph.py
import logging
from langgraph.graph import StateGraph, END
from nodes.dynamic_agent import dynamic_redteam_node

logger = logging.getLogger("GraphBuilder")

def should_continue(state: dict) -> str:
    if state.get("mission_complete", False):
        logger.info("[+] Misión completada o fases evaluadas con éxito.")
        return "end"
    if state.get("step_count", 0) >= 15:
        logger.info("[*] Límite de iteraciones alcanzado.")
        return "end"
    return "continue"

def build_persistent_redteam_graph():
    workflow = StateGraph(dict)
    workflow.add_node("autonomous_agent", dynamic_redteam_node)
    workflow.set_entry_point("autonomous_agent")
    workflow.add_conditional_edges(
        "autonomous_agent",
        should_continue,
        {"continue": "autonomous_agent", "end": END}
    )
    return workflow.compile()