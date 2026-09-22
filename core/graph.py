"""Unified LangGraph entry point for the objective-driven controller."""
from langgraph.graph import StateGraph, END

def build_persistent_redteam_graph():
    workflow=StateGraph(dict)
    workflow.add_node("autonomous_controller", lambda state: state)
    workflow.set_entry_point("autonomous_controller")
    workflow.add_edge("autonomous_controller",END)
    return workflow.compile()

def should_continue(state:dict)->str:
    return "end" if state.get("flags",{}).get("complete") else "continue"
