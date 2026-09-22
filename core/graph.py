"""LangGraph supervisor for the autonomous HTB/lab mission."""
from __future__ import annotations
from langgraph.graph import StateGraph, END

def build_persistent_redteam_graph(agent):
    workflow=StateGraph(dict)

    def autonomous_step(state):
        decision=agent.engine.decide(state)
        state,event=agent.execute(state,decision)
        agent.save(state,event)
        return state

    workflow.add_node("autonomous_step",autonomous_step)
    workflow.set_entry_point("autonomous_step")
    workflow.add_conditional_edges(
        "autonomous_step",
        lambda state: "end" if state.get("flags",{}).get("complete") else "continue",
        {"continue":"autonomous_step","end":END},
    )
    return workflow.compile()
