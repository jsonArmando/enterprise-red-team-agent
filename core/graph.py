import logging
from langgraph.graph import StateGraph,END
from nodes.dynamic_agent import dynamic_redteam_node
logger=logging.getLogger("GraphBuilder")
MAX_STEPS=200
def should_continue(state):
    if state.get("mission_complete",False):return "end"
    if int(state.get("step_count",0))>=MAX_STEPS:return "end"
    return "continue"
def build_persistent_redteam_graph():
    w=StateGraph(dict); w.add_node("autonomous_agent",dynamic_redteam_node); w.set_entry_point("autonomous_agent")
    w.add_conditional_edges("autonomous_agent",should_continue,{"continue":"autonomous_agent","end":END}); return w.compile()
