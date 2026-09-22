"""Normalized world model built from evidence; target agnostic."""
from typing import Any, Dict
from core.reasoning import ReasoningState

class WorldModel:
    def __init__(self,state: Dict[str,Any]): self.state=state
    def snapshot(self)->Dict[str,Any]:
        r=ReasoningState(self.state).context()
        return {k:r.get(k,[]) for k in ("facts","new_facts","capabilities","hypotheses","candidate_goals","vulnerability_signals","entities","resources","control_signal","hypothesis_control")}
