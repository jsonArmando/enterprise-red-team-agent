"""Objective-driven controller: observe -> select -> execute adapter -> verify -> replan."""
from pathlib import Path
from core.cve_engine import build_inventory, merge_inventory
from core.objective import verify_flags, next_objective
from core.autonomous_policy import authorize

class AutonomousController:
    def __init__(self,target:str,workdir:Path,scope:dict):
        self.target=target; self.workdir=workdir; self.scope=scope
        self.loot=workdir/"loot"; self.loot.mkdir(parents=True,exist_ok=True)

    def observe(self,state:dict)->dict:
        outputs=[h.get("output","") for h in state.get("history",[])]
        status=verify_flags(self.loot,outputs)
        state["flags"]=status
        state["objective"]=next_objective(status)
        return state

    def ingest_scan(self,state:dict,scan_output:str)->dict:
        found=build_inventory(self.target,scan_output)
        state["vulnerabilities"]=merge_inventory(state.get("vulnerabilities",[]),found)
        state.setdefault("evidence_ledger",[]).append({
            "source_tool":"vulnerability_scanner","confidence":0.70,
            "verified":False,"raw_output":scan_output[:10000]
        })
        return state

    def choose_candidate(self,state:dict)->dict|None:
        pending=[v for v in state.get("vulnerabilities",[]) if v.get("status")=="candidate"]
        pending.sort(key=lambda v:(-v.get("confidence",0),v.get("cve","")))
        return pending[0] if pending else None

    def authorize_exploit(self,candidate:dict)->tuple[bool,str]:
        return authorize(self.target,self.scope,"exploit",candidate)

    def record_result(self,state:dict,candidate_id:str,success:bool,evidence:str="")->dict:
        for v in state.get("vulnerabilities",[]):
            if v.get("id")==candidate_id:
                v["status"]="confirmed" if success else "rejected"
                if evidence: v.setdefault("evidence",[]).append(evidence[:4000])
        return self.observe(state)
