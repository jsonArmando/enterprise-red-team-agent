"""Single entry point for the objective-driven autonomous HTB/lab agent."""
from __future__ import annotations
import sys, time, json
from pathlib import Path

from core.state_manager import StateManager
from core.audit import AuditTrail
from core.cve_engine import build_inventory, merge_inventory
from core.flags import mission_status
from core.decision_engine import DecisionEngine
from core.policy_engine import evaluate_policy
from tools.autonomous_tools import (
    run_recon, run_vulnerability_scan, run_cve_lookup,
    run_mcp_exploit, run_post_exploit, verify_flags_remote,
)

class EnterpriseDynamicAgent:
    def __init__(self, target_ip: str):
        self.target = target_ip
        self.manager = StateManager(target_ip)
        self.workdir = Path(f"testing/{target_ip}")
        self.audit = AuditTrail(self.workdir)
        self.engine = DecisionEngine()
        self.scope_policy = {"allowed_networks": None, "allowed_domains": [".htb", ".lab", ".local"]}
        if not evaluate_policy(target_ip, self.scope_policy):
            raise SystemExit(f"Target blocked by scope policy: {target_ip}")

    def load(self) -> dict:
        state = self.manager.load_state()
        state.setdefault("mission", "HTB authorized lab: obtain and verify user.txt and root.txt")
        state.setdefault("objective", "obtain_user_flag")
        state.setdefault("vulnerabilities", [])
        state.setdefault("hypotheses", [])
        state.setdefault("evidence_ledger", [])
        state.setdefault("history", [])
        state.setdefault("recon_complete", False)
        state.setdefault("vulnerability_scan_complete", False)
        state.setdefault("foothold", False)
        return state

    def save(self, state: dict, event: dict | None = None) -> None:
        if event:
            state.setdefault("history", []).append(event)
            self.audit.record(event.get("event_type", "state"), **event)
        state["step_count"] = len(state.get("history", []))
        self.manager.save_state(
            step=state["step_count"],
            history_entry=event or {"event_type":"state_sync"},
            phase=state.get("objective","planner"),
            mission_complete=state.get("flags",{}).get("complete",False),
            discovered_services=state.get("discovered_services",[]),
            vulnerabilities=state.get("vulnerabilities",[]),
            extra=state,
        )

    def update_flags(self, state: dict) -> dict:
        outputs=[h.get("output","") for h in state.get("history",[])]
        state["flags"]=mission_status(outputs,self.workdir/"loot")
        if state["flags"]["user_ok"] and not state["flags"]["root_ok"]:
            state["objective"]="obtain_root_flag"
        elif state["flags"]["complete"]:
            state["objective"]="complete"
        else:
            state["objective"]="obtain_user_flag"
        return state

    def find_candidate(self,state,candidate_id):
        return next((x for x in state.get("vulnerabilities",[]) if x.get("id")==candidate_id),None)

    def execute(self,state,decision):
        action=decision.get("action")
        cid=decision.get("candidate_id")
        self.audit.record("decision",action=action,candidate_id=cid,reason=decision.get("reason"))
        output=""
        evidence={}
        if action=="recon":
            output=run_recon(self.target,self.workdir/"scans"/"full_recon.txt")
            state["recon_complete"]=True
            state["discovered_services"]=[line for line in output.splitlines() if "/tcp" in line and "open" in line]
        elif action=="vulnerability_scan":
            output=run_vulnerability_scan(self.target,self.workdir/"scans"/"vulnerability_scan.txt")
            state["vulnerability_scan_complete"]=True
            state["vulnerabilities"]=merge_inventory(
                state.get("vulnerabilities",[]),
                build_inventory(self.target,output,"nmap-vuln")
            )
        elif action=="cve_lookup":
            candidate=self.find_candidate(state,cid)
            if not candidate: return state,"missing_candidate"
            output=run_cve_lookup(candidate["cve"])
            candidate["exploit_references"]=output[:12000]
            candidate["status"]="candidate"
        elif action=="exploit_candidate":
            candidate=self.find_candidate(state,cid)
            if not candidate: return state,"missing_candidate"
            if candidate.get("status")=="rejected": return state,"candidate_rejected"
            output=run_mcp_exploit(self.target,candidate)
            success=any(x in output.lower() for x in ("shell","session","foothold","meterpreter","uid="))
            candidate["status"]="confirmed" if success else "rejected"
            candidate.setdefault("attempts",0); candidate["attempts"]+=1
            state["foothold"]=state.get("foothold",False) or success
            evidence={"candidate_id":cid,"success":success}
        elif action=="post_exploit_enum":
            output=run_post_exploit(self.target,{"foothold":state.get("foothold",False)})
            state["foothold"]=True
        elif action=="privilege_escalation":
            output=run_post_exploit(self.target,{"foothold":True,"objective":"root.txt"})
            state["foothold"]=True
        elif action=="verify_flags":
            output=verify_flags_remote(self.target)
        elif action=="replan":
            output=json.dumps({"vulnerabilities":state.get("vulnerabilities",[]),"failed":state.get("failed_paths",[])})
        else:
            raise ValueError(f"unsupported_action:{action}")

        event={"event_type":"execution","action":action,"candidate_id":cid,
               "reason":decision.get("reason",""),"output":output[:12000],**evidence}
        state.setdefault("evidence_ledger",[]).append({
            "source_tool":action,"confidence":0.8,"verified":False,"raw_output":output[:12000]
        })
        self.update_flags(state)
        return state,event

    def run(self):
        state=self.load()
        self.update_flags(state)
        self.save(state)
        while not state["flags"]["complete"]:
            decision=self.engine.decide(state)
            state,event=self.execute(state,decision)
            self.save(state,event)
            if state["flags"]["complete"]:
                self.audit.record("mission_complete",flags=state["flags"])
                break
            time.sleep(1)
        print(json.dumps({
            "target":self.target,
            "status":"COMPLETE",
            "flags":state["flags"],
            "audit":str(self.audit.events),
            "state":str(self.manager.state_file),
        },indent=2))

if __name__=="__main__":
    if len(sys.argv)!=2:
        raise SystemExit("Uso: python main.py <HTB_TARGET_IP>")
    EnterpriseDynamicAgent(sys.argv[1]).run()
