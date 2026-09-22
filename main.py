"""Single autonomous entry point for authorized HTB/lab targets."""
from __future__ import annotations
import sys, time, json
from pathlib import Path

from core.state_manager import StateManager
from core.audit import AuditTrail
from core.flags import mission_status
from core.decision_engine import DecisionEngine
from core.policy_engine import evaluate_policy
from utils.exploit_matcher import ExploitMatcher
from tools.autonomous_tools import (
    run_recon, run_vulnerability_scan, run_cve_lookup,
    run_mcp_validate, run_mcp_exploit, run_post_exploit, verify_flags_remote,
)

class EnterpriseDynamicAgent:
    def __init__(self, target_ip: str):
        self.target = target_ip
        self.manager = StateManager(target_ip)
        self.workdir = Path(f"testing/{target_ip}")
        self.audit = AuditTrail(self.workdir)
        self.engine = DecisionEngine()
        self.matcher = ExploitMatcher(target_ip)
        self.scope_policy = {"allowed_networks": None, "allowed_domains": [".htb", ".lab", ".local"]}
        if not evaluate_policy(target_ip, self.scope_policy):
            raise SystemExit(f"Target blocked by scope policy: {target_ip}")

    def load(self) -> dict:
        state=self.manager.load_state()
        defaults={
            "mission":"HTB authorized lab: obtain and verify user.txt and root.txt",
            "objective":"obtain_user_flag",
            "vulnerabilities":[],
            "hypotheses":[],
            "evidence_ledger":[],
            "history":[],
            "recon_complete":False,
            "vulnerability_scan_complete":False,
            "potential_exploits_ready":False,
            "foothold":False,
            "failed_paths":[],
        }
        for k,v in defaults.items(): state.setdefault(k,v)
        if not state.get("flags"):
            state["flags"]={"user_verified":False,"root_verified":False,"complete":False}
        return state

    def save(self,state:dict,event:dict|None=None)->None:
        if event:
            state.setdefault("history",[]).append(event)
            self.audit.record(event.get("event_type","state"),**event)
        state["step_count"]=len(state.get("history",[]))
        self.manager.save_state(
            step=state["step_count"],
            history_entry=event or {"event_type":"state_sync"},
            phase=state.get("objective","planner"),
            mission_complete=state.get("flags",{}).get("complete",False),
            discovered_services=state.get("discovered_services",[]),
            vulnerabilities=state.get("vulnerabilities",[]),
            extra=state,
        )

    def update_flags(self,state:dict)->dict:
        outputs=[h.get("output","") for h in state.get("history",[])]
        state["flags"]=mission_status(outputs,self.workdir/"loot")
        if state["flags"]["complete"]:
            state["objective"]="complete"
        elif state["flags"]["user_ok"]:
            state["objective"]="obtain_root_flag"
        else:
            state["objective"]="obtain_user_flag"
        return state

    def candidate(self,state,cid):
        return next((x for x in state.get("vulnerabilities",[]) if x.get("id")==cid),None)

    def build_potential_exploits(self,state)->None:
        recon_text=""
        for p in [self.workdir/"scans"/"full_recon.txt",self.workdir/"scans"/"vulnerability_scan.txt"]:
            if p.exists(): recon_text += "\n" + p.read_text(errors="ignore")
        if not recon_text:
            recon_text="\n".join(h.get("output","") for h in state.get("history",[]) if h.get("action") in {"recon","vulnerability_scan"})
        candidates=self.matcher.analyze_enumeration(recon_text,"recon+enumeration")
        by_id={x.get("id"):x for x in candidates}
        state["vulnerabilities"]=list(by_id.values())
        state["potential_exploits_ready"]=True
        self.audit.record("potential_exploits_generated",count=len(candidates),path=str(self.matcher.exploits_file))

    def execute(self,state,decision):
        action=decision.get("action")
        cid=decision.get("candidate_id")
        self.audit.record("decision",action=action,candidate_id=cid,reason=decision.get("reason",""))
        output=""
        event_extra={}

        if action=="recon":
            output=run_recon(self.target,self.workdir/"scans"/"full_recon.txt")
            state["recon_complete"]=True
            state["discovered_services"]=[line for line in output.splitlines() if "/tcp" in line and "open" in line]

        elif action=="vulnerability_scan":
            output=run_vulnerability_scan(self.target,self.workdir/"scans"/"vulnerability_scan.txt")
            state["vulnerability_scan_complete"]=True
            self.build_potential_exploits(state)

        elif action=="cve_lookup":
            c=self.candidate(state,cid)
            if not c: return state,{"event_type":"error","action":action,"error":"missing_candidate"}
            output=run_cve_lookup(c["cve"])
            c["exploit_references"]=output[:12000]
            c["status"]="discovered"

        elif action=="analyze_candidate":
            c=self.candidate(state,cid)
            if not c: return state,{"event_type":"error","action":action,"error":"missing_candidate"}
            analysis=self.engine.analyze_candidate(c,state)
            c["analysis"]=analysis
            c["status"]="analyzed"
            c["validation"]="pending"
            output=json.dumps(analysis,ensure_ascii=False)

        elif action=="validate_candidate":
            c=self.candidate(state,cid)
            if not c: return state,{"event_type":"error","action":action,"error":"missing_candidate"}
            output=run_mcp_validate(self.target,c)
            valid="VULNERABILITY_CONFIRMED" in output.upper() or "VALIDATED" in output.upper()
            c["validation"]="validated" if valid else "rejected"
            c["validation_evidence"]=output[:12000]

        elif action=="exploit_candidate":
            c=self.candidate(state,cid)
            if not c: return state,{"event_type":"error","action":action,"error":"missing_candidate"}
            if c.get("validation")!="validated":
                return state,{"event_type":"blocked","action":action,"candidate_id":cid,"reason":"candidate_not_validated"}
            output=run_mcp_exploit(self.target,c)
            success=any(x in output.lower() for x in ("shell","session","foothold","meterpreter","uid="))
            c["exploit_status"]="confirmed" if success else "rejected"
            c.setdefault("attempts",[]).append({"result":"success" if success else "failure","output":output[:4000]})
            if success: state["foothold"]=True
            else: state.setdefault("failed_paths",[]).append({"candidate_id":cid,"cve":c.get("cve"),"reason":"exploit_failed"})

        elif action=="post_exploit_enum":
            output=run_post_exploit(self.target,{"foothold":True,"objective":state.get("objective")})
            state["foothold"]=True

        elif action=="privilege_escalation":
            output=run_post_exploit(self.target,{"foothold":True,"objective":"root.txt","mode":"authorized_lab"})

        elif action=="verify_flags":
            output=verify_flags_remote(self.target)

        elif action=="replan":
            output=json.dumps({
                "unresolved": [v for v in state.get("vulnerabilities",[]) if v.get("validation")!="rejected" and v.get("exploit_status")!="confirmed"],
                "failed_paths":state.get("failed_paths",[]),
                "objective":state.get("objective"),
            },ensure_ascii=False)

        else:
            raise ValueError(f"unsupported_action:{action}")

        event={
            "event_type":"execution",
            "action":action,
            "candidate_id":cid,
            "reason":decision.get("reason",""),
            "output":output[:12000],
            **event_extra,
        }
        state.setdefault("evidence_ledger",[]).append({
            "source_tool":action,
            "confidence":0.8,
            "verified":action in {"validate_candidate","verify_flags"},
            "raw_output":output[:12000],
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

        final_status="COMPLETE" if state["flags"]["complete"] else "RUNNING"
        print(json.dumps({
            "target":self.target,
            "status":final_status,
            "flags":state["flags"],
            "potential_exploits":str(self.matcher.exploits_file),
            "audit":str(self.audit.events),
            "state":str(self.manager.state_file),
        },indent=2,ensure_ascii=False))

if __name__=="__main__":
    if len(sys.argv)!=2:
        raise SystemExit("Uso: python main.py <HTB_TARGET_IP>")
    EnterpriseDynamicAgent(sys.argv[1]).run()
