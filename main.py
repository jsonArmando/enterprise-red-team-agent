"""Single autonomous entry point for authorized HTB/lab targets."""
from __future__ import annotations
import sys, json, os
from pathlib import Path
from dataclasses import asdict

from core.state_manager import StateManager
from core.audit import AuditTrail
from core.flags import mission_status
from core.decision_engine import DecisionEngine
from core.policy_engine import evaluate_policy
from core.graph import build_persistent_redteam_graph
from core.session_manager import SessionManager
from core.reverse_shell import ReverseShellOrchestrator
from core.privesc_engine import PrivEscEngine
from core.kali_tools import KaliToolCatalog
from utils.exploit_matcher import ExploitMatcher
from tools.autonomous_tools import (
    run_recon, run_vulnerability_scan, run_cve_lookup,
    run_mcp_validate, run_mcp_exploit, run_post_exploit, run_privilege_validation, run_privilege_escalation,
    verify_flags_remote, run_shell_tool,
)
from tools.mcp_client import call_kali_mcp_tool

class EnterpriseDynamicAgent:
    def __init__(self, target_ip: str):
        self.target = target_ip
        self.manager = StateManager(target_ip)
        self.workdir = Path(f"testing/{target_ip}")
        self.audit = AuditTrail(self.workdir)
        self.engine = DecisionEngine()
        self.matcher = ExploitMatcher(target_ip)
        self.sessions = SessionManager(target_ip, call_kali_mcp_tool)
        self.reverse_shell = ReverseShellOrchestrator(target_ip, call_kali_mcp_tool)
        self.privesc = PrivEscEngine()
        self.kali_catalog = KaliToolCatalog(target_ip, self.workdir, call_kali_mcp_tool)
        self.scope_policy = {
            "allowed_networks": None,
            "allowed_domains": [".htb", ".lab", ".local"],
        }
        if not evaluate_policy(target_ip, self.scope_policy):
            raise SystemExit(f"Target blocked by scope policy: {target_ip}")

    def load(self) -> dict:
        state = self.manager.load_state()
        defaults = {
            "mission":"HTB authorized lab: obtain and verify user.txt and root.txt",
            "objective":"obtain_user_flag",
            "vulnerabilities":[],
            "hypotheses":[],
            "privesc_candidates":[],
            "evidence_ledger":[],
            "history":[],
            "reasoning_trace":[],
            "failure_memory":[],
            "failed_paths":[],
            "kali_tools":[],
            "kali_tools_catalogued":False,
            "recon_complete":False,
            "vulnerability_scan_complete":False,
            "potential_exploits_ready":False,
            "foothold":False,
            "session":{},
            "post_exploit_complete":False,
            "reverse_shell_attempted":False,
        }
        for key, value in defaults.items():
            state.setdefault(key, value)
        if not state.get("flags"):
            state["flags"]={"user_ok":False,"root_ok":False,"user_verified":False,"root_verified":False,"complete":False}
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
            credentials=state.get("credentials",[]),
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
        state["mission_complete"]=bool(state["flags"]["complete"])
        return state

    def candidate(self,state,cid):
        return next((x for x in state.get("vulnerabilities",[]) if x.get("id")==cid),None)

    def build_potential_exploits(self,state)->None:
        text_parts=[]
        for p in [
            self.workdir/"scans"/"full_recon.txt",
            self.workdir/"scans"/"vulnerability_scan.txt",
        ]:
            if p.exists():
                text_parts.append(p.read_text(errors="ignore"))
        if not text_parts:
            text_parts=[h.get("output","") for h in state.get("history",[]) if h.get("action") in {"recon","vulnerability_scan"}]
        text="\n".join(text_parts)
        candidates=self.matcher.analyze_enumeration(text,"recon+enumeration")
        state["vulnerabilities"]=candidates
        state["potential_exploits_ready"]=True
        self.audit.record("potential_exploits_generated",count=len(candidates),path=str(self.matcher.exploits_file))

    @staticmethod
    def structured_success(output:str)->bool:
        try:
            data=json.loads(output)
            if isinstance(data,dict):
                privilege=str(data.get("privilege_level") or data.get("user") or "").lower()
                return bool(
                    data.get("success") or data.get("access_obtained") or
                    data.get("session_established") or data.get("root_obtained") or
                    data.get("verified") or data.get("uid")==0 or privilege in {"root","system"}
                )
        except Exception:
            pass
        low=output.lower()
        return any(x in low for x in ("session_established","access_obtained","foothold","uid=","root_obtained"))

    def register_failure(self,state,action,output,cid=None,candidate=None)->dict:
        failure_id=f"{len(state.get('history',[]))+1}:{action}:{cid or '-'}"
        failure={
            "id":failure_id,"action":action,"candidate_id":cid,
            "candidate":candidate or {},"output":output[:8000],
            "new_evidence_required":True,
        }
        state.setdefault("failure_memory",[]).append(failure)
        state.setdefault("failed_paths",[]).append({
            "id":failure_id,"action":action,"candidate_id":cid,
            "reason":"action_failed","output":output[:3000],
        })
        self.audit.record("action_failure",**failure)
        return failure

    def execute(self,state,decision):
        action=decision.get("action")
        cid=decision.get("candidate_id")
        if decision.get("deep_reasoning"):
            state.setdefault("reasoning_trace",[]).append(decision["deep_reasoning"])
            state["failure_reasoned_id"]=decision.get("failure_id")
            self.audit.record("deep_reasoning",**decision["deep_reasoning"])

        self.audit.record("decision",action=action,candidate_id=cid,reason=decision.get("reason",""))
        output=""
        failure=None
        event_extra={}

        if action=="recon":
            output=run_recon(self.target,self.workdir/"scans"/"full_recon.txt")
            state["recon_complete"]=bool(output)
            if output.startswith("ERROR:") or "Salida con código" in output:
                failure=self.register_failure(state,action,output)
            state["discovered_services"]=[
                line for line in output.splitlines() if "/tcp" in line and "open" in line
            ]

        elif action=="discover_kali_tools":
            tools=self.kali_catalog.discover_all()
            state["kali_tools"]=tools
            state["kali_tools_catalogued"]=True
            output=json.dumps({"count":len(tools),"sample":[x.get("name") for x in tools[:100]]},ensure_ascii=False)

        elif action=="vulnerability_scan":
            output=run_vulnerability_scan(self.target,self.workdir/"scans"/"vulnerability_scan.txt")
            state["vulnerability_scan_complete"]=bool(output)
            if output.startswith("ERROR:") or "Salida con código" in output:
                failure=self.register_failure(state,action,output)
            else:
                self.build_potential_exploits(state)

        elif action=="run_kali_tool":
            tool=decision.get("tool_name")
            args=decision.get("arguments",[])
            allowed={x.get("name") for x in state.get("kali_tools",[]) if x.get("name")}
            if tool not in allowed:
                return state,{"event_type":"blocked","action":action,"reason":"tool_not_in_discovered_kali_catalog"}
            try:
                output=run_shell_tool(tool,args,timeout=int(decision.get("timeout",900)),catalogued_tools=allowed)
            except Exception as exc:
                output=f"ERROR: {exc}"
                failure=self.register_failure(state,action,output)

        elif action=="cve_lookup":
            c=self.candidate(state,cid)
            if not c:
                return state,{"event_type":"error","action":action,"error":"missing_candidate"}
            output=run_cve_lookup(c["cve"])
            c["exploit_references"]=output[:12000]
            c["status"]="discovered"

        elif action=="analyze_candidate":
            c=self.candidate(state,cid)
            if not c:
                return state,{"event_type":"error","action":action,"error":"missing_candidate"}
            analysis=self.engine.analyze_candidate(c,state)
            c["analysis"]=analysis
            c["status"]="analyzed"
            c["validation"]="pending"
            output=json.dumps(analysis,ensure_ascii=False)

        elif action=="validate_candidate":
            c=self.candidate(state,cid)
            if not c:
                return state,{"event_type":"error","action":action,"error":"missing_candidate"}
            output=run_mcp_validate(self.target,c)
            valid="VULNERABILITY_CONFIRMED" in output.upper() or "VALIDATED" in output.upper()
            c["validation"]="validated" if valid else "rejected"
            c["validation_evidence"]=output[:12000]
            if not valid:
                failure=self.register_failure(state,action,output,cid,c)

        elif action=="exploit_candidate":
            c=self.candidate(state,cid)
            if not c:
                return state,{"event_type":"error","action":action,"error":"missing_candidate"}
            if c.get("validation")!="validated":
                return state,{"event_type":"blocked","action":action,"candidate_id":cid,"reason":"candidate_not_validated"}
            output=run_mcp_exploit(self.target,c)
            success=self.structured_success(output)
            c["exploit_status"]="confirmed" if success else "rejected"
            c.setdefault("attempts",[]).append({"result":"success" if success else "failure","output":output[:4000]})
            if success:
                state["foothold"]=True
                state["access_evidence"]=output[:12000]
            else:
                failure=self.register_failure(state,action,output,cid,c)

        elif action=="establish_access":
            session=self.sessions.establish({
                "foothold":state.get("foothold",False),
                "access_evidence":state.get("access_evidence",""),
            })
            output=session.evidence
            state["session"]=asdict(session)
            state["session_established"]=bool(session.connected)
            state["foothold"]=state.get("foothold",False) or state["session_established"]
            if not state["session_established"]:
                failure=self.register_failure(state,action,output)

        elif action=="reverse_shell":
            state["reverse_shell_attempted"]=True
            output=self.reverse_shell.establish({
                "foothold":state.get("foothold",False),
                "access_evidence":state.get("access_evidence",""),
                "previous_session":state.get("session",{}),
            })
            parsed=self.sessions._parse(output)
            if parsed.get("connected"):
                state["session"]=parsed
                state["session_established"]=True
            else:
                failure=self.register_failure(state,action,output)

        elif action=="session_enum":
            output=self.sessions.inspect(state.get("session",{}))
            state["session_evidence"]=output[:12000]

        elif action=="post_exploit_enum":
            output=run_post_exploit(self.target,{
                "session":state.get("session",{}),
                "objective":state.get("objective"),
                "access_evidence":state.get("access_evidence",""),
            })
            state["post_exploit_complete"]=bool(output)
            combined=(state.get("session_evidence","")+"\n"+output)[-30000:]
            fresh=self.privesc.build_hypotheses(combined,state.get("session",{}))
            state["privesc_candidates"]=self.privesc.merge(state.get("privesc_candidates",[]),fresh)
            state["session_evidence"]=combined

        elif action=="analyze_privesc":
            combined=state.get("session_evidence","")
            fresh=self.privesc.build_hypotheses(combined,state.get("session",{}))
            state["privesc_candidates"]=self.privesc.merge(state.get("privesc_candidates",[]),fresh)
            pending=[h for h in state["privesc_candidates"] if h.get("status") in {"discovered","analyzed"}]
            analysis=self.engine.analyze_privesc(pending,state)
            selected=analysis.get("validated_id")
            for h in state["privesc_candidates"]:
                h.pop("selected_by_reasoner",None)
                if h.get("id")==selected:
                    h["status"]="analyzed"
                    h["selected_by_reasoner"]=True
                    h["reasoning"]=analysis
                elif h.get("status")=="discovered":
                    h["status"]="analyzed"
            output=json.dumps(analysis,ensure_ascii=False)

        elif action=="validate_privesc":
            selected=[h for h in state.get("privesc_candidates",[]) if h.get("status")=="analyzed"]
            if not selected:
                return state,{"event_type":"blocked","action":action,"reason":"no_analyzed_privesc_hypothesis"}
            hypothesis=next((h for h in selected if h.get("selected_by_reasoner")),selected[0])
            output=run_privilege_validation(self.target,hypothesis)
            valid="VALIDATED" in output.upper() or "VULNERABILITY_CONFIRMED" in output.upper()
            if valid:
                hypothesis["status"]="validated"
                hypothesis["validation_evidence"]=output[:12000]
            else:
                hypothesis["status"]="rejected"
                hypothesis["validation_evidence"]=output[:12000]
                failure=self.register_failure(state,action,output,None,hypothesis)

        elif action=="privilege_escalation":
            selected=[h for h in state.get("privesc_candidates",[]) if h.get("status")=="validated"]
            if not selected:
                return state,{"event_type":"blocked","action":action,"reason":"no_validated_privesc_hypothesis"}
            output=run_privilege_escalation(self.target,{
                "session":state.get("session",{}),
                "evidence":state.get("session_evidence",""),
            },selected)
            success=self.structured_success(output)
            state["privesc_result"]=output[:12000]
            if not success and "root.txt" not in output.lower():
                failure=self.register_failure(state,action,output,None,selected[0])

        elif action=="verify_flags":
            output=verify_flags_remote(self.target)
            if "user.txt" not in output.lower() and "root.txt" not in output.lower():
                failure=self.register_failure(state,action,output)

        elif action=="replan":
            round_no=int(state.get("replan_round",0))+1
            out_file=self.workdir/"scans"/f"adaptive_recon_{round_no}.txt"
            output=run_recon(self.target,out_file)
            state["replan_round"]=round_no
            state["recon_complete"]=bool(output)
            state["vulnerability_scan_complete"]=False
            state["potential_exploits_ready"]=False
            state["discovered_services"]=list(dict.fromkeys(
                state.get("discovered_services",[])+[
                    line for line in output.splitlines() if "/tcp" in line and "open" in line
                ]
            ))

        else:
            raise ValueError(f"unsupported_action:{action}")

        event={
            "event_type":"execution",
            "action":action,
            "candidate_id":cid,
            "reason":decision.get("reason",""),
            "output":output[:12000],
            "failure_id":failure.get("id") if failure else None,
            **event_extra,
        }
        state.setdefault("evidence_ledger",[]).append({
            "source_tool":action,
            "confidence":0.8 if not failure else 0.3,
            "verified":action in {"validate_candidate","verify_flags"} and not failure,
            "raw_output":output[:12000],
        })
        self.update_flags(state)
        return state,event

    def run(self):
        state=self.load()
        self.update_flags(state)
        self.save(state)
        graph=build_persistent_redteam_graph(self)
        final_state=graph.invoke(
            state,
            config={"recursion_limit":int(os.getenv("GRAPH_RECURSION_LIMIT","10000"))},
        )
        self.update_flags(final_state)
        if final_state["flags"]["complete"]:
            self.audit.record("mission_complete",flags=final_state["flags"])
        print(json.dumps({
            "target":self.target,
            "status":"COMPLETE" if final_state["flags"]["complete"] else "INCOMPLETE",
            "flags":final_state["flags"],
            "kali_tool_count":len(final_state.get("kali_tools",[])),
            "session":final_state.get("session",{}),
            "privesc_candidates":final_state.get("privesc_candidates",[]),
            "potential_exploits":str(self.matcher.exploits_file),
            "audit":str(self.audit.events),
            "state":str(self.manager.state_file),
        },indent=2,ensure_ascii=False))

if __name__=="__main__":
    if len(sys.argv)!=2:
        raise SystemExit("Uso: python main.py <HTB_TARGET_IP>")
    EnterpriseDynamicAgent(sys.argv[1]).run()
