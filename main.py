import hashlib, json, logging, os, re, shlex, sys, time
from pathlib import Path
from typing import Optional
from core.reasoning import ReasoningState
from core.state_manager import StateManager
from utils.smart_executor import SmartCommandExecutor
from nodes.dynamic_agent import CommandSanitizer, LLMDecisionEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger=logging.getLogger("EnterpriseDynamicAgent")
MAX_STEPS=int(os.getenv("AGENT_MAX_STEPS","0")) or None
MAX_NO_PROGRESS_STREAK=int(os.getenv("AGENT_MAX_NO_PROGRESS","25"))
MAX_PLANNER_RETRIES=int(os.getenv("AGENT_MAX_PLANNER_RETRIES","3"))
ARTIFACT_EXTENSIONS={".xml",".txt",".json",".ini",".conf",".config",".yaml",".yml",".log"}

class EnterpriseDynamicAgent:
    """Single autonomous runtime. No target-specific attack path lives here."""
    def __init__(self,target:str,domain_name:Optional[str]=None):
        self.target=target; self.domain_name=domain_name; self.state_manager=StateManager(target)
        state=self.state_manager.load_state(); self.current_step=int(state.get("step_count",0))+1
        self.executor=SmartCommandExecutor(timeout_minutes=int(os.getenv("AGENT_COMMAND_TIMEOUT_MINUTES","20")),poll_interval=int(os.getenv("AGENT_POLL_INTERVAL","15")))
        self.planner=LLMDecisionEngine(); self.reasoning=ReasoningState(state)

    @staticmethod
    def _digest(value): return hashlib.sha256(value.encode("utf-8",errors="ignore")).hexdigest()[:16]
    @staticmethod
    def _norm(value): return re.sub(r"\s+"," ",str(value or "").strip())
    def scan_path(self): return Path(f"testing/{self.target}/scans/recon.txt")

    def flags_found(self):
        root=Path(f"testing/{self.target}")
        if not root.exists(): return []
        marker=re.compile(r"(?:flag|htb)\{[^}]{4,400}\}",re.I); names={"user.txt","root.txt","proof.txt","flag.txt","flags.json","user.flag","root.flag"}; found=[]
        for p in root.rglob("*"):
            if not p.is_file(): continue
            if p.name.lower() in names: found.append(str(p)); continue
            try:
                if p.stat().st_size<=2_000_000 and marker.search(p.read_text(encoding="utf-8",errors="ignore")): found.append(str(p))
            except (OSError,UnicodeError): pass
        return sorted(set(found))

    def _artifacts(self):
        loot=Path(f"testing/{self.target}/loot")
        if not loot.exists(): return []
        out=[]
        for p in loot.rglob("*"):
            if p.is_file() and p.name!="potential_exploits.json" and p.suffix.lower() in ARTIFACT_EXTENSIONS:
                try:
                    if p.stat().st_size<=2_000_000: out.append(p)
                except OSError: pass
        return out

    def _next_artifact(self,state):
        inspected={self._norm(h.get("resource")) for h in state.get("history",[]) if h.get("event_type")=="action" and h.get("action_class")=="inspect_artifact"}
        candidates=[p for p in self._artifacts() if self._norm(os.path.relpath(p,Path.cwd())) not in inspected and self._norm(str(p)) not in inspected]
        if not candidates: return None
        p=max(candidates,key=lambda x:(x.stat().st_mtime,x.stat().st_size)); resource=os.path.relpath(p,Path.cwd())
        return {"action_class":"inspect_artifact","goal_id":"inspect_new_evidence","hypothesis_id":"","evidence_question":"What security-relevant facts and capabilities does this newly acquired artifact provide?","resource":resource,"command":f"sed -n '1,240p' {shlex.quote(resource)}","mission_complete":False}

    def _world(self,state):
        self.reasoning=ReasoningState(state); c=self.reasoning.context()
        return {"facts":c.get("facts",[])[-80:],"new_facts":c.get("new_facts",[])[-40:],"capabilities":c.get("capabilities",[]),"hypotheses":c.get("hypotheses",[])[:16],"candidate_goals":c.get("candidate_goals",[])[:16],"vulnerability_signals":c.get("vulnerability_signals",{}),"resources":c.get("resources",[])[-80:],"control_signal":c.get("control_signal",{}),"hypothesis_control":c.get("hypothesis_control",{})}

    def _context(self,state):
        return {"world":self._world(state),"recent_actions":[{k:h.get(k) for k in ("step","action_class","goal_id","hypothesis_id","evidence_question","resource","command","returncode","evidence_delta","capability_delta","no_new_evidence")} for h in state.get("history",[])[-12:] if h.get("event_type")=="action"],"mission":{"complete":bool(state.get("mission_complete")),"progress_streak":int((state.get("planner_state") or {}).get("no_progress_streak",0))}}

    def _block(self,state,reason,decision=None):
        entry={"event_type":"planner_rejection","step":self.current_step,"reason":reason,"decision":decision or {}}
        self.state_manager.save_state(self.current_step,entry,phase="planning",mission_complete=False,extra={"planner_state":{**dict(state.get("planner_state") or {}),"last_reason":reason}})

    def _initial(self):
        p=self.scan_path()
        if p.exists(): return None
        p.parent.mkdir(parents=True,exist_ok=True)
        return {"action_class":"discover_services","goal_id":"discover_services","hypothesis_id":"","evidence_question":"What services, protocols and exposed surfaces are present on the target?","resource":self.target,"command":f"nmap -sV -sC -oN {shlex.quote(str(p))} {shlex.quote(self.target)}","mission_complete":False}

    def _plan(self,state):
        context=self._context(state)
        for _ in range(MAX_PLANNER_RETRIES):
            d=self.planner.plan(self.target,context)
            if not isinstance(d,dict): self._block(state,"planner_non_object"); continue
            d["command"]=CommandSanitizer.clean(str(d.get("command") or ""))
            if d.get("mission_complete"):
                if self.flags_found(): return d
                self._block(state,"mission_complete_without_flag",d); continue
            if not d["command"]: self._block(state,"empty_action",d); continue
            if not CommandSanitizer.validate_command_safety(d["command"]): self._block(state,"execution_policy_rejected",d); continue
            valid={str(h.get("id")) for h in context["world"].get("hypotheses",[]) if h.get("id")}; hid=str(d.get("hypothesis_id") or "")
            if hid and valid and hid not in valid: self._block(state,"unknown_hypothesis",d); continue
            return d
        return None

    def _execute(self,state,d):
        before=self._world(state); r=self.executor.execute_with_polling(d["command"]); output=r.get("stdout","")
        if r.get("stderr"): output+="\nSTDERR:\n"+r["stderr"]
        provisional={"event_type":"action","step":self.current_step,"action_class":d.get("action_class","unspecified"),"goal_id":d.get("goal_id",""),"hypothesis_id":d.get("hypothesis_id",""),"evidence_question":d.get("evidence_question",""),"resource":d.get("resource",""),"command":d["command"],"output":output[:8000],"returncode":r.get("returncode"),"status":r.get("status")}
        after=self._world({**state,"history":list(state.get("history",[]))+[provisional]})
        oldf={str(x).lower() for x in before.get("facts",[])}; newf={str(x).lower() for x in after.get("facts",[])}; oldc={str(x).lower() for x in before.get("capabilities",[])}; newc={str(x).lower() for x in after.get("capabilities",[])}
        oldh={h.get("id"):h.get("confidence") for h in before.get("hypotheses",[]) if h.get("id")}; conf=0.0
        for h in after.get("hypotheses",[]):
            if h.get("id") in oldh and isinstance(h.get("confidence"),(int,float)) and isinstance(oldh[h.get("id")],(int,float)): conf+=abs(float(h["confidence"])-float(oldh[h.get("id")]))
        delta={"fact_delta":len(newf-oldf),"capability_delta":len(newc-oldc),"hypothesis_confidence_delta":round(conf,4),"output_digest":self._digest(output) if output else ""}
        progress=delta["fact_delta"]>0 or delta["capability_delta"]>0 or delta["hypothesis_confidence_delta"]>0.05
        provisional.update({"evidence_delta":delta,"capability_delta":delta["capability_delta"],"no_new_evidence":not progress,"output_digest":delta["output_digest"]}); return provisional

    def run_autonomous_loop(self):
        while MAX_STEPS is None or self.current_step<=MAX_STEPS:
            state=self.state_manager.load_state()
            if state.get("mission_complete"): return
            flags=self.flags_found()
            if flags: self.state_manager.mark_complete(f"flag_found:{flags[0]}",self.current_step); logger.info("[+] Flag evidence detected."); return
            d=self._next_artifact(state) or self._initial() or self._plan(state)
            if d is None: logger.error("[!] No valid action; stopping safely."); self._block(state,"no_valid_action"); return
            if d.get("mission_complete"):
                if self.flags_found(): self.state_manager.mark_complete("flag_found",self.current_step)
                return
            key=self._norm(f"{d.get('goal_id','')}|{d.get('evidence_question','')}|{d.get('resource','')}")
            duplicate=any(key==self._norm(f"{h.get('goal_id','')}|{h.get('evidence_question','')}|{h.get('resource','')}") and h.get("returncode")==0 and h.get("no_new_evidence") is False for h in state.get("history",[])[-12:])
            if duplicate and d.get("action_class")!="inspect_artifact": self._block(state,"semantic_evidence_question_already_answered",d); self.current_step+=1; continue
            logger.info("[*] Paso %d/%s | %s | %s",self.current_step,MAX_STEPS or "∞",d.get("action_class","action"),d["command"])
            if not CommandSanitizer.validate_command_safety(d["command"]): self._block(state,"execution_policy_rejected",d); return
            entry=self._execute(state,d); ps=dict(state.get("planner_state") or {}); streak=int(ps.get("no_progress_streak",0)); streak=streak+1 if entry.get("no_new_evidence") else 0
            ps.update({"status":"NO_PROGRESS" if entry.get("no_new_evidence") else "PROGRESS","no_progress_streak":streak,"last_reason":"no_new_evidence" if entry.get("no_new_evidence") else "new_evidence"})
            reasoning=self.reasoning.update(entry.get("output",""),state.get("history",[])+[entry])
            self.state_manager.save_state(self.current_step,entry,phase=entry.get("action_class","autonomous"),mission_complete=False,extra={"planner_state":ps,"reasoning":reasoning,"last_action":{k:entry.get(k) for k in ("action_class","goal_id","hypothesis_id","evidence_question","resource")}})
            if streak>=MAX_NO_PROGRESS_STREAK: logger.error("[!] Progress budget exhausted; stopping safely."); return
            self.current_step+=1; time.sleep(1)

if __name__=="__main__":
    if len(sys.argv)<2: raise SystemExit("Usage: python main.py <target>")
    EnterpriseDynamicAgent(sys.argv[1]).run_autonomous_loop()
