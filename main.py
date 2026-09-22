import hashlib, json, logging, os, re, shlex, sys, time
from pathlib import Path
from typing import Optional
from core.reasoning import ReasoningState
from core.action_policy import ActionPolicy
from core.world_model import WorldModel
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

    def _action_signature(self, decision):
        command = CommandSanitizer.clean(str(decision.get("command") or ""))
        return {
            "intent": ReasoningState.action_intent(command),
            "action_class": self._norm(decision.get("action_class")),
            "resource": self._norm(decision.get("resource")),
            "command": self._norm(command),
        }

    def _recent_blocked_actions(self,state):
        blocked=[]
        for h in state.get("history",[])[-20:]:
            if h.get("event_type")!="action" or h.get("returncode")!=0:
                continue
            if h.get("no_new_evidence") is True:
                blocked.append({
                    "intent": ReasoningState.action_intent(h.get("command","")),
                    "action_class": self._norm(h.get("action_class")),
                    "resource": self._norm(h.get("resource")),
                    "command": self._norm(h.get("command")),
                    "reason": "previous successful action produced no new evidence",
                })
        return blocked[-12:]

    def _is_sterile_repeat(self,state,decision):
        sig=self._action_signature(decision)
        for h in reversed(state.get("history",[])[-20:]):
            if h.get("event_type")!="action" or h.get("returncode")!=0:
                continue
            prior={"intent":ReasoningState.action_intent(h.get("command","")),"action_class":self._norm(h.get("action_class")),"resource":self._norm(h.get("resource")),"command":self._norm(h.get("command"))}
            if sig["command"]==prior["command"]:
                return True
            if sig["intent"]==prior["intent"] and sig["resource"]==prior["resource"] and h.get("no_new_evidence") is True:
                return True
        return False

    def _context(self,state):
        world=WorldModel(state).snapshot()
        actions=[h for h in state.get("history",[]) if h.get("event_type")=="action"][-12:]
        recent=[{k:h.get(k) for k in ("step","action_class","goal_id","hypothesis_id","evidence_question","resource","command","returncode","evidence_delta","capability_delta","no_new_evidence","evidence_question_key","command_key")} for h in actions[-16:]]
        ldap_actions=[h for h in actions if ReasoningState.action_intent(h.get("command","")).startswith("enumerate_ldap:")]
        ldap_low_info=sum(1 for h in ldap_actions if h.get("no_new_evidence") is True)
        smb_available="smb_surface" in world.get("capabilities",[]) or "smb_access" in world.get("capabilities",[])
        rotate=bool(smb_available and len(ldap_actions)>=3 and ldap_low_info>=2)
        constraints={
            "rotate_surface": rotate,
            "reason": "LDAP family is saturated: recent LDAP actions produced low information. Switch to an observed alternative surface." if rotate else "",
            "available_alternative_surfaces": ["SMB/remote resources"] if smb_available else [],
            "recent_ldap_actions": len(ldap_actions),
            "recent_ldap_low_information": ldap_low_info
        }
        return {"world":world,"recent_actions":recent,"selection_constraints":constraints,"mission":{"complete":bool(state.get("mission_complete")),"progress_streak":int((state.get("planner_state") or {}).get("no_progress_streak",0))}}
    def _block(self,state,reason,decision=None):
        decision=decision or {}
        logger.warning("[!] Planner rejection: %s | action_class=%s | resource=%s | command=%s", reason, decision.get("action_class",""), decision.get("resource",""), decision.get("command",""))
        entry={"event_type":"planner_rejection","step":self.current_step,"reason":reason,"decision":decision}
        self.state_manager.save_state(self.current_step,entry,phase="planning",mission_complete=False,extra={"planner_state":{**dict(state.get("planner_state") or {}),"last_reason":reason}})

    def _initial(self):
        p=self.scan_path()
        if p.exists(): return None
        p.parent.mkdir(parents=True,exist_ok=True)
        return {"action_class":"discover_services","goal_id":"discover_services","hypothesis_id":"","evidence_question":"What services, protocols and exposed surfaces are present on the target?","resource":self.target,"command":f"nmap -sV -sC -oN {shlex.quote(str(p))} {shlex.quote(self.target)}","mission_complete":False}

    def _plan(self,state):
        context=self._context(state)
        for _ in range(MAX_PLANNER_RETRIES):
            raw=self.planner.plan(self.target,context)
            if not isinstance(raw,dict):
                self._block(state,"planner_non_object"); continue
            candidates=raw.get("candidates")
            if not isinstance(candidates,list):
                candidates=[raw] if raw.get("command") else []
            if raw.get("mission_complete"):
                if self.flags_found(): return raw
                self._block(state,"mission_complete_without_flag",raw); continue
            hypotheses=context["world"].get("hypotheses",[])
            goals=context["world"].get("candidate_goals",[])
            valid_h={str(h.get("id")) for h in hypotheses if h.get("id")}
            valid_g={str(g.get("id")) for g in goals if g.get("id")}
            constraints=context.get("selection_constraints",{})
            accepted=[]
            seen_intents=set()
            for candidate in candidates[:6]:
                if not isinstance(candidate,dict): continue
                d=dict(candidate)
                d["command"]=CommandSanitizer.clean(str(d.get("command") or ""))
                if not d["command"] or not CommandSanitizer.validate_command_safety(d["command"]):
                    self._block(state,"candidate_execution_policy_rejected",d); continue
                required=("action_class","evidence_question","hypothesis_id","evidence_basis")
                if any(not str(d.get(k) or "").strip() for k in required):
                    self._block(state,"candidate_missing_reasoning_fields",d); continue
                hid=str(d.get("hypothesis_id") or "")
                gid=str(d.get("goal_id") or "")
                if valid_h and hid not in valid_h:
                    self._block(state,"candidate_unknown_hypothesis",d); continue
                if valid_g and gid and gid not in valid_g:
                    self._block(state,"candidate_unknown_goal",d); continue
                intent=ReasoningState.action_intent(d["command"])
                if intent in seen_intents:
                    self._block(state,"candidate_semantic_duplicate",d); continue
                seen_intents.add(intent)
                if constraints.get("rotate_surface") and intent.startswith("enumerate_ldap:"):
                    self._block(state,"surface_rotation_required",d); continue
                decision=ActionPolicy(state.get("history",[])).evaluate(d)
                if not decision["allowed"]:
                    self._block(state,decision["reason"],d); continue
                d["evidence_question_key"]=decision["question_key"]
                d["command_key"]=ActionPolicy.command_key(d["command"])
                d["novelty"]=1.0
                accepted.append(d)
            if accepted:
                ranked=ActionPolicy(state.get("history",[])).rank(accepted)
                selected=ranked[0]
                selected["_planner_latency_ms"]=raw.get("_planner_latency_ms")
                logger.info("[?] Candidates=%d accepted=%d | selected=%s | intent=%s | gain=%s | cost=%s | hypothesis=%s | question=%s | rationale=%s",
                            len(candidates),len(accepted),selected.get("action_class",""),ReasoningState.action_intent(selected["command"]),
                            selected.get("expected_information_gain","?"),selected.get("cost","?"),
                            selected.get("hypothesis_id",""),selected.get("evidence_question",""),selected.get("rationale",""))
                return selected
            self._block(state,"no_evidence_grounded_candidate",{"candidate_count":len(candidates)})
        return None
    def _execute(self,state,d):
        before=self._world(state); started=time.monotonic(); r=self.executor.execute_with_polling(d["command"]); execution_ms=round((time.monotonic()-started)*1000); output=r.get("stdout","")
        if r.get("stderr"): output+="\nSTDERR:\n"+r["stderr"]
        provisional={"event_type":"action","step":self.current_step,"evidence_question_key":d.get("evidence_question_key") or ActionPolicy.question_key(d),"command_key":d.get("command_key") or ActionPolicy.command_key(d["command"]),"action_class":d.get("action_class","unspecified"),"goal_id":d.get("goal_id",""),"hypothesis_id":d.get("hypothesis_id",""),"evidence_question":d.get("evidence_question",""),"resource":d.get("resource",""),"command":d["command"],"output":output[:8000],"returncode":r.get("returncode"),"status":r.get("status"),"planner_latency_ms":d.get("_planner_latency_ms"),"execution_latency_ms":execution_ms}
        after_reasoning=self.reasoning.update(output,state.get("history",[])+[provisional],d.get("command", ""))
        after={"facts":after_reasoning.get("facts",[]),"capabilities":after_reasoning.get("capabilities",[]),"hypotheses":after_reasoning.get("hypotheses",[])}
        oldf={str(x).lower() for x in before.get("facts",[])}; newf={str(x).lower() for x in after.get("facts",[])}; oldc={str(x).lower() for x in before.get("capabilities",[])}; newc={str(x).lower() for x in after.get("capabilities",[])}
        oldh={h.get("id"):h.get("confidence") for h in before.get("hypotheses",[]) if h.get("id")}; conf=0.0
        for h in after.get("hypotheses",[]):
            if h.get("id") in oldh and isinstance(h.get("confidence"),(int,float)) and isinstance(oldh[h.get("id")],(int,float)): conf+=abs(float(h["confidence"])-float(oldh[h.get("id")]))
        delta={"fact_delta":len(newf-oldf),"capability_delta":len(newc-oldc),"hypothesis_confidence_delta":round(conf,4),"output_digest":self._digest(output) if output else ""}
        progress=delta["fact_delta"]>0 or delta["capability_delta"]>0 or delta["hypothesis_confidence_delta"]>0.05
        provisional.update({"evidence_delta":delta,"capability_delta":delta["capability_delta"],"no_new_evidence":not progress,"output_digest":delta["output_digest"]})
        logger.info("[=] Evidence | exec=%sms | rc=%s | facts+%s | capabilities+%s | hypothesis_delta=%s | progress=%s | digest=%s", execution_ms, r.get("returncode"), delta["fact_delta"], delta["capability_delta"], delta["hypothesis_confidence_delta"], progress, delta["output_digest"])
        return provisional

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
            logger.info("[*] Paso %d/%s | %s | %s",self.current_step,MAX_STEPS or "∞",d.get("action_class","action"),d["command"])
            if not CommandSanitizer.validate_command_safety(d["command"]): self._block(state,"execution_policy_rejected",d); return
            entry=self._execute(state,d); ps=dict(state.get("planner_state") or {}); streak=int(ps.get("no_progress_streak",0)); streak=streak+1 if entry.get("no_new_evidence") else 0
            ps.update({"status":"NO_PROGRESS" if entry.get("no_new_evidence") else "PROGRESS","no_progress_streak":streak,"last_reason":"no_new_evidence" if entry.get("no_new_evidence") else "new_evidence"})
            reasoning=self.reasoning.update(entry.get("output",""),state.get("history",[])+[entry],entry.get("command", ""))
            self.state_manager.save_state(self.current_step,entry,phase=entry.get("action_class","autonomous"),mission_complete=False,extra={"planner_state":ps,"reasoning":reasoning,"last_action":{k:entry.get(k) for k in ("action_class","goal_id","hypothesis_id","evidence_question","resource")}})
            if streak>=MAX_NO_PROGRESS_STREAK: logger.error("[!] Progress budget exhausted; stopping safely."); return
            self.current_step+=1; time.sleep(1)

if __name__=="__main__":
    if len(sys.argv)<2: raise SystemExit("Usage: python main.py <target>")
    EnterpriseDynamicAgent(sys.argv[1]).run_autonomous_loop()
