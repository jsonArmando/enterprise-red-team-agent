import base64, hashlib, json, logging, os, re, shlex, shutil, subprocess, sys, time
from pathlib import Path
from typing import Any, Dict, List, Optional
from core.reasoning import ReasoningState
from core.action_policy import ActionPolicy
from core.world_model import WorldModel
from core.state_manager import StateManager
from core.policy_engine import evaluate_policy
from utils.smart_executor import SmartCommandExecutor
from nodes.dynamic_agent import CommandSanitizer, LLMDecisionEngine, LLMHypothesisEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger=logging.getLogger("EnterpriseDynamicAgent")
MAX_STEPS=int(os.getenv("AGENT_MAX_STEPS","0")) or None
MAX_NO_PROGRESS_STREAK=int(os.getenv("AGENT_MAX_NO_PROGRESS","25"))
MAX_PLANNER_RETRIES=int(os.getenv("AGENT_MAX_PLANNER_RETRIES","3"))
ARTIFACT_EXTENSIONS={".xml",".txt",".json",".ini",".conf",".config",".yaml",".yml",".log"}

# --- Flag recognition -------------------------------------------------------
# HTB flags are bare 32-hex tokens (no flag{}/htb{} wrapper). A naive 32-hex
# scan over all stdout would collide with NTLM hashes and Kerberos TGS blobs,
# so hex detection in command output is deliberately bound to a flag-file
# context (the command must reference user.txt/root.txt/proof.txt/flag.txt).
FLAG_FILE_NAMES={"user.txt","root.txt","proof.txt","flag.txt","flags.json","user.flag","root.flag"}
FLAG_BRACE=re.compile(r"(?:flag|htb)\{[^}]{4,400}\}",re.I)
FLAG_HEX32=re.compile(r"\b[a-f0-9]{32}\b",re.I)
FLAG_FILE_REF=re.compile(r"\b(?:user|root|proof|flag)\.txt\b",re.I)

# --- Environment preflight --------------------------------------------------
# Advisory (non-fatal) presence checks for the toolchain an AD assessment
# typically needs. Missing tools are logged so a run that later fails on a
# missing binary is diagnosable up front rather than as an opaque returncode.
REQUIRED_TOOLS=("nmap","smbclient","ldapsearch")
OPTIONAL_TOOLS=("nxc","netexec","crackmapexec","rpcclient","enum4linux","kerbrute",
                "gpp-decrypt","hashcat","john","impacket-GetUserSPNs","GetUserSPNs.py",
                "impacket-wmiexec","wmiexec.py","evil-winrm")
DEFAULT_WORDLIST=os.getenv("AGENT_WORDLIST","/usr/share/wordlists/rockyou.txt")


def _load_knowledge_base() -> str:
    """Concatenate knowledge_base/*.md as advisory tactics for the hypothesis
    engine (RAG-lite). Missing directory is fine."""
    kb = Path(__file__).resolve().parent / "knowledge_base"
    if not kb.is_dir():
        return ""
    chunks = []
    for p in sorted(kb.glob("*.md")):
        try:
            chunks.append(p.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
    return "\n\n".join(chunks)


def preflight_dependencies() -> Dict[str, List[str]]:
    """Report which expected tools/wordlists are resolvable on PATH.

    Never fatal: the planner is free to use whatever is installed, and the
    operator may run a subset of the chain.
    """
    missing_required=[t for t in REQUIRED_TOOLS if not shutil.which(t)]
    missing_optional=[t for t in OPTIONAL_TOOLS if not shutil.which(t)]
    wordlist_ok=Path(DEFAULT_WORDLIST).is_file()
    if missing_required:
        logger.warning("[preflight] Missing REQUIRED tools: %s", ", ".join(missing_required))
    if missing_optional:
        logger.info("[preflight] Optional tools not found (chain may be limited): %s", ", ".join(missing_optional))
    if not wordlist_ok:
        logger.warning("[preflight] Wordlist not found at %s (set AGENT_WORDLIST)", DEFAULT_WORDLIST)
    else:
        logger.info("[preflight] Wordlist available: %s", DEFAULT_WORDLIST)
    return {"missing_required":missing_required,"missing_optional":missing_optional,
            "wordlist_ok":[DEFAULT_WORDLIST] if wordlist_ok else []}


# --- GPP credential harvesting ---------------------------------------------
# Microsoft published the static AES-256 key used to encrypt Group Policy
# Preferences cpasswords (MS-GPPREF 2.2.1.1.4), so decryption is deterministic.
# Doing it in-process avoids the planner reinventing broken AES and looping.
GPP_AES_KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
CPASSWORD_RE = re.compile(r'cpassword\s*=\s*"([^"]*)"', re.I)
GPP_USERNAME_RE = re.compile(r'(?:userName|runAs|name)\s*=\s*"([^"]+)"', re.I)


def decrypt_gpp_cpassword(cpassword: str):
    """Decrypt a GPP cpassword to plaintext. Returns None on failure.

    Tries in-process AES first (pycryptodome), then the `gpp-decrypt` CLI.
    """
    cpassword = (cpassword or "").strip()
    if not cpassword:
        return None
    padded = cpassword + "=" * ((4 - len(cpassword) % 4) % 4)
    try:
        blob = base64.b64decode(padded)
        try:
            from Crypto.Cipher import AES  # pycryptodome
        except ImportError:
            from Cryptodome.Cipher import AES
        raw = AES.new(GPP_AES_KEY, AES.MODE_CBC, b"\x00" * 16).decrypt(blob)
        if raw and raw[-1] <= 16:  # strip PKCS#7 padding
            raw = raw[:-raw[-1]]
        text = raw.decode("utf-16-le", errors="ignore").strip("\x00").strip()
        if text:
            return text
    except Exception as exc:
        logger.debug("[gpp] in-process decrypt failed: %s", exc)
    if shutil.which("gpp-decrypt"):
        try:
            r = subprocess.run(["gpp-decrypt", cpassword], capture_output=True, text=True, timeout=30)
            out = (r.stdout or "").strip().splitlines()
            if out:
                return out[-1].strip()
        except Exception as exc:
            logger.debug("[gpp] gpp-decrypt CLI failed: %s", exc)
    return None

class EnterpriseDynamicAgent:
    """Single autonomous runtime. No target-specific attack path lives here."""
    def __init__(self,target:str,domain_name:Optional[str]=None):
        if not evaluate_policy(target):
            raise PermissionError(f"Target '{target}' is outside the authorized scope. Aborting before any command runs.")
        self.target=target; self.domain_name=domain_name; self.state_manager=StateManager(target)
        # Absolute anchors so child-process cwd can be pinned to loot/ (Patch 2)
        # without breaking the agent's own state/scan bookkeeping.
        self.target_root=Path(f"testing/{target}").resolve()
        self.scans_dir=self.target_root/"scans"; self.loot_dir=self.target_root/"loot"
        self.loot_dir.mkdir(parents=True,exist_ok=True); self.scans_dir.mkdir(parents=True,exist_ok=True)
        state=self.state_manager.load_state(); self.current_step=int(state.get("step_count",0))+1
        self.executor=SmartCommandExecutor(timeout_minutes=int(os.getenv("AGENT_COMMAND_TIMEOUT_MINUTES","20")),poll_interval=int(os.getenv("AGENT_POLL_INTERVAL","15")))
        self.planner=LLMDecisionEngine()
        # Domain-agnostic reasoning: the LLM proposes hypotheses for ANY target
        # type; static AD templates remain only as an offline fallback.
        ReasoningState.set_hypothesis_engine(LLMHypothesisEngine(knowledge=_load_knowledge_base()))
        self.reasoning=ReasoningState(state)

    @staticmethod
    def _digest(value): return hashlib.sha256(value.encode("utf-8",errors="ignore")).hexdigest()[:16]
    @staticmethod
    def _norm(value): return re.sub(r"\s+"," ",str(value or "").strip())
    def scan_path(self): return self.scans_dir/"recon.txt"

    def _harvest_credentials(self, state: Dict[str, Any]) -> bool:
        """Deterministically decrypt any GPP cpassword found in loot and inject
        the resulting credential as a `valid_cred:` fact.

        This closes the gap where the planner would otherwise loop trying to
        hand-roll AES. Reads cpasswords straight from the loot files on disk
        (unredacted), so it is independent of what the LLM copied. Returns True
        when a new credential was added (i.e. real progress)."""
        reasoning=dict(state.get("reasoning") or {})
        facts=list(reasoning.get("facts",[]))
        have={f.split("%",1)[0] for f in facts if isinstance(f,str) and f.startswith("valid_cred:")}
        added=[]
        if not self.loot_dir.exists(): return False
        for p in self.loot_dir.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in {".xml",".txt",".ini"}: continue
            try:
                if p.stat().st_size>2_000_000: continue
                content=p.read_text(encoding="utf-8",errors="ignore")
            except (OSError,UnicodeError): continue
            for cpw in CPASSWORD_RE.findall(content):
                if not cpw.strip(): continue  # empty cpassword = no stored secret
                plain=decrypt_gpp_cpassword(cpw)
                if not plain: continue
                um=GPP_USERNAME_RE.search(content)
                user=(um.group(1) if um else "").strip() or "UNKNOWN"
                fact=f"valid_cred: {user}%{plain}"
                key=f"valid_cred: {user}"
                if key in have or fact in facts: continue
                facts.append(fact); added.append(fact); have.add(key)
                logger.info("[+] GPP credential recovered: %s (source=%s)", user, p.name)
        if not added: return False
        reasoning["facts"]=facts[-256:]
        caps=list(reasoning.get("capabilities",[]))
        if "authenticated_identity" not in caps: caps.append("authenticated_identity")
        reasoning["capabilities"]=caps
        entry={"event_type":"credential_harvest","step":self.current_step,"credentials":added,
               "output":"\n".join(added),"returncode":0,"no_new_evidence":False,"action_class":"harvest_credentials"}
        self.state_manager.save_state(self.current_step,entry,phase="credential_harvest",mission_complete=False,extra={"reasoning":reasoning})
        return True

    @staticmethod
    def _extract_flag_token(text: str) -> Optional[str]:
        """Return a normalized flag token from text, brace form first."""
        m=FLAG_BRACE.search(text or "")
        if m: return m.group(0)
        m=FLAG_HEX32.search(text or "")
        return m.group(0) if m else None

    def _flags_from_filesystem(self) -> List[str]:
        found=[]
        if not self.target_root.exists(): return found
        for p in self.target_root.rglob("*"):
            if not p.is_file(): continue
            try:
                if p.stat().st_size>2_000_000: continue
                content=p.read_text(encoding="utf-8",errors="ignore")
            except (OSError,UnicodeError): continue
            token=self._extract_flag_token(content)
            # HTB flag files hold exactly one 32-hex line; accept that shape too.
            stripped=content.strip()
            if p.name.lower() in FLAG_FILE_NAMES and (token or FLAG_HEX32.fullmatch(stripped)):
                found.append(f"{p}::{token or stripped}"); continue
            if FLAG_BRACE.search(content):
                found.append(f"{p}::{token}"); continue
            if FLAG_HEX32.fullmatch(stripped):  # a file whose whole body is a flag
                found.append(f"{p}::{stripped}")
        return found

    def _flags_from_history(self, state: Dict[str, Any]) -> List[str]:
        """Detect flags printed to stdout. Bare 32-hex is only trusted when the
        producing command referenced a flag file, which avoids treating NTLM
        hashes / Kerberos TGS material as flags."""
        found=[]
        for h in state.get("history",[]):
            if h.get("event_type")!="action": continue
            out=str(h.get("output","")); cmd=str(h.get("command",""))
            brace=FLAG_BRACE.search(out)
            if brace:
                found.append(f"stdout(step {h.get('step')})::{brace.group(0)}"); continue
            ref=FLAG_FILE_REF.search(cmd)
            if ref:
                hexm=FLAG_HEX32.search(out)
                if hexm:
                    # tag with the referenced flag filename so user/root can be told apart
                    found.append(f"stdout {ref.group(0)} (step {h.get('step')})::{hexm.group(0)}")
        return found

    def flags_found(self, state: Optional[Dict[str, Any]]=None) -> List[str]:
        found=list(self._flags_from_filesystem())
        if state is not None:
            found.extend(self._flags_from_history(state))
        return sorted(set(found))

    def _artifacts(self):
        if not self.loot_dir.exists(): return []
        out=[]
        for p in self.loot_dir.rglob("*"):
            if p.is_file() and p.name!="potential_exploits.json" and p.suffix.lower() in ARTIFACT_EXTENSIONS:
                try:
                    if p.stat().st_size<=2_000_000: out.append(p)
                except OSError: pass
        return out

    def _next_artifact(self,state):
        inspected=set()
        for h in state.get("history",[]):
            if h.get("event_type")=="action" and h.get("action_class")=="inspect_artifact":
                inspected.add(self._norm(h.get("resource")))
        candidates=[]
        for p in self._artifacts():
            keys={self._norm(str(p)),self._norm(os.path.relpath(p,self.loot_dir))}
            try: keys.add(self._norm(os.path.relpath(p,Path.cwd())))
            except ValueError: pass
            if not (keys & inspected): candidates.append(p)
        if not candidates: return None
        p=max(candidates,key=lambda x:(x.stat().st_mtime,x.stat().st_size)); resource=str(p)
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
        workspace={
            "cwd_note":"Commands run with their working directory set to the loot directory below. Write downloads and tool artifacts using RELATIVE filenames; they are persisted and auto-inspected next iteration.",
            "loot_dir":str(self.loot_dir),
            "scans_dir":str(self.scans_dir),
            "wordlist":DEFAULT_WORDLIST,
            "execution_note":"Execution is strictly non-interactive (stdin is closed). Always pass explicit auth flags (e.g. -N / --no-pass / user:pass@host); never rely on a password prompt.",
        }
        return {"world":world,"recent_actions":recent,"selection_constraints":constraints,"workspace":workspace,"mission":{"complete":bool(state.get("mission_complete")),"progress_streak":int((state.get("planner_state") or {}).get("no_progress_streak",0))}}
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

    def _candidate_grounded(self,d,context):
        world=context.get("world",{})
        serialized=json.dumps(world,ensure_ascii=False).lower()
        basis=self._norm(d.get("evidence_basis"))
        if not basis:
            return False,"missing_evidence_basis"
        tokens=[t for t in re.findall(r"[a-z0-9_./=-]{5,}",basis.lower()) if t not in {"observed","evidence","resource","facts","capability"}]
        if tokens and not any(t in serialized for t in tokens):
            return False,"evidence_basis_not_grounded"
        intent=ReasoningState.action_intent(d.get("command",""))
        caps={str(x).lower() for x in world.get("capabilities",[])}
        if intent.startswith("enumerate_ldap:") and "ldap_visibility" not in caps:
            return False,"ldap_surface_not_observed"
        if intent.startswith("inspect_smb_resource:") or intent.startswith("retrieve_remote_artifact:"):
            if "smb_surface" not in caps and "smb_access" not in caps:
                return False,"smb_surface_not_observed"
        hid=str(d.get("hypothesis_id") or "")
        hypotheses={str(h.get("id")):h for h in world.get("hypotheses",[]) if h.get("id")}
        if hid not in hypotheses:
            return False,"hypothesis_not_observed"
        # NOTE: the goal<->hypothesis binding is intentionally NOT enforced as a
        # hard reject. Requiring goal.source_hypothesis == hypothesis_id starved
        # legitimate pivots (LDAP/RPC) whose goal was generated under a sibling
        # hypothesis. Scope, evidence-basis and surface-observed checks above
        # remain the real gates; goal coherence is left to ranking.
        return True,"grounded"

    def _recent_failed_intent(self,state,intent) -> int:
        """Count recent actions with the same semantic intent that FAILED
        (returncode != 0). Used to force a pivot instead of hammering an
        approach that keeps erroring (the planner varies flags/paths so
        command-key dedup alone misses these)."""
        n=0
        for h in state.get("history",[])[-30:]:
            if h.get("event_type")!="action": continue
            if h.get("returncode") in (0,None): continue
            if ReasoningState.action_intent(h.get("command",""))==intent: n+=1
        return n

    @staticmethod
    def _known_identity(context) -> bool:
        """True if a concrete username/credential has been observed, which is
        what justifies a large brute-force. Blind rockyou runs against an
        unknown user are blocked otherwise (they burned hours for nothing)."""
        world=context.get("world",{})
        for f in world.get("facts",[]):
            if str(f).startswith("valid_cred:"): return True
        if "authenticated_identity" in {str(c).lower() for c in world.get("capabilities",[])}:
            return True
        ents=world.get("entities",{}) or {}
        return bool(ents.get("identities"))

    def _plan(self,state):
        context=self._context(state)
        # Autonomy guard: if we have observed facts but no hypotheses yet
        # (stale state, or the engine was unavailable when evidence arrived),
        # regenerate hypotheses from current facts before grounding candidates,
        # so planning is never dead-locked by an empty hypothesis set.
        if not context["world"].get("hypotheses") and context["world"].get("facts"):
            try:
                refreshed=ReasoningState(state).update("", state.get("history",[]), "")
                if refreshed.get("hypotheses"):
                    merged=dict(state); merged["reasoning"]=refreshed
                    self.state_manager.save_state(self.current_step,{"event_type":"reasoning_refresh","step":self.current_step,"output":"","returncode":0,"no_new_evidence":True,"action_class":"reasoning_refresh"},phase="reasoning_refresh",mission_complete=False,extra={"reasoning":refreshed})
                    state=self.state_manager.load_state(); context=self._context(state)
                    logger.info("[~] Regenerated %d hypotheses from existing evidence.", len(refreshed.get("hypotheses",[])))
            except Exception as exc:
                logger.warning("[~] Hypothesis refresh failed: %s", exc)
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
                if CommandSanitizer.has_placeholder(d["command"]):
                    self._block(state,"candidate_has_unfilled_placeholder",d); continue
                if CommandSanitizer.is_blind_bruteforce(d["command"]) and not self._known_identity(context):
                    self._block(state,"blind_bruteforce_without_known_user",d); continue
                required=("action_class","evidence_question","hypothesis_id","evidence_basis")
                if any(not str(d.get(k) or "").strip() for k in required):
                    self._block(state,"candidate_missing_reasoning_fields",d); continue
                hid=str(d.get("hypothesis_id") or "")
                gid=str(d.get("goal_id") or "")
                if valid_h and hid not in valid_h:
                    self._block(state,"candidate_unknown_hypothesis",d); continue
                if valid_g and gid and gid not in valid_g:
                    self._block(state,"candidate_unknown_goal",d); continue
                grounded,ground_reason=self._candidate_grounded(d,context)
                if not grounded:
                    self._block(state,ground_reason,d); continue
                intent=ReasoningState.action_intent(d["command"])
                if intent in seen_intents:
                    self._block(state,"candidate_semantic_duplicate",d); continue
                seen_intents.add(intent)
                if self._recent_failed_intent(state,intent)>=3:
                    self._block(state,"repeated_failed_intent",d); continue
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
        # Patch 3: guarantee non-interactive execution. Child cwd is pinned to
        # loot/ (Patch 2) so any relative output file the tool writes is
        # captured and auto-inspected on the next iteration.
        d["command"]=CommandSanitizer.ensure_noninteractive(d["command"])
        before=self._world(state); started=time.monotonic(); r=self.executor.execute_with_polling(d["command"],cwd=str(self.loot_dir)); execution_ms=round((time.monotonic()-started)*1000); output=r.get("stdout","")
        if r.get("stderr"): output+="\nSTDERR:\n"+r["stderr"]
        provisional={"event_type":"action","step":self.current_step,"evidence_question_key":d.get("evidence_question_key") or ActionPolicy.question_key(d),"command_key":d.get("command_key") or ActionPolicy.command_key(d["command"]),"action_class":d.get("action_class","unspecified"),"goal_id":d.get("goal_id",""),"hypothesis_id":d.get("hypothesis_id",""),"evidence_question":d.get("evidence_question",""),"resource":d.get("resource",""),"command":d["command"],"output":output[:8000],"returncode":r.get("returncode"),"status":r.get("status"),"planner_latency_ms":d.get("_planner_latency_ms"),"execution_latency_ms":execution_ms}
        after_reasoning=self.reasoning.update(output,state.get("history",[])+[provisional],d.get("command", ""))
        after={"facts":after_reasoning.get("facts",[]),"capabilities":after_reasoning.get("capabilities",[]),"hypotheses":after_reasoning.get("hypotheses",[])}
        oldf={str(x).lower() for x in before.get("facts",[])}; newf={str(x).lower() for x in after.get("facts",[])}; oldc={str(x).lower() for x in before.get("capabilities",[])}; newc={str(x).lower() for x in after.get("capabilities",[])}
        oldh={h.get("id"):h.get("confidence") for h in before.get("hypotheses",[]) if h.get("id")}; conf=0.0
        for h in after.get("hypotheses",[]):
            if h.get("id") in oldh and isinstance(h.get("confidence"),(int,float)) and isinstance(oldh[h.get("id")],(int,float)): conf+=abs(float(h["confidence"])-float(oldh[h.get("id")]))
        delta={"fact_delta":len(newf-oldf),"capability_delta":len(newc-oldc),"hypothesis_confidence_delta":round(conf,4),"output_digest":self._digest(output) if output else ""}
        # Fix 1: real-progress accounting. Error-noise text was being counted as
        # "new facts", so failed/sterile commands looked like progress and the
        # no-progress budget never fired (10h runs). Now:
        #  - a repeated output_digest is never progress (identical output again),
        #  - a failed command (rc!=0) counts only on STRUCTURED gain (a new
        #    capability or a real hypothesis-confidence shift), not raw fact text.
        rc=r.get("returncode")
        prior_digests={h.get("output_digest") for h in state.get("history",[]) if h.get("output_digest")}
        digest_repeat=bool(delta["output_digest"]) and delta["output_digest"] in prior_digests
        structured=delta["capability_delta"]>0 or delta["hypothesis_confidence_delta"]>0.05
        if rc not in (0,None):
            progress=structured and not digest_repeat
        else:
            progress=(delta["fact_delta"]>0 or structured) and not digest_repeat
        provisional.update({"evidence_delta":delta,"capability_delta":delta["capability_delta"],"no_new_evidence":not progress,"output_digest":delta["output_digest"]})
        logger.info("[=] Evidence | exec=%sms | rc=%s | facts+%s | capabilities+%s | hypothesis_delta=%s | progress=%s | digest=%s", execution_ms, r.get("returncode"), delta["fact_delta"], delta["capability_delta"], delta["hypothesis_confidence_delta"], progress, delta["output_digest"])
        return provisional

    @staticmethod
    def _flag_kind(source: str) -> str:
        low=str(source or "").lower()
        if "root" in low or "proof" in low: return "root"
        if "user" in low: return "user"
        return "other"

    def _record_foothold(self, state, user_flags) -> bool:
        """Record a captured user flag without ending the mission, and steer the
        agent toward privilege escalation. Returns True only the first time (so
        it counts as progress and the planner then pivots to root)."""
        reasoning=dict(state.get("reasoning") or {})
        facts=list(reasoning.get("facts",[]))
        marker=f"captured_user_flag: {user_flags[0]}"
        if marker in facts:
            return False
        facts.append(marker)
        facts.append("objective: user flag captured; escalate privileges to Administrator/root and read root.txt")
        reasoning["facts"]=facts[-256:]
        caps=list(reasoning.get("capabilities",[]))
        if "needs_privilege_escalation" not in caps: caps.append("needs_privilege_escalation")
        reasoning["capabilities"]=caps
        entry={"event_type":"foothold","step":self.current_step,"output":marker,"returncode":0,
               "no_new_evidence":False,"action_class":"record_foothold"}
        self.state_manager.save_state(self.current_step,entry,phase="foothold",mission_complete=False,extra={"reasoning":reasoning})
        logger.info("[+] User flag captured (foothold): %s -- continuing to privilege escalation.", user_flags[0])
        return True

    def _handle_flags(self, state) -> str:
        """Return 'complete' (root/terminal flag -> stop), 'foothold' (only a
        user flag, newly recorded -> keep going), or 'none'."""
        flags=self.flags_found(state)
        if not flags: return "none"
        terminal=[f for f in flags if self._flag_kind(f)!="user"]
        if terminal:
            self.state_manager.mark_complete(f"flag_found:{terminal[0]}",self.current_step)
            logger.info("[+] ROOT/terminal flag detected -- mission complete: %s", terminal[0])
            return "complete"
        users=[f for f in flags if self._flag_kind(f)=="user"]
        if users and self._record_foothold(state,users):
            return "foothold"
        return "none"

    def run_autonomous_loop(self):
        preflight_dependencies()
        while MAX_STEPS is None or self.current_step<=MAX_STEPS:
            state=self.state_manager.load_state()
            if state.get("mission_complete"): return
            status=self._handle_flags(state)
            if status=="complete": return
            if status=="foothold":
                self.current_step+=1; continue  # pivot to privilege escalation
            if self._harvest_credentials(state):
                self.current_step+=1; continue  # let the planner act on the new credential
            d=self._next_artifact(state) or self._initial() or self._plan(state)
            if d is None: logger.error("[!] No valid action; stopping safely."); self._block(state,"no_valid_action"); return
            if d.get("mission_complete"):
                if self._handle_flags(state)=="complete": return
            logger.info("[*] Paso %d/%s | %s | %s",self.current_step,MAX_STEPS or "∞",d.get("action_class","action"),d["command"])
            if not CommandSanitizer.validate_command_safety(d["command"]): self._block(state,"execution_policy_rejected",d); return
            entry=self._execute(state,d); ps=dict(state.get("planner_state") or {}); streak=int(ps.get("no_progress_streak",0)); streak=streak+1 if entry.get("no_new_evidence") else 0
            ps.update({"status":"NO_PROGRESS" if entry.get("no_new_evidence") else "PROGRESS","no_progress_streak":streak,"last_reason":"no_new_evidence" if entry.get("no_new_evidence") else "new_evidence"})
            reasoning=self.reasoning.update(entry.get("output",""),state.get("history",[])+[entry],entry.get("command", ""))
            self.state_manager.save_state(self.current_step,entry,phase=entry.get("action_class","autonomous"),mission_complete=False,extra={"planner_state":ps,"reasoning":reasoning,"last_action":{k:entry.get(k) for k in ("action_class","goal_id","hypothesis_id","evidence_question","resource")}})
            # Root/terminal flag read to stdout this iteration ends the mission.
            if self._handle_flags(self.state_manager.load_state())=="complete": return
            if streak>=MAX_NO_PROGRESS_STREAK: logger.error("[!] Progress budget exhausted; stopping safely."); return
            self.current_step+=1; time.sleep(1)

if __name__=="__main__":
    if len(sys.argv)<2: raise SystemExit("Usage: python main.py <target>")
    try:
        EnterpriseDynamicAgent(sys.argv[1]).run_autonomous_loop()
    except PermissionError as exc:
        raise SystemExit(f"[-] {exc}")
