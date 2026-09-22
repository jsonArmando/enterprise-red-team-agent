import json, logging, os, subprocess
from pathlib import Path
from core.security import redact_secrets
logger=logging.getLogger("EnterpriseDynamicAgent")
class StateManager:
    def __init__(self,target_ip):
        self.target_ip=target_ip; self.state_dir=Path(f"testing/{target_ip}"); self.scans_dir=self.state_dir/"scans"; self.loot_dir=self.state_dir/"loot"
        self.state_dir.mkdir(parents=True,exist_ok=True); self.scans_dir.mkdir(exist_ok=True); self.loot_dir.mkdir(exist_ok=True); self.state_file=self.state_dir/"agent_state.json"
    def update_etc_hosts(self,domain_name,hostnames=None):
        if not domain_name:return
        hostnames=hostnames or [domain_name,f"dc.{domain_name}","dc"]; line=f"{self.target_ip} {' '.join(hostnames)}"
        try:
            content=Path("/etc/hosts").read_text(encoding="utf-8")
            if self.target_ip in content and domain_name in content:return
            pwd=os.getenv("SUDO_PASS")
            if not pwd:return
            r=subprocess.run(["sudo","-S","tee","-a","/etc/hosts"],input=f"{pwd}\n{line}\n",capture_output=True,text=True,check=False)
            if r.returncode:logger.error("[-] hosts update failed: %s",r.stderr)
        except Exception as e:logger.error("[-] hosts exception: %s",e)
    def save_state(self,step,history_entry,phase="recon",mission_complete=False,discovered_services=None,vulnerabilities=None,credentials=None,extra=None):
        old=self.load_state(); history=old.get("history",[]); history.append(history_entry)
        data={**old,"target":self.target_ip,"phase":phase,"step_count":step,"mission_complete":mission_complete,"last_output":history_entry.get("output",""),"history":history,
              "discovered_services":discovered_services if discovered_services is not None else old.get("discovered_services",[]),
              "vulnerabilities":vulnerabilities if vulnerabilities is not None else old.get("vulnerabilities",[]),
              "credentials":credentials if credentials is not None else old.get("credentials",[])}
        if extra:data.update(extra)
        self._atomic_write(redact_secrets(data), self.state_file)
    def mark_complete(self,reason,step):
        data={**self.load_state(),"step_count":step,"mission_complete":True,"completion_reason":reason}
        self._atomic_write(redact_secrets(data), self.state_file)
    @staticmethod
    def _atomic_write(data,path):
        tmp=path.with_suffix(".json.tmp"); tmp.write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding="utf-8"); tmp.replace(path)
    def load_state(self):
        if self.state_file.exists():
            try:
                d=json.loads(self.state_file.read_text(encoding="utf-8"))
                d.setdefault("history",[]); d.setdefault("completed_actions",[]); d.setdefault("action_attempts",{}); d.setdefault("mission_complete",False)
                d.setdefault("planner_state",{"status":"READY","stalled_attempts":0,"blocked_goals":[],"blocked_actions":[],"recovery_attempts":[],"last_reason":"","no_progress_streak":0})
                return d
            except Exception as e:logger.error("[-] state read: %s",e)
        return {"target":self.target_ip,"phase":"recon","step_count":0,"mission_complete":False,"last_output":"","history":[],"discovered_services":[],"vulnerabilities":[],"credentials":[],"completed_actions":[],"action_attempts":{},"planner_state":{"status":"READY","stalled_attempts":0,"blocked_goals":[],"blocked_actions":[],"recovery_attempts":[],"last_reason":"","no_progress_streak":0}}
def get_target_dir(target):
    p=Path(f"testing/{target}"); p.mkdir(parents=True,exist_ok=True); (p/"scans").mkdir(exist_ok=True); (p/"loot").mkdir(exist_ok=True); return str(p)
def save_persistent_state(state):
    target=state.get("target") or state.get("mission_target")
    if not target:return
    p=Path(get_target_dir(target))/"agent_state.json"; tmp=p.with_suffix(".json.tmp"); tmp.write_text(json.dumps(redact_secrets(state),indent=2,ensure_ascii=False),encoding="utf-8"); tmp.replace(p)
def save_loot(target,name,content):
    safe_name=Path(name).name
    (Path(get_target_dir(target))/"loot"/safe_name).write_text(redact_secrets(content),encoding="utf-8")
