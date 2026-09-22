import json, logging, os, re
import httpx
logger=logging.getLogger("EnterpriseDynamicAgent")

class CommandSanitizer:
    BLOCKED_PATTERNS=(r"(^|\s)rm\s+-rf\s+/(?:\s|$)",r"(^|\s)mkfs(?:\s|$)",r"(^|\s)shutdown(?:\s|$)",r"(^|\s)reboot(?:\s|$)",r"(^|\s)poweroff(?:\s|$)",r":\(\)\s*\{",r">\s*/dev/(?:sd|nvme)",r"dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/")
    @classmethod
    def clean(cls,command): return re.sub(r"\s+"," ",re.sub(r"[\x00-\x1f\x7f]"," ",str(command or ""))).strip()
    @classmethod
    def validate_command_safety(cls,command):
        text=cls.clean(command)
        return bool(text) and len(text)<=12000 and not any(re.search(p,text,re.I) for p in cls.BLOCKED_PATTERNS)

class LLMDecisionEngine:
    """Generic evidence-driven planner; no benchmark-specific playbook or fallback."""
    def __init__(self):
        self.api_key=os.environ.get("OPENAI_API_KEY","").strip()
        self.base_url=os.environ.get("OPENAI_API_BASE","https://api.x.ai/v1").strip()
        self.model_name=os.environ.get("MODEL_NAME","grok-3").strip()
    def plan(self,target,context):
        if not self.api_key: logger.error("OPENAI_API_KEY is not configured."); return {}
        prompt=("You are the tactical planner of an autonomous authorized security assessment agent. "
                "Use only the supplied world model. Never assume a benchmark, hostname, share, account, credential, exploit or attack path absent from it. "
                "Do not follow a fixed playbook. Maintain competing hypotheses, choose the action with the highest expected information gain relative to cost, and adapt after every observation. "
                "A successful command is not proof that a goal is complete; the evidence question must be sufficiently answered. "
                "Return ONLY JSON with fields thought, action_class, goal_id, hypothesis_id, evidence_question, resource, command, mission_complete. "
                "mission_complete is true only with explicit flag evidence. Potential vulnerability metadata is advisory only. Do not invent output or credentials.")
        payload={"model":self.model_name,"messages":[{"role":"system","content":prompt},{"role":"user","content":f"Target: {target}\nWorld model:\n{json.dumps(context,ensure_ascii=False,indent=2)}"}],"temperature":float(os.getenv("AGENT_LLM_TEMPERATURE","0.35"))}
        try:
            with httpx.Client(timeout=90) as c:
                r=c.post(f"{self.base_url}/chat/completions",json=payload,headers={"Authorization":f"Bearer {self.api_key}","Content-Type":"application/json"})
            r.raise_for_status(); content=r.json()["choices"][0]["message"]["content"].replace(String.fromCharCode(96),"").strip()
            data=json.loads(content); return data if isinstance(data,dict) else {}
        except Exception as exc:
            logger.error("Planner failure: %s",exc); return {}
