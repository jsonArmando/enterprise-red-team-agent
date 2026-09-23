import json, logging, os, re, time, time
import httpx
logger=logging.getLogger("EnterpriseDynamicAgent")

class CommandSanitizer:
    BLOCKED_PATTERNS=(r"(^|\s)rm\s+-rf\s+/(?:\s|$)",r"(^|\s)mkfs(?:\s|$)",r"(^|\s)shutdown(?:\s|$)",r"(^|\s)reboot(?:\s|$)",r"(^|\s)poweroff(?:\s|$)",r":\(\)\s*\{",r">\s*/dev/(?:sd|nvme)",r"dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/")
    # smbclient blocks on an interactive password prompt when no auth flag is
    # given; under closed stdin that manifests as an immediate failure. When
    # the planner supplies no explicit authentication, force an anonymous
    # (null) session so anonymous enumeration works headlessly.
    _SMB_AUTH_FLAGS=re.compile(r"(?:^|\s)(?:-N|--no-pass|-U\b|--user\b|-A\b|--authentication-file\b|-k\b|--kerberos\b|-P\b|--machine-pass\b)")
    @classmethod
    def clean(cls,command): return re.sub(r"\s+"," ",re.sub(r"[\x00-\x1f\x7f]"," ",str(command or ""))).strip()
    @classmethod
    def ensure_noninteractive(cls,command):
        """Make headless-safe adjustments without altering intent.

        Only smbclient invocations that carry no authentication flag are
        touched, by inserting -N (anonymous). Everything else is returned
        unchanged; broad auto-injection is intentionally avoided so the
        planner keeps full control of authenticated commands.
        """
        text=cls.clean(command)
        if not text: return text
        if re.search(r"(?:^|\s)smbclient(?:\s|$)",text) and not cls._SMB_AUTH_FLAGS.search(text):
            text=re.sub(r"((?:^|\s)smbclient)(\s)",r"\1 -N\2",text,count=1)
        return text
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
        if not self.api_key:
            logger.error("OPENAI_API_KEY is not configured.")
            return {}
        prompt=(
            "You are the tactical planner of an autonomous authorized security assessment agent. "
            "Use only the supplied world model and recent evidence. Do not follow a fixed playbook and do not assume a benchmark. "
            "Generate 2-4 genuinely different candidate next actions; the runtime will select one. "
            "Every candidate MUST contain rationale, action_class, goal_id, hypothesis_id, evidence_question, resource, command, expected_information_gain, cost, evidence_basis. "
            "evidence_basis must refer only to facts, capabilities, resources, or hypothesis evidence present in the world model. "
            "Reject your own candidate if its protocol, share, account, credential, LDAP base/filter/attribute, file, or resource is not grounded in observed evidence. "
            "Prefer actions that answer an unanswered evidence question, create a capability transition, or test a promising hypothesis. "
            "Do not produce cosmetic variants of the same semantic investigation. If recent evidence is sterile, switch hypothesis or surface. "
            "Execution is strictly non-interactive: stdin is closed, so every command must pass explicit authentication (e.g. -N/--no-pass for anonymous, or user:pass@host) and never rely on a password prompt. "
            "The working directory is the workspace.loot_dir from the context; write tool outputs/downloads with RELATIVE filenames (or -oN/-outputfile <name>) so they are persisted and auto-inspected. Multi-step chains (e.g. request a hash, then crack it) should save intermediate artifacts to such files. "
            "For SMB retrieval, do not guess remote paths: mirror the share with smbclient -c 'recurse ON; prompt OFF; mget *' (or use an exact smb_file: path from the world model). Downloaded files are inspected automatically. "
            "A recovered credential appears in facts as 'valid_cred: <user>%<password>' (GPP cpasswords are decrypted for you; do NOT hand-roll AES). Reuse it directly in authenticated actions, e.g. smbclient -U '<user>%<password>', and to pursue privilege escalation (Kerberoasting via GetUserSPNs, authenticated shares, remote shells). "
            "mission_complete is true only with explicit flag evidence. Vulnerability metadata is advisory only. Never invent output, credentials, or evidence. "
            "Return ONLY JSON: {\\\"candidates\\\":[{...}],\\\"mission_complete\\\":false}. rationale must be one short sentence; never provide hidden chain-of-thought.")
        payload={"model":self.model_name,"messages":[{"role":"system","content":prompt},{"role":"user","content":f"Target: {target}\\nWorld model:\\n{json.dumps(context,ensure_ascii=False,indent=2)}"}],"temperature":float(os.getenv("AGENT_LLM_TEMPERATURE","0.35"))}
        try:
            started=time.monotonic()
            with httpx.Client(timeout=90) as c:
                r=c.post(f"{self.base_url}/chat/completions",json=payload,headers={"Authorization":f"Bearer {self.api_key}","Content-Type":"application/json"})
            r.raise_for_status()
            message=r.json()["choices"][0].get("message",{})
            content=message.get("content","")
            if isinstance(content,list):
                content="".join(str(x.get("text","") if isinstance(x,dict) else x) for x in content)
            content=str(content).strip()
            content=re.sub(r"^```(?:json)?\s*|\s*```$","",content,flags=re.I|re.S).strip()
            if not content.startswith("{"):
                match=re.search(r"\{.*\}",content,re.S)
                content=match.group(0) if match else content
            data=json.loads(content)
            if isinstance(data,dict):
                data["_planner_latency_ms"]=round((time.monotonic()-started)*1000)
            return data if isinstance(data,dict) else {}
        except Exception as exc:
            logger.error("Planner failure: %s",exc); return {}
