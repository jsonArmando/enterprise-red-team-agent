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
            content=_llm_post(self.base_url,self.api_key,payload)
            data=_extract_json(content)
            if isinstance(data,dict) and data:
                data["_planner_latency_ms"]=round((time.monotonic()-started)*1000)
            return data if isinstance(data,dict) else {}
        except Exception as exc:
            logger.error("Planner failure: %s",exc); return {}


def _llm_post(base_url, api_key, payload, timeout=90, retries=2):
    """POST a chat-completion with backoff on transient failures (429/5xx and
    connection errors). Returns the message content string. Non-transient
    errors (e.g. 401/403 auth/quota) are raised immediately - retrying those
    only wastes calls."""
    last=None
    for attempt in range(retries+1):
        try:
            with httpx.Client(timeout=timeout) as c:
                r=c.post(f"{base_url}/chat/completions",json=payload,
                         headers={"Authorization":f"Bearer {api_key}","Content-Type":"application/json"})
            if r.status_code in (429,500,502,503,504):
                last=httpx.HTTPStatusError(f"{r.status_code}",request=r.request,response=r)
                time.sleep(2*(attempt+1)); continue
            r.raise_for_status()
            return r.json()["choices"][0].get("message",{}).get("content","")
        except httpx.HTTPStatusError:
            raise
        except Exception as exc:
            last=exc; time.sleep(2*(attempt+1))
    if last: raise last
    return ""


def _extract_json(content):
    """Pull a JSON object out of an LLM response (handles code fences/prose)."""
    if isinstance(content,list):
        content="".join(str(x.get("text","") if isinstance(x,dict) else x) for x in content)
    content=str(content or "").strip()
    content=re.sub(r"^```(?:json)?\s*|\s*```$","",content,flags=re.I|re.S).strip()
    if not content.startswith("{"):
        m=re.search(r"\{.*\}",content,re.S)
        content=m.group(0) if m else content
    # strict=False tolerates raw control chars (newlines/tabs) inside string
    # values, which LLMs routinely emit inside command fields; retry with a
    # sanitized copy if the model produced something still-malformed.
    for candidate in (content, re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]"," ",content)):
        try:
            data=json.loads(candidate, strict=False)
            return data if isinstance(data,dict) else {}
        except Exception:
            continue
    return {}


class LLMHypothesisEngine:
    """Domain-agnostic hypothesis generator.

    Replaces the hardcoded AD-only hypothesis templates: given observed
    evidence it asks the model to propose attack-surface hypotheses for ANY
    technology (web, Linux, Windows/AD, databases, network services). The
    deterministic runtime still scores, leases and grounds them. Returns [] on
    any failure so the caller can fall back to static templates offline.
    """
    def __init__(self, knowledge: str = ""):
        self.api_key=os.environ.get("OPENAI_API_KEY","").strip()
        self.base_url=os.environ.get("OPENAI_API_BASE","https://api.x.ai/v1").strip()
        self.model_name=os.environ.get("MODEL_NAME","grok-3").strip()
        self.knowledge=(knowledge or "")[:6000]

    def available(self) -> bool:
        return bool(self.api_key)

    def generate(self, world):
        if not self.api_key:
            return []
        prompt=(
            "You are the reasoning module of an autonomous authorized penetration-testing agent. "
            "From the OBSERVED evidence only, propose 3-8 hypotheses about exploitable attack surfaces or the next investigations worth pursuing. "
            "Cover ANY technology as the evidence warrants - web apps, Linux services and privilege escalation, Windows/Active Directory, databases, network services - do NOT assume a benchmark or a fixed methodology. "
            "Each hypothesis MUST be an object with: id (short stable slug, e.g. H-WEB-LFI, H-SMB-ANON, H-SSH-CREDS), statement (one sentence), tests (list of short evidence categories a next action would gather), confidence (0-1), expected_information_gain (0-1), cost (0-1). "
            "Ground every hypothesis in the supplied facts/capabilities/services; do not invent services that were not observed. Prefer high information gain at low cost. "
            "Return ONLY JSON: {\"hypotheses\":[{...}]}. No prose, no chain-of-thought.")
        if self.knowledge:
            prompt += " Reference tactics (advisory, use only if the evidence fits):\n"+self.knowledge
        payload={"model":self.model_name,
                 "messages":[{"role":"system","content":prompt},
                             {"role":"user","content":"Observed world model:\n"+json.dumps(world,ensure_ascii=False,indent=2)}],
                 "temperature":float(os.getenv("AGENT_HYPOTHESIS_TEMPERATURE","0.4"))}
        try:
            data=_extract_json(_llm_post(self.base_url,self.api_key,payload))
            hyps=data.get("hypotheses")
            return hyps if isinstance(hyps,list) else []
        except Exception as exc:
            logger.error("Hypothesis engine failure: %s",exc); return []
