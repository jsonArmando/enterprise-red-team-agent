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
    _PLACEHOLDER=re.compile(r"<[a-z][a-z0-9 _/-]{1,40}>", re.I)
    _BRUTEFORCE=re.compile(r"\b(?:hydra|medusa|ncrack|patator)\b", re.I)
    _BIG_WORDLIST=re.compile(r"rockyou|seclists|/big\.txt|directory-list", re.I)

    @classmethod
    def has_placeholder(cls,command):
        """True if the command still carries an unfilled <placeholder> (e.g.
        `hydra -l <user> ...`) - the LLM hallucinated a value it never resolved."""
        return bool(cls._PLACEHOLDER.search(str(command or "")))

    @classmethod
    def is_blind_bruteforce(cls,command):
        """True for a mass credential brute-force (a large wordlist against a
        service) - hours of runtime with near-zero payoff unless a valid
        username is already known."""
        text=cls.clean(command)
        return bool(cls._BRUTEFORCE.search(text) and cls._BIG_WORDLIST.search(text))

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
            "ROLE. You are the tactical planning core of an autonomous, AUTHORIZED penetration-testing agent, operating with the discipline of a senior offensive-security engineer (OSCP/OSEP-level white-hat) on a sanctioned engagement. Your objective is to progress from reconnaissance to a foothold to privilege escalation and to capture flags (user.txt then root.txt), efficiently and methodically.\n"
            "OUTPUT CONTRACT. Return ONLY JSON: {\"candidates\":[{...}],\"mission_complete\":false}. Emit 2-4 candidates that are GENUINELY DIFFERENT investigations (not cosmetic variants); the runtime selects and executes one. Each candidate MUST have: rationale (one short sentence), action_class, goal_id, hypothesis_id, evidence_question, resource, command, expected_information_gain (0-1), cost (0-1), evidence_basis. No prose, no markdown, no chain-of-thought.\n"
            "GROUNDING. Use ONLY the supplied world model and recent evidence; do not assume a benchmark or a fixed playbook. evidence_basis must cite facts/capabilities/resources/hypotheses actually present in the world model. Never target a protocol, port, path, share, account, credential, parameter or CVE that has not been observed. Never invent output, credentials, versions or evidence. Never emit an unfilled <placeholder> (e.g. <user>, <password>): if you do not have the value, gather it first.\n"
            "METHODOLOGY (evidence-driven, not scripted). 1) Enumerate observed services precisely: identify the exact product AND version behind each open port. For HTTP, retrieve and READ the response BODY (curl -s http://host:port/), inspect titles, headers, redirects, cookies, favicon, JS bundles and /robots.txt; a bare `curl -I` (headers only) is rarely enough. 2) Turn a precise product+version into a TARGETED known-exploit path (searchsploit / known CVE) or a specific misconfiguration, rather than generic scanning. 3) Only then exploit; then escalate. Prefer the highest expected_information_gain at the lowest cost.\n"
            "ANTI-STALL. Do NOT repeat a semantically equivalent action: re-running the same directory brute-force or the same header fetch with a different output filename or wordlist is NOT new work and will be rejected. If recent actions were sterile (no new evidence), CHANGE approach or surface - inspect gathered artifacts, read a page body, pivot to another service or hypothesis. Prefer to act on evidence you already collected before gathering more.\n"
            "CREDENTIAL ATTACKS. Do NOT launch mass/blind brute-force (e.g. hydra/medusa with rockyou) against a service unless a VALID USERNAME is already known - it costs hours for near-zero payoff and will be rejected. Prefer: default/weak credential pairs, credentials found in the target's own content, and service-specific auth flaws. Only brute-force once you have a confirmed username or a small, justified candidate set.\n"
            "EXECUTION ENVIRONMENT. Strictly non-interactive: stdin is closed, so every command must pass explicit auth (e.g. -N/--no-pass for anonymous SMB, user:pass@host, -U 'user%pass') and never rely on a prompt. Use CORRECT tool syntax (e.g. ffuf uses -o/-of, gobuster uses -o, nmap uses -oN - do not mix them). The working directory is workspace.loot_dir; write outputs with RELATIVE filenames so they are persisted and auto-inspected. Multi-step chains (request a hash, then crack it) should save intermediate artifacts to files. Keep individual commands bounded in time; avoid unbounded scans.\n"
            "DOMAIN NOTES. For SMB retrieval do not guess remote paths: mirror the share with smbclient -c 'recurse ON; prompt OFF; mget *' or use an exact smb_file: path from the world model. A recovered credential appears in facts as 'valid_cred: <user>%<password>' (GPP cpasswords are decrypted for you - never hand-roll AES); reuse it directly in authenticated actions and for privilege escalation (Kerberoasting via GetUserSPNs, authenticated shares, remote shells).\n"
            "COMPLETION. mission_complete is true ONLY with explicit flag evidence (user.txt/root.txt content or a flag token). Vulnerability metadata is advisory only.")
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
