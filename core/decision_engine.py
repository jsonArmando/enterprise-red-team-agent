"""Structured autonomous decision engine for an authorized lab."""
from __future__ import annotations
import json, os, httpx

ALLOWED_ACTIONS={"recon","vulnerability_scan","cve_lookup","analyze_candidate","validate_candidate","exploit_candidate","post_exploit_enum","privilege_escalation","verify_flags","replan"}

class DecisionEngine:
    def __init__(self):
        self.api_key=os.getenv("OPENAI_API_KEY","").strip()
        self.base_url=os.getenv("OPENAI_API_BASE","https://api.x.ai/v1").rstrip("/")
        self.model=os.getenv("MODEL_NAME","grok-3").strip()

    def decide(self,state):
        if not self.api_key: return self._fallback(state)
        prompt={"mission":state.get("mission"),"objective":state.get("objective"),"flags":state.get("flags",{}),"recon_complete":state.get("recon_complete"),"vulnerability_scan_complete":state.get("vulnerability_scan_complete"),"potential_exploits_ready":state.get("potential_exploits_ready"),"vulnerabilities":state.get("vulnerabilities",[]),"hypotheses":state.get("hypotheses",[]),"recent_history":state.get("history",[])[-10:],"evidence":state.get("evidence_ledger",[])[-15:]}
        system="You are the autonomous decision engine for an authorized HTB/lab. Choose one registered action from evidence. After enumeration, analyze every potential exploit candidate line by line using its evidence_lines, CVE, service, version, port and exploit references. A candidate must be validated before exploitation. Never declare mission completion; the verifier owns completion. Return JSON with action, candidate_id, reason, priority."
        try:
            r=httpx.post(f"{self.base_url}/chat/completions",headers={"Authorization":f"Bearer {self.api_key}","Content-Type":"application/json"},json={"model":self.model,"temperature":0.1,"messages":[{"role":"system","content":system},{"role":"user","content":json.dumps(prompt,ensure_ascii=False)}]},timeout=90)
            r.raise_for_status()
            raw=r.json()["choices"][0]["message"]["content"].strip().replace("```json","").replace("```","").strip()
            d=json.loads(raw)
            if d.get("action") not in ALLOWED_ACTIONS: raise ValueError("invalid_action")
            return d
        except Exception: return self._fallback(state)

    def analyze_candidate(self, candidate:dict, state:dict)->dict:
        """Analyze candidate evidence line-by-line; returns validation intent, never a shell command."""
        lines=candidate.get("evidence_lines") or []
        relevant=[]
        for item in lines:
            text=str(item.get("text",""))
            relevant.append({"line":item.get("line"),"text":text[:2000],"cves":item.get("cves",[]),"ports":item.get("ports",[])})
        if not candidate.get("cve") or not relevant:
            return {"valid":False,"confidence":0.1,"reason":"Insufficient line-level evidence"}
        if not self.api_key:
            return {"valid":True,"confidence":candidate.get("confidence",0.6),"reason":"Candidate has CVE and correlated scanner evidence"}
        payload={"candidate":{k:candidate.get(k) for k in ("id","cve","target","service","version","port","confidence","exploit_references","evidence_lines")},"mission":state.get("mission"),"objective":state.get("objective"),"recent_failures":state.get("failed_paths",[])}
        system="Analyze this authorized-lab vulnerability candidate line by line. Determine whether the scanner evidence plausibly maps the CVE to the target service. Return JSON only: {valid:boolean,confidence:number,reason:string}. Do not produce exploit commands."
        try:
            r=httpx.post(f"{self.base_url}/chat/completions",headers={"Authorization":f"Bearer {self.api_key}","Content-Type":"application/json"},json={"model":self.model,"temperature":0.0,"messages":[{"role":"system","content":system},{"role":"user","content":json.dumps(payload,ensure_ascii=False)}]},timeout=90)
            r.raise_for_status()
            raw=r.json()["choices"][0]["message"]["content"].strip().replace("```json","").replace("```","").strip()
            d=json.loads(raw)
            return {"valid":bool(d.get("valid")),"confidence":float(d.get("confidence",0.0)),"reason":str(d.get("reason",""))}
        except Exception:
            return {"valid":True,"confidence":candidate.get("confidence",0.6),"reason":"Fallback: correlated CVE evidence is present"}

    def _fallback(self,state):
        flags=state.get("flags",{})
        if flags.get("complete"): return {"action":"verify_flags","candidate_id":None,"reason":"Independent flag verification","priority":1.0}
        if not state.get("recon_complete"): return {"action":"recon","candidate_id":None,"reason":"Complete reconnaissance first","priority":1.0}
        if not state.get("vulnerability_scan_complete"): return {"action":"vulnerability_scan","candidate_id":None,"reason":"Build vulnerability evidence inventory","priority":1.0}
        candidates=state.get("vulnerabilities",[])
        unanalyzed=[v for v in candidates if v.get("status")=="discovered" and v.get("validation")=="pending"]
        unvalidated=[v for v in candidates if v.get("status")=="analyzed" and v.get("validation")=="pending"]
        validated=[v for v in candidates if v.get("validation")=="validated" and v.get("exploit_status")=="pending"]
        if unanalyzed:
            return {"action":"analyze_candidate","candidate_id":unanalyzed[0].get("id"),"reason":"Analyze candidate evidence line by line","priority":0.95}
        if unvalidated:
            return {"action":"validate_candidate","candidate_id":unvalidated[0].get("id"),"reason":"Validate candidate preconditions","priority":0.92}
        if validated:
            return {"action":"exploit_candidate","candidate_id":validated[0].get("id"),"reason":"Exploit validated lab candidate","priority":0.90}
        if flags.get("user_verified") and not flags.get("root_verified"): return {"action":"privilege_escalation","candidate_id":None,"reason":"User verified; pursue root objective","priority":0.98}
        if state.get("foothold"): return {"action":"post_exploit_enum","candidate_id":None,"reason":"Generate new post-exploit evidence","priority":0.90}
        return {"action":"replan","candidate_id":None,"reason":"No unprocessed candidate; acquire new evidence","priority":0.70}