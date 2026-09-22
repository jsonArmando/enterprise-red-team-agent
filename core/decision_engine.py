"""Structured autonomous decision engine."""
from __future__ import annotations
import json, os, httpx

ALLOWED_ACTIONS={"recon","vulnerability_scan","cve_lookup","exploit_candidate","post_exploit_enum","privilege_escalation","verify_flags","replan"}

class DecisionEngine:
    def __init__(self):
        self.api_key=os.getenv("OPENAI_API_KEY","").strip()
        self.base_url=os.getenv("OPENAI_API_BASE","https://api.x.ai/v1").rstrip("/")
        self.model=os.getenv("MODEL_NAME","grok-3").strip()

    def decide(self,state):
        if not self.api_key: return self._fallback(state)
        prompt={"mission":state.get("mission"),"objective":state.get("objective"),"flags":state.get("flags",{}),"services":state.get("discovered_services",[]),"vulnerabilities":state.get("vulnerabilities",[]),"hypotheses":state.get("hypotheses",[]),"recent_history":state.get("history",[])[-8:],"evidence":state.get("evidence_ledger",[])[-12:]}
        system="You are the decision engine for an authorized HTB/lab Red Team agent. Choose one allowed action from evidence. Never declare completion; the verifier owns completion. Do not repeat rejected hypotheses without new evidence. Return JSON with action, candidate_id, reason, priority."
        try:
            r=httpx.post(f"{self.base_url}/chat/completions",headers={"Authorization":f"Bearer {self.api_key}","Content-Type":"application/json"},json={"model":self.model,"temperature":0.1,"messages":[{"role":"system","content":system},{"role":"user","content":json.dumps(prompt)}]},timeout=90)
            r.raise_for_status()
            raw=r.json()["choices"][0]["message"]["content"].strip().replace("```","")
            d=json.loads(raw)
            if d.get("action") not in ALLOWED_ACTIONS: raise ValueError("invalid_action")
            return d
        except Exception: return self._fallback(state)

    def _fallback(self,state):
        flags=state.get("flags",{})
        if flags.get("complete"): return {"action":"verify_flags","candidate_id":None,"reason":"Verifier check","priority":1.0}
        if not state.get("recon_complete"): return {"action":"recon","candidate_id":None,"reason":"Full enumeration required","priority":1.0}
        if not state.get("vulnerability_scan_complete"): return {"action":"vulnerability_scan","candidate_id":None,"reason":"Build vulnerability inventory","priority":1.0}
        pending=[v for v in state.get("vulnerabilities",[]) if v.get("status")=="candidate"]
        if pending:
            c=pending[0]
            if not c.get("exploit_references"): return {"action":"cve_lookup","candidate_id":c.get("id"),"reason":"Find exploit reference","priority":0.9}
            return {"action":"exploit_candidate","candidate_id":c.get("id"),"reason":"Try next untested candidate","priority":0.8}
        if flags.get("user_verified") and not flags.get("root_verified"): return {"action":"privilege_escalation","candidate_id":None,"reason":"User objective reached; pursue root","priority":0.95}
        if state.get("foothold"): return {"action":"post_exploit_enum","candidate_id":None,"reason":"Refresh local evidence","priority":0.9}
        return {"action":"replan","candidate_id":None,"reason":"Generate new evidence/hypothesis","priority":0.7}