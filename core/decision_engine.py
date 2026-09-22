"""Deep autonomous decision engine for authorized HTB/lab missions."""
from __future__ import annotations
import json, os, httpx
from core.failure_reasoner import FailureReasoner

ALLOWED_ACTIONS = {
    "recon","vulnerability_scan","discover_kali_tools","cve_lookup",
    "analyze_candidate","validate_candidate","exploit_candidate",
    "establish_access","reverse_shell","session_enum","post_exploit_enum",
    "analyze_privesc","privilege_escalation","verify_flags","replan",
}

class DecisionEngine:
    def __init__(self):
        self.api_key=os.getenv("OPENAI_API_KEY","").strip()
        self.base_url=os.getenv("OPENAI_API_BASE","https://api.x.ai/v1").rstrip("/")
        self.model=os.getenv("MODEL_NAME","grok-3").strip()
        self.failure_reasoner=FailureReasoner()

    def decide(self,state):
        failure_memory=state.get("failure_memory",[])
        if failure_memory and state.get("failure_reasoned_id") != failure_memory[-1].get("id"):
            recovery=self.failure_reasoner.reason(state)
            if recovery:
                return {
                    "action":recovery.get("recovery_action","replan"),
                    "candidate_id":failure_memory[-1].get("candidate_id"),
                    "reason":recovery.get("rationale",""),
                    "priority":recovery.get("confidence",0.5),
                    "failure_id":recovery.get("failure_id"),
                    "deep_reasoning":recovery,
                }

        if not self.api_key:
            return self._fallback(state)

        prompt={
            "mission":state.get("mission"),
            "objective":state.get("objective"),
            "flags":state.get("flags",{}),
            "recon_complete":state.get("recon_complete"),
            "vulnerability_scan_complete":state.get("vulnerability_scan_complete"),
            "kali_tools_count":len(state.get("kali_tools",[])),
            "potential_exploits_ready":state.get("potential_exploits_ready"),
            "vulnerabilities":state.get("vulnerabilities",[]),
            "privesc_candidates":state.get("privesc_candidates",[]),
            "session":state.get("session",{}),
            "recent_history":state.get("history",[])[-12:],
            "evidence":state.get("evidence_ledger",[])[-15:],
            "failed_paths":state.get("failed_paths",[])[-12:],
            "reasoning_trace":state.get("reasoning_trace",[])[-8:],
        }
        system=(
            "You are the autonomous decision engine for an authorized HTB/lab. "
            "Choose exactly one registered action from current evidence. "
            "Reason over service/version/CVE evidence before exploitation. "
            "After a foothold, establish a stable session or use the reverse-shell orchestrator. "
            "Post-exploit enumeration must generate evidence before privilege escalation. "
            "Privilege escalation is a separate hypothesis/validation/execution stage. "
            "When an action fails, never repeat it without materially new evidence. "
            "Mission completion is owned only by the flag verifier. Return JSON with "
            "action,candidate_id,reason,priority."
        )
        try:
            r=httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization":f"Bearer {self.api_key}","Content-Type":"application/json"},
                json={
                    "model":self.model,"temperature":0.1,
                    "messages":[
                        {"role":"system","content":system},
                        {"role":"user","content":json.dumps(prompt,ensure_ascii=False)}
                    ]
                },
                timeout=90,
            )
            r.raise_for_status()
            raw=r.json()["choices"][0]["message"]["content"].strip()
            raw=raw.replace(chr(96)*3+"json","").replace(chr(96)*3,"").strip()
            decision=json.loads(raw)
            if decision.get("action") not in ALLOWED_ACTIONS:
                raise ValueError("invalid_action")
            return decision
        except Exception:
            return self._fallback(state)

    def analyze_candidate(self,candidate:dict,state:dict)->dict:
        lines=candidate.get("evidence_lines") or []
        relevant=[{
            "line":item.get("line"),"text":str(item.get("text",""))[:2000],
            "cves":item.get("cves",[]),"ports":item.get("ports",[])
        } for item in lines]
        if not candidate.get("cve") or not relevant:
            return {"valid":False,"confidence":0.1,"reason":"Insufficient line-level evidence"}
        if not self.api_key:
            return {"valid":True,"confidence":candidate.get("confidence",0.6),"reason":"Correlated CVE scanner evidence"}
        payload={
            "candidate":{k:candidate.get(k) for k in (
                "id","cve","target","service","version","port","confidence",
                "exploit_references","evidence_lines")},
            "objective":state.get("objective"),
            "recent_failures":state.get("failed_paths",[])[-10:],
        }
        system=(
            "Analyze this authorized-lab vulnerability candidate line by line. "
            "Check service/version/CVE consistency and identify missing preconditions. "
            "Return JSON only: valid,confidence,reason,missing_evidence."
        )
        try:
            r=httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization":f"Bearer {self.api_key}","Content-Type":"application/json"},
                json={"model":self.model,"temperature":0.0,"messages":[
                    {"role":"system","content":system},
                    {"role":"user","content":json.dumps(payload,ensure_ascii=False)}
                ]},
                timeout=90,
            )
            r.raise_for_status()
            raw=r.json()["choices"][0]["message"]["content"].strip()
            raw=raw.replace(chr(96)*3+"json","").replace(chr(96)*3,"").strip()
            d=json.loads(raw)
            return {
                "valid":bool(d.get("valid")),
                "confidence":float(d.get("confidence",0.0)),
                "reason":str(d.get("reason","")),
                "missing_evidence":d.get("missing_evidence",[]),
            }
        except Exception:
            return {"valid":True,"confidence":candidate.get("confidence",0.6),"reason":"Fallback correlated CVE evidence"}

    def analyze_privesc(self,hypotheses:list[dict],state:dict)->dict:
        if not hypotheses:
            return {"validated_id":None,"reason":"No privilege-escalation hypotheses"}
        if not self.api_key:
            return {"validated_id":hypotheses[0]["id"],"reason":"Highest-confidence evidence-backed hypothesis"}
        payload={
            "objective":state.get("objective"),
            "session":state.get("session",{}),
            "hypotheses":hypotheses[:20],
            "recent_failures":state.get("failed_paths",[])[-10:],
        }
        system=(
            "For this authorized HTB/lab session, evaluate privilege-escalation hypotheses "
            "against evidence. Select ONE hypothesis to validate next. Do not provide commands. "
            "Return JSON only: validated_id,reason,missing_evidence."
        )
        try:
            r=httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization":f"Bearer {self.api_key}","Content-Type":"application/json"},
                json={"model":self.model,"temperature":0.0,"messages":[
                    {"role":"system","content":system},
                    {"role":"user","content":json.dumps(payload,ensure_ascii=False)}
                ]},
                timeout=90,
            )
            r.raise_for_status()
            raw=r.json()["choices"][0]["message"]["content"].strip()
            raw=raw.replace(chr(96)*3+"json","").replace(chr(96)*3,"").strip()
            d=json.loads(raw)
            valid_id=d.get("validated_id")
            allowed={h["id"] for h in hypotheses}
            if valid_id not in allowed:
                return {"validated_id":hypotheses[0]["id"],"reason":"Model selected unavailable hypothesis"}
            return d
        except Exception:
            return {"validated_id":hypotheses[0]["id"],"reason":"Fallback top evidence-backed hypothesis"}

    def _fallback(self,state):
        flags=state.get("flags",{})
        if flags.get("complete"):
            return {"action":"verify_flags","candidate_id":None,"reason":"Independent completion check","priority":1.0}
        if not state.get("recon_complete"):
            return {"action":"recon","candidate_id":None,"reason":"Build complete reconnaissance evidence","priority":1.0}
        if not state.get("kali_tools_catalogued"):
            return {"action":"discover_kali_tools","candidate_id":None,"reason":"Read available Kali tool catalog","priority":0.99}
        if not state.get("vulnerability_scan_complete"):
            return {"action":"vulnerability_scan","candidate_id":None,"reason":"Build vulnerability evidence inventory","priority":0.98}

        candidates=state.get("vulnerabilities",[])
        unanalyzed=[v for v in candidates if v.get("status")=="discovered" and v.get("validation")=="pending"]
        unvalidated=[v for v in candidates if v.get("status")=="analyzed" and v.get("validation")=="pending"]
        validated=[v for v in candidates if v.get("validation")=="validated" and v.get("exploit_status") not in {"confirmed","rejected"}]
        if unanalyzed:
            return {"action":"analyze_candidate","candidate_id":unanalyzed[0].get("id"),"reason":"Analyze CVE evidence line by line","priority":0.95}
        if unvalidated:
            return {"action":"validate_candidate","candidate_id":unvalidated[0].get("id"),"reason":"Validate target-specific preconditions","priority":0.93}
        if validated:
            return {"action":"exploit_candidate","candidate_id":validated[0].get("id"),"reason":"Execute only validated candidate","priority":0.91}

        if state.get("foothold") and not state.get("session",{}).get("connected"):
            if not state.get("reverse_shell_attempted"):
                return {"action":"establish_access","candidate_id":None,"reason":"Convert foothold into stable session","priority":0.99}
            return {"action":"reverse_shell","candidate_id":None,"reason":"Use lab reverse-shell recovery path","priority":0.98}

        if state.get("session",{}).get("connected") and not state.get("post_exploit_complete"):
            return {"action":"post_exploit_enum","candidate_id":None,"reason":"Enumerate host/session before privesc","priority":0.97}

        if state.get("session",{}).get("connected") and not flags.get("user_ok"):
            return {"action":"session_enum","candidate_id":None,"reason":"Inspect stable session and user flag context","priority":0.96}

        if flags.get("user_ok") and not flags.get("root_ok"):
            hypotheses=state.get("privesc_candidates",[])
            pending=[h for h in hypotheses if h.get("status") in {"discovered","analyzed"}]
            if pending:
                return {"action":"analyze_privesc","candidate_id":None,"reason":"Evaluate privilege escalation hypotheses","priority":0.95}
            return {"action":"privilege_escalation","candidate_id":None,"reason":"Attempt validated privilege-escalation hypothesis","priority":0.94}

        return {"action":"verify_flags","candidate_id":None,"reason":"Verify objective state","priority":0.90}
