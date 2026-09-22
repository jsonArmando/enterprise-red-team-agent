"""Deep failure-reasoning loop for authorized HTB/lab execution."""
from __future__ import annotations
import json, os, httpx
from typing import Any

RECOVERY_ACTIONS = {
    "recon","vulnerability_scan","cve_lookup","analyze_candidate","validate_candidate",
    "exploit_candidate","run_kali_tool","discover_kali_tools","establish_access","reverse_shell",
    "session_enum","post_exploit_enum","analyze_privesc","privilege_escalation",
    "verify_flags","replan",
}

class FailureReasoner:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY", "").strip()
        self.base_url = os.getenv("OPENAI_API_BASE", "https://api.x.ai/v1").rstrip("/")
        self.model = os.getenv("MODEL_NAME", "grok-3").strip()

    def reason(self, state: dict[str, Any]) -> dict[str, Any]:
        failure = state.get("failure_memory", [])[-1] if state.get("failure_memory") else {}
        if not failure:
            return {}
        fallback = self._fallback(failure, state)
        if not self.api_key:
            return fallback

        payload = {
            "failure": failure,
            "objective": state.get("objective"),
            "flags": state.get("flags", {}),
            "candidate": failure.get("candidate"),
            "recent_history": state.get("history", [])[-12:],
            "evidence": state.get("evidence_ledger", [])[-12:],
            "failed_paths": state.get("failed_paths", [])[-12:],
            "reasoning_trace": state.get("reasoning_trace", [])[-8:],
        }
        system = (
            "You are the deep-reasoning recovery engine for an authorized HTB/lab agent. "
            "Analyze why the last action failed. Distinguish tool/environment failure from "
            "an incorrect hypothesis. Identify missing evidence. Generate several alternative "
            "hypotheses internally, compare them, and select ONE registered recovery action. "
            "Never repeat the same failed action/candidate without materially new evidence. "
            "Never output exploit commands. Return JSON only."
        )
        try:
            r = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={
                    "model": self.model,
                    "temperature": 0.0,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
                    ],
                },
                timeout=90,
            )
            r.raise_for_status()
            raw = r.json()["choices"][0]["message"]["content"].strip()
            result = json.loads(raw)
            if result.get("recovery_action") not in RECOVERY_ACTIONS:
                return fallback
            result["failure_id"] = failure.get("id")
            return result
        except Exception:
            return fallback

    def _fallback(self, failure: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        action = failure.get("action", "")
        output = str(failure.get("output", "")).lower()
        if "timeout" in output or "unreachable" in output:
            next_action = "recon"
        elif action in {"exploit_candidate", "validate_candidate"}:
            next_action = "replan"
        elif action in {"establish_access", "reverse_shell"}:
            next_action = "session_enum" if any(x in output for x in ("uid=", "session_established")) else "reverse_shell"
        elif action == "privilege_escalation":
            next_action = "analyze_privesc"
        else:
            next_action = "replan"
        return {
            "failure_id": failure.get("id"),
            "root_cause": "Fallback failure classification",
            "missing_evidence": ["fresh evidence from a different observation path"],
            "alternatives": [{"action": next_action, "reason": "change evidence or hypothesis"}],
            "recovery_action": next_action,
            "confidence": 0.45,
            "rationale": "Do not retry blindly; change evidence source or attack hypothesis.",
        }
