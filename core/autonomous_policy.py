"""Strict authorization layer for autonomous lab actions."""
from core.policy_engine import evaluate_policy

def authorize(target: str, scope: dict, action: str, candidate: dict | None = None) -> tuple[bool,str]:
    if not evaluate_policy(target, scope):
        return False, "target_out_of_scope"
    if action == "exploit" and not candidate:
        return False, "exploit_requires_candidate"
    if action == "exploit" and not candidate.get("cve"):
        return False, "candidate_requires_cve"
    if action == "exploit" and candidate.get("status") == "rejected":
        return False, "candidate_rejected"
    return True, "allowed"
