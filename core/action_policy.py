"""Generic action policy: separates candidate validity from LLM choice."""
import hashlib, re
from typing import Any, Dict, List

class ActionPolicy:
    def __init__(self, history: List[Dict[str, Any]]):
        self.history = history or []

    @staticmethod
    def norm(value: Any) -> str:
        return re.sub(r"\s+", " ", str(value or "").strip()).lower()

    @staticmethod
    def question_key(decision: Dict[str, Any]) -> str:
        raw="|".join(ActionPolicy.norm(decision.get(k)) for k in ("hypothesis_id","goal_id","evidence_question","resource"))
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def command_key(command: str) -> str:
        return hashlib.sha256(ActionPolicy.norm(command).encode()).hexdigest()[:16]

    def evaluate(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        qkey=self.question_key(decision)
        ckey=self.command_key(decision.get("command",""))
        for h in self.history[-64:]:
            if h.get("event_type")!="action": continue
            prior_command=h.get("command_key") or self.command_key(h.get("command",""))
            prior_question=h.get("evidence_question_key") or self.question_key(h)
            if prior_command==ckey and h.get("returncode")==0:
                return {"allowed":False,"reason":"identical_successful_command","question_key":qkey}
            if prior_question==qkey and h.get("returncode")==0 and h.get("no_new_evidence") is False:
                return {"allowed":False,"reason":"evidence_question_answered","question_key":qkey}
        return {"allowed":True,"reason":"candidate_is_novel","question_key":qkey}

    def rank(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        scored=[]
        for d in candidates:
            gain=float(d.get("expected_information_gain",0) or 0)
            cost=float(d.get("cost",0.5) or 0.5)
            novelty=float(d.get("novelty",0) or 0)
            scored.append((gain+novelty-cost,d))
        return [d for _,d in sorted(scored,key=lambda x:x[0],reverse=True)]
