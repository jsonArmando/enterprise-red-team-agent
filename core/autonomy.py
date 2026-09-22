import hashlib
import re
from typing import Any, Dict, List


class AutonomyEngine:
    """Stateful supervisor for autonomous planning.

    It deliberately does not choose the tactic for the LLM. It records evidence,
    capabilities and progress so the planner can make the next tactical decision.
    """

    def __init__(self, target: str):
        self.target = target

    @staticmethod
    def _normalize(text: str) -> str:
        return re.sub(r"\s+", " ", str(text or "").strip())

    @staticmethod
    def _evidence_types(output: str) -> List[str]:
        text = str(output or "").lower()
        found = []
        patterns = {
            "network": ("open", "tcp", "udp", "service"),
            "identity": ("user", "account", "principal", "domain"),
            "group": ("group", "member", "memberof"),
            "share": ("share", "smb", "cifs"),
            "credential": ("password", "credential", "hash", "ntlm", "secret"),
            "session": ("authenticated", "authentication", "session", "shell"),
            "privilege": ("administrator", "system", "root", "privilege"),
            "file": ("file", "directory", "loot", "downloaded")
        }
        for name, terms in patterns.items():
            if any(t in text for t in terms):
                found.append(name)
        return found

    @staticmethod
    def _session_signal(command: str, output: str, returncode: Any) -> bool:
        if returncode not in (0, None):
            return False
        text = (str(command or "") + " " + str(output or "")).lower()
        return any(x in text for x in ("authenticated", "psexec", "wmiexec", "smbexec", "evil-winrm", "interactive shell"))

    @classmethod
    def _meaningful_progress(cls, command: str, output: str, returncode: Any, new_evidence: List[str], new_session: bool) -> bool:
        if returncode not in (0, None):
            return False
        text = cls._normalize(output).lower()
        if not text or any(marker in text for marker in ("error:", "failed", "access denied", "not found", "invalid")):
            return bool(new_evidence or new_session)
        return bool(new_evidence or new_session)

    def observe(self, state: Dict[str, Any], entry: Dict[str, Any]) -> Dict[str, Any]:
        old = dict(state.get("autonomy") or {})
        output = str(entry.get("output", ""))
        command = str(entry.get("command", ""))
        digest = hashlib.sha256(self._normalize(output).encode()).hexdigest()[:16] if output else ""
        evidence = list(old.get("evidence_types", []))
        current_evidence = self._evidence_types(output)
        new_evidence = [item for item in current_evidence if item not in evidence]
        for item in new_evidence:
            evidence.append(item)
        sessions = list(old.get("sessions", []))
        session_signal = self._session_signal(command, output, entry.get("returncode"))
        new_session = False
        if session_signal:
            sid = hashlib.sha256(self._normalize(command).encode()).hexdigest()[:12]
            if sid not in {s.get("id") for s in sessions if isinstance(s, dict)}:
                sessions.append({"id": sid, "source": command[:240], "step": entry.get("step")})
                new_session = True
        history_digests = list(old.get("output_digests", []))
        if digest and digest not in history_digests:
            history_digests.append(digest)
        progress = self._meaningful_progress(command, output, entry.get("returncode"), new_evidence, new_session)
        streak = int(old.get("no_progress_streak", 0))
        streak = 0 if progress else streak + 1
        return {
            "evidence_types": evidence[-32:],
            "sessions": sessions[-16:],
            "output_digests": history_digests[-64:],
            "progress_events": int(old.get("progress_events", 0)) + (1 if progress else 0),
            "no_progress_streak": streak,
            "last_progress_step": entry.get("step") if progress else old.get("last_progress_step"),
            "last_action": command[:240],
            "last_new_evidence": new_evidence,
            "last_progress": progress
        }

    def context(self, state: Dict[str, Any]) -> Dict[str, Any]:
        a = state.get("autonomy") or {}
        return {
            "evidence_types": a.get("evidence_types", []),
            "sessions": a.get("sessions", []),
            "progress_events": a.get("progress_events", 0),
            "last_progress_step": a.get("last_progress_step"),
            "no_progress_streak": a.get("no_progress_streak", 0),
            "last_new_evidence": a.get("last_new_evidence", []),
            "last_progress": a.get("last_progress", False),
            "last_action": a.get("last_action", "")
        }
