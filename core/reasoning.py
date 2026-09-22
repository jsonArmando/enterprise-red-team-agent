"""Evidence-driven reasoning state for the autonomous operator.

This module deliberately does not encode a target-specific playbook. It turns
observations into generic facts/capabilities/hypotheses/goals so the LLM can
choose among multiple plausible next investigations.
"""
import re
from typing import Any, Dict, List


class ReasoningState:
    """Build a compact world model from command evidence."""

    _PATTERNS = (
        ("network", re.compile(r"\b(?:\d{1,5}/(?:tcp|udp)|open\s+port|service|nmap)\b", re.I)),
        ("identity", re.compile(r"\b(?:domain|user|account|principal|sAMAccountName|userPrincipalName)\b", re.I)),
        ("group", re.compile(r"\b(?:group|memberOf|members|administrators)\b", re.I)),
        ("share", re.compile(r"\b(?:share|SMB|CIFS|SYSVOL|NETLOGON|Replication)\b", re.I)),
        ("artifact", re.compile(r"\b(?:GPO|Groups\.xml|SYSVOL|file|directory|policy|artifact)\b", re.I)),
        ("credential", re.compile(r"\b(?:credential|password|cpassword|hash|secret|authenticated|authentication)\b", re.I)),
        ("service_relationship", re.compile(r"\b(?:SPN|servicePrincipalName|Kerberos|CIFS/|HTTP/|MSSQL/|HOST/)\b", re.I)),
        ("privilege", re.compile(r"\b(?:Administrator|admin|SYSTEM|root|privilege|delegation)\b", re.I)),
        ("session", re.compile(r"\b(?:shell|session|interactive|wmiexec|psexec|winrm)\b", re.I)),
    )

    def __init__(self, state: Dict[str, Any]):
        self.state = state
        self.old = dict(state.get("reasoning") or {})

    @staticmethod
    def _norm(value: Any) -> str:
        return re.sub(r"\s+", " ", str(value or "").strip())

    @staticmethod
    def _unique(values: List[str], limit: int = 128) -> List[str]:
        result = []
        seen = set()
        for value in values:
            value = ReasoningState._norm(value)
            if value and value.lower() not in seen:
                seen.add(value.lower())
                result.append(value)
        return result[-limit:]

    @classmethod
    def extract_facts(cls, output: str) -> List[str]:
        facts = []
        for raw in str(output or "").splitlines():
            line = cls._norm(raw)
            if len(line) < 3:
                continue
            lower = line.lower()
            if lower.startswith(("warning:", "error:", "debug:", "traceback")):
                continue
            # Preserve useful lines, but cap their size so state remains bounded.
            if any(pattern.search(line) for _, pattern in cls._PATTERNS):
                facts.append(line[:320])
        return cls._unique(facts, 64)

    @classmethod
    def derive_capabilities(cls, facts: List[str], history: List[Dict[str, Any]]) -> List[str]:
        text = " ".join(facts + [str(h.get("output", "")) for h in history[-8:]]).lower()
        capabilities = []
        if re.search(r"\b(?:open|accessible|listing).{0,80}\b(?:smb|cifs|share)\b|\b(?:smb|cifs).{0,80}\b(?:accessible|anonymous|read)\b", text):
            capabilities.append("smb_access")
        if re.search(r"\b(?:ldap|389/tcp|636/tcp|3268/tcp)\b", text):
            capabilities.append("ldap_visibility")
        if re.search(r"\b(?:authenticated|authentication|credential|password|cpassword)\b", text):
            capabilities.append("authenticated_identity")
        if re.search(r"\b(?:domain|active directory|objectclass=|sAMAccountName)\b", text):
            capabilities.append("directory_enumeration")
        if re.search(r"\b(?:spn|serviceprincipalname|kerberos|cifs/)\b", text):
            capabilities.append("service_relationship_visibility")
        if re.search(r"\b(?:shell|session|wmiexec|psexec|winrm|interactive)\b", text):
            capabilities.append("remote_session")
        if re.search(r"\b(?:administrator|system|root|privilege)\b", text):
            capabilities.append("privilege_signal")
        if re.search(r"\b(?:gpo|groups\.xml|sysvol|replication)\b", text):
            capabilities.append("policy_artifact_access")
        return cls._unique(capabilities, 32)

    @staticmethod
    def action_intent(command: str) -> str:
        """Canonicalize command variants into a generic semantic intent."""
        text = re.sub(r"\s+", " ", str(command or "").strip().lower())
        if not text:
            return "empty"
        if any(x in text for x in ("decrypt", "decode", "decipher", "base64", "aes.new", "openssl enc")):
            return "transform_credential_or_secret_material"
        if any(x in text for x in ("cat ", "head ", "tail ", "less ", "more ", "jq ", "xmllint ", "grep ")):
            return "inspect_local_artifact"
        if any(x in text for x in ("get ", "mget ", "wget ", "curl ", "download")):
            return "retrieve_remote_artifact"
        if any(x in text for x in ("ldapsearch", "rpcclient", "enum4linux", "smbmap")):
            return "enumerate_remote_surface"
        return text[:180]
    @staticmethod
    def generate_hypotheses(facts: List[str], capabilities: List[str]) -> List[Dict[str, Any]]:
        hypotheses = []
        def add(hid: str, statement: str, tests: List[str]):
            hypotheses.append({"id": hid, "statement": statement, "tests": tests})

        if "authenticated_identity" in capabilities:
            add("H-AUTH-EXPANSION",
                "La identidad obtenida puede habilitar nuevas relaciones o recursos que no eran visibles antes.",
                ["directory_enumeration", "share_access", "service_relationships"])
        if "directory_enumeration" in capabilities:
            add("H-AD-RELATIONSHIPS",
                "La superficie de directorio puede contener relaciones entre identidades, grupos y servicios que cambien la ruta de la misión.",
                ["users", "groups", "service_relationships"])
        if "service_relationship_visibility" in capabilities:
            add("H-SERVICE-PATH",
                "Una relación de servicio observada puede justificar una nueva investigación de acceso o privilegio.",
                ["service_relationships", "access_transition"])
        if "policy_artifact_access" in capabilities:
            add("H-POLICY-DATA",
                "Los artefactos de política pueden contener información que habilite capacidades adicionales.",
                ["artifact_contents", "identity_material"])
        if "smb_access" in capabilities:
            add("H-RESOURCE-SURFACE",
                "El acceso SMB puede exponer recursos distintos con evidencia adicional.",
                ["shares", "files", "permissions"])
        if "privilege_signal" in capabilities:
            add("H-PRIVILEGE-TRANSITION",
                "La evidencia de privilegio puede representar una transición de capacidad que debe verificarse.",
                ["session", "privilege_context"])
        return hypotheses[:12]

    @staticmethod
    def generate_goals(hypotheses: List[Dict[str, Any]], capabilities: List[str]) -> List[Dict[str, Any]]:
        goals = []
        seen = set()
        mapping = {
            "directory_enumeration": "map_directory_relationships",
            "service_relationships": "map_service_relationships",
            "share_access": "map_accessible_resources",
            "artifact_contents": "understand_policy_artifacts",
            "identity_material": "validate_identity_capabilities",
            "access_transition": "validate_capability_transition",
            "users": "enumerate_identity_surface",
            "groups": "enumerate_group_relationships",
            "files": "discover_relevant_artifacts",
            "permissions": "map_resource_permissions",
            "session": "validate_session_capability",
            "privilege_context": "validate_privilege_context",
        }
        for hypothesis in hypotheses:
            for test in hypothesis.get("tests", []):
                goal = mapping.get(test)
                if goal and goal not in seen:
                    seen.add(goal)
                    goals.append({
                        "id": goal,
                        "source_hypothesis": hypothesis["id"],
                        "reason": hypothesis["statement"],
                        "status": "candidate",
                    })
        return goals[:16]

    def update(self, output: str, history: List[Dict[str, Any]]) -> Dict[str, Any]:
        old_facts = list(self.old.get("facts", []))
        new_facts = self.extract_facts(output)
        facts = self._unique(old_facts + new_facts, 256)
        capabilities = self.derive_capabilities(facts, history)
        hypotheses = self.generate_hypotheses(facts, capabilities)
        goals = self.generate_goals(hypotheses, capabilities)

        old_fact_set = {x.lower() for x in old_facts}
        newly_observed = [x for x in new_facts if x.lower() not in old_fact_set]
        return {
            "facts": facts,
            "new_facts": newly_observed[:32],
            "capabilities": capabilities,
            "hypotheses": hypotheses,
            "candidate_goals": goals,
        }

    def context(self) -> Dict[str, Any]:
        return {
            "facts": self.old.get("facts", [])[-64:],
            "capabilities": self.old.get("capabilities", []),
            "hypotheses": self.old.get("hypotheses", [])[:12],
            "candidate_goals": self.old.get("candidate_goals", [])[:16],
            "new_facts": self.old.get("new_facts", [])[:32],
        }
