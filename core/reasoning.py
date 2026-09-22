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
        recent = history[-12:]
        text = " ".join(
            facts
            + [str(h.get("output", "")) for h in recent]
            + [str(h.get("command", "")) for h in recent]
        ).lower()
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
        """Canonicalize commands into semantic intent + resource scope.

        The scope keeps different SMB resources distinguishable while still
        preventing sterile re-enumeration of the same surface.
        """
        text = re.sub(r"\s+", " ", str(command or "").strip().lower())
        if not text:
            return "empty"
        if any(x in text for x in ("decrypt", "decode", "decipher", "base64", "aes.new", "openssl enc")):
            return "transform_credential_or_secret_material"
        if any(x in text for x in ("cat ", "head ", "tail ", "less ", "more ", "jq ", "xmllint ", "grep ", "sed ")):
            return "inspect_local_artifact"
        if "smbclient" in text:
            resource = "server"
            m = re.search(r"smbclient\s+[^ ]*//[^/\s]+/([^\s'\"]+)", text)
            if not m:
                m = re.search(r"//[^/\s]+/([^\s'\"]+)", text)
            if m:
                resource = re.sub(r"[^a-z0-9_.-]", "", m.group(1)) or "server"
            # A get/mget is retrieval, not merely inspection of the SMB surface.
            # Keep the resource scope so different shares remain distinct.
            if re.search(r"\b(?:mget|get|reget)\b", text):
                return f"retrieve_remote_artifact:{resource}"
            return f"inspect_smb_resource:{resource}"
        if any(x in text for x in ("get ", "mget ", "wget ", "curl ", "download")):
            return "retrieve_remote_artifact"
        if any(x in text for x in ("ldapsearch", "rpcclient", "enum4linux", "smbmap")):
            return "enumerate_remote_surface"
        return text[:180]

    @staticmethod
    def extract_entities(output: str) -> Dict[str, List[str]]:
        """Extract stable resource/identity names without target-specific assumptions."""
        text = str(output or "")
        entities = {"identities": [], "groups": [], "shares": [], "artifacts": [], "services": []}
        patterns = {
            "identities": (r"(?im)^\\s*(?:user|username|account|sAMAccountName)\\s*[:=]\\s*([A-Za-z0-9_.@\\\\-]+)",),
            "groups": (r"(?im)^\\s*(?:group|groupname|cn)\\s*[:=]\\s*([A-Za-z0-9_.@\\\\-]+)",),
            "shares": (r"(?im)^\\s*([A-Za-z0-9$_.-]{2,})\\s+(?:Disk|IPC|Printer|Remote|Special|Unknown)\\b",),
            "artifacts": (r"(?im)\\b([A-Za-z0-9_.-]+\\.(?:xml|ini|conf|config|txt|json|pcap))\\b",),
            "services": (r"(?im)\\b([A-Za-z0-9_.-]+/(?:[A-Za-z0-9_.-]+))\\b",),
        }
        for kind, pats in patterns.items():
            for pat in pats:
                entities[kind].extend(re.findall(pat, text))
        return {k: ReasoningState._unique(v, 64) for k, v in entities.items()}

    @classmethod
    def derive_resources(cls, history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Track discovered resources and whether they have been inspected."""
        resources = {}
        for h in history[-64:]:
            output = str(h.get("output", ""))
            entities = cls.extract_entities(output)
            for share in entities["shares"]:
                key = share.lower()
                resources.setdefault(key, {"name": share, "type": "share", "observed_steps": [], "inspected_steps": []})
                resources[key]["observed_steps"].append(h.get("step"))
                if "smbclient" in str(h.get("command", "")).lower():
                    resources[key]["inspected_steps"].append(h.get("step"))
        return list(resources.values())[-64:]

    @staticmethod
    def derive_vulnerability_signals(
        facts: List[str], capabilities: List[str], history: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Derive generic vulnerability signals from observed evidence and actions.

        Signals are evidence abstractions, not target-specific playbooks and never
        contain exploit payloads or commands.
        """
        recent = history[-16:]
        text = " ".join(
            facts
            + [str(h.get("output", "")) for h in recent]
            + [str(h.get("command", "")) for h in recent]
        ).lower()
        signals: Dict[str, Any] = {}

        def signal(name: str, strength: float, evidence: List[str], info_gain: float, cost: float):
            signals[name] = {
                "strength": round(max(0.0, min(1.0, strength)), 3),
                "evidence": evidence[-8:],
                "expected_information_gain": round(max(0.0, min(1.0, info_gain)), 3),
                "cost": round(max(0.0, min(1.0, cost)), 3),
            }

        if re.search(r"anonymous|guest|unauthenticated|['"]%['"]|\b-u\s+['"]?['"]?|\s-n\b", text):
            signal(
                "anonymous_remote_access", 0.9,
                ["anonymous/unauthenticated remote access observed"],
                0.85, 0.2
            )

        if "smb_access" in capabilities and re.search(r"replication|sysvol|netlogon|gpo|group policy|policy artifact", text):
            signal(
                "policy_share_exposure", 0.95,
                ["SMB policy/domain share evidence observed"],
                0.95, 0.2
            )

        if re.search(r"\b(?:groups?\.xml|cpassword|gpp|group policy preference|policy artifact)\b", text):
            signal(
                "policy_artifact_exposure", 1.0,
                ["policy artifact or GPP indicator observed"],
                1.0, 0.15
            )

        if re.search(r"\b(?:spn|serviceprincipalname|kerberos|cifs/)\b", text):
            signal(
                "service_identity_relationship", 0.85,
                ["service identity relationship observed"],
                0.8, 0.35
            )

        if re.search(r"\b(?:password|credential|cpassword|secret|hash|ntlm)\b", text):
            signal(
                "credential_material_exposure", 0.95,
                ["credential/secret material indicator observed"],
                0.95, 0.25
            )

        if re.search(r"\b(?:administrator|system|root|privilege|delegation)\b", text):
            signal(
                "privilege_transition_signal", 0.8,
                ["privilege-related evidence observed"],
                0.8, 0.45
            )
        return signals

    @staticmethod
    def generate_hypotheses(
        facts: List[str], capabilities: List[str], history: List[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        history = history or []
        signals = ReasoningState.derive_vulnerability_signals(facts, capabilities, history)
        hypotheses = []

        def add(
            hid: str, statement: str, tests: List[str], signal_names: List[str],
            expected_information_gain: float, cost: float
        ):
            evidence = []
            strength = 0.0
            for name in signal_names:
                item = signals.get(name)
                if item:
                    strength = max(strength, float(item.get("strength", 0.0)))
                    evidence.extend(item.get("evidence", []))
            hypotheses.append({
                "id": hid,
                "statement": statement,
                "tests": tests,
                "evidence": list(dict.fromkeys(evidence))[-8:],
                "confidence": round(strength, 3),
                "expected_information_gain": round(expected_information_gain, 3),
                "cost": round(cost, 3),
            })

        if signals.get("policy_artifact_exposure") or signals.get("policy_share_exposure"):
            add(
                "H-POLICY-EXPOSURE",
                "Los recursos de políticas accesibles pueden contener artefactos de configuración que revelen material sensible o nuevas capacidades.",
                ["artifact_contents", "identity_material", "capability_transition"],
                ["policy_artifact_exposure", "policy_share_exposure"],
                0.98, 0.15
            )

        if signals.get("credential_material_exposure"):
            add(
                "H-CREDENTIAL-MATERIAL",
                "La evidencia de material de autenticación puede permitir identificar una capacidad reutilizable y debe validarse antes de cambiar de superficie.",
                ["identity_material", "capability_transition"],
                ["credential_material_exposure"],
                0.95, 0.25
            )

        if signals.get("service_identity_relationship"):
            add(
                "H-SERVICE-IDENTITY",
                "Las relaciones entre identidades y servicios pueden revelar una vía adicional de autenticación o privilegio.",
                ["service_relationships", "capability_transition"],
                ["service_identity_relationship"],
                0.85, 0.35
            )

        if "authenticated_identity" in capabilities:
            add(
                "H-AUTH-EXPANSION",
                "La identidad obtenida puede habilitar nuevas relaciones o recursos que no eran visibles antes.",
                ["directory_enumeration", "share_access", "service_relationships"],
                [],
                0.75, 0.3
            )

        if "directory_enumeration" in capabilities:
            add(
                "H-AD-RELATIONSHIPS",
                "La superficie de directorio puede contener relaciones entre identidades, grupos y servicios que cambien la ruta de la misión.",
                ["users", "groups", "service_relationships"],
                [],
                0.7, 0.3
            )

        if "service_relationship_visibility" in capabilities:
            add(
                "H-SERVICE-PATH",
                "Una relación de servicio observada puede justificar una nueva investigación de acceso o privilegio.",
                ["service_relationships", "access_transition"],
                ["service_identity_relationship"],
                0.8, 0.4
            )

        if "smb_access" in capabilities:
            add(
                "H-RESOURCE-SURFACE",
                "El acceso SMB puede exponer recursos distintos con evidencia adicional.",
                ["shares", "files", "permissions"],
                [],
                0.55, 0.35
            )

        if "privilege_signal" in capabilities:
            add(
                "H-PRIVILEGE-TRANSITION",
                "La evidencia de privilegio puede representar una transición de capacidad que debe verificarse.",
                ["session", "privilege_context"],
                ["privilege_transition_signal"],
                0.8, 0.45
            )

        return hypotheses[:12]

    @staticmethod
    def score_hypotheses(
        hypotheses: List[Dict[str, Any]],
        capabilities: List[str],
        history: List[Dict[str, Any]],
        old: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Rank hypotheses using explicit progress and information-gain signals."""
        ranked = []
        for h in hypotheses:
            hid = h.get("id")
            if not hid:
                continue
            tests = [e for e in history if e.get("hypothesis_id") == hid]
            progress = sum(1 for e in tests if e.get("no_new_evidence") is False)
            no_progress = sum(1 for e in tests if e.get("no_new_evidence") is True)
            # Best-first bias: unexplored hypotheses are valuable; sterile ones decay.
            score = 1.0 + (2.0 if not tests else 0.0)
            score += 1.5 * progress
            score -= 1.25 * no_progress
            score += min(1.5, 0.25 * len(capabilities))
            score += 2.0 * float(h.get("confidence", 0.0))
            score += 2.5 * float(h.get("expected_information_gain", 0.0))
            score -= 1.0 * float(h.get("cost", 0.0))
            item = dict(h)
            item["control"] = {
                "score": round(max(0.0, score), 3),
                "tests": len(tests),
                "progress_events": progress,
                "no_progress": no_progress,
                "status": "promising" if score >= 2.0 else "deprioritized",
                "confidence": h.get("confidence", 0.0),
                "expected_information_gain": h.get("expected_information_gain", 0.0),
                "cost": h.get("cost", 0.0),
            }
            ranked.append(item)
        return sorted(ranked, key=lambda x: x.get("control", {}).get("score", 0), reverse=True)[:12]

    @staticmethod
    def control_signal(hypotheses: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not hypotheses:
            return {"mode": "explore", "reason": "no_hypotheses", "hypothesis": None}
        top = hypotheses[0].get("control", {})
        sterile = int(top.get("no_progress", 0))
        tests = int(top.get("tests", 0))
        progress = int(top.get("progress_events", 0))
        if sterile >= 3:
            return {"mode": "switch_hypothesis", "reason": "hypothesis_sterile",
                    "hypothesis": hypotheses[0].get("id")}
        if tests >= 4 and progress == 0:
            return {"mode": "switch_hypothesis", "reason": "low_information_gain",
                    "hypothesis": hypotheses[0].get("id")}
        return {"mode": "continue", "reason": "expected_information_gain",
                "hypothesis": hypotheses[0].get("id")}

    @staticmethod
    def build_hypothesis_control(hypotheses: List[Dict[str, Any]], control_signal: Dict[str, Any], old: Dict[str, Any]) -> Dict[str, Any]:
        """Runtime-enforced hypothesis lease; the LLM cannot spend attempts on a sterile hypothesis."""
        previous = dict(old.get("hypothesis_control") or {})
        leases = dict(previous.get("leases") or {})
        deprioritized = set(previous.get("deprioritized") or [])
        exhausted = set(previous.get("exhausted") or [])
        active = control_signal.get("hypothesis")

        for hypothesis in hypotheses:
            hid = hypothesis.get("id")
            if not hid:
                continue
            control = hypothesis.get("control", {})
            tests = int(control.get("tests", 0))
            sterile = int(control.get("no_progress", 0))
            progress = int(control.get("progress_events", 0))
            leases[hid] = {
                "tests": tests, "progress_events": progress, "no_progress": sterile,
                "budget": max(0, 3 - sterile), "status": "ACTIVE",
            }
            if sterile >= 3 or (tests >= 4 and progress == 0):
                deprioritized.add(hid)
                leases[hid]["status"] = "DEPRIORITIZED"
            elif hid in deprioritized and sterile == 0:
                deprioritized.discard(hid)
            if hid == active and hid not in deprioritized:
                leases[hid]["status"] = "ACTIVE"

        known_ids = {h.get("id") for h in hypotheses}
        deprioritized &= known_ids
        exhausted &= known_ids
        candidates = [h for h in hypotheses if h.get("id") not in deprioritized and h.get("id") not in exhausted]
        selected = candidates[0].get("id") if candidates else None
        return {
            "mode": "switch" if control_signal.get("mode") == "switch_hypothesis" else "continue",
            "active_hypothesis": selected,
            "controller_hypothesis": active,
            "deprioritized": sorted(deprioritized),
            "exhausted": sorted(exhausted),
            "leases": leases,
        }

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
        hypotheses = self.generate_hypotheses(facts, capabilities, history)
        hypotheses = self.score_hypotheses(hypotheses, capabilities, history, self.old)
        control = self.control_signal(hypotheses)
        hypothesis_control = self.build_hypothesis_control(hypotheses, control, self.old)
        goals = self.generate_goals(hypotheses, capabilities)
        vulnerability_signals = self.derive_vulnerability_signals(facts, capabilities, history)
        entities = self.extract_entities(output)
        resources = self.derive_resources(history + [{"output": output, "command": history[-1].get("command", "") if history else "", "step": history[-1].get("step") if history else None}])

        old_fact_set = {x.lower() for x in old_facts}
        newly_observed = [x for x in new_facts if x.lower() not in old_fact_set]
        return {
            "facts": facts,
            "new_facts": newly_observed[:32],
            "capabilities": capabilities,
            "hypotheses": hypotheses,
            "vulnerability_signals": vulnerability_signals,
            "hypothesis_scores": {h.get("id"): h.get("control", {}) for h in hypotheses if h.get("id")},
            "control_signal": control,
            "hypothesis_control": hypothesis_control,
            "candidate_goals": goals,
            "entities": entities,
            "resources": resources,
        }

    def context(self) -> Dict[str, Any]:
        return {
            "facts": self.old.get("facts", [])[-64:],
            "capabilities": self.old.get("capabilities", []),
            "hypotheses": self.old.get("hypotheses", [])[:12],
            "vulnerability_signals": self.old.get("vulnerability_signals", {}),
            "hypothesis_scores": self.old.get("hypothesis_scores", {}),
            "control_signal": self.old.get("control_signal", {"mode": "explore"}),
            "hypothesis_control": self.old.get("hypothesis_control", {}),
            "candidate_goals": self.old.get("candidate_goals", [])[:16],
            "new_facts": self.old.get("new_facts", [])[:32],
            "entities": self.old.get("entities", {}),
            "resources": self.old.get("resources", [])[-64:],
        }
