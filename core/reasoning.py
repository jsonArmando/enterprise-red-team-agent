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
    def extract_facts(cls, output: str, command: str = "") -> List[str]:
        """Extract evidence without requiring benchmark-specific keywords."""
        facts = []
        cmd = str(command or "").lower()
        for raw in str(output or "").splitlines():
            line = cls._norm(raw)
            if len(line) < 3:
                continue
            lower = line.lower()
            if lower.startswith(("warning:", "error:", "debug:", "traceback")):
                continue
            structured = bool(re.search(
                r"^(?:dn|dc|ou|cn|uid|member|memberof|samaccountname|userprincipalname|objectclass|"
                r"namingcontexts|defaultnamingcontext|distinguishedname|serviceprincipalname|"
                r"port|state|service|version|host|address|server|share)\s*[:=]",
                line, re.I
            ))
            if "ldapsearch" in cmd:
                structured = structured or bool(re.search(
                    r"^(?:dn|objectclass|namingcontexts|defaultnamingcontext|distinguishedname|"
                    r"cn|ou|dc|samaccountname|userprincipalname|memberof|serviceprincipalname)\s*[:=]",
                    line, re.I
                ))
            if structured or any(pattern.search(line) for _, pattern in cls._PATTERNS):
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
        # --- Generic service/surface map (any technology, not just AD) -------
        surface_patterns = {
            "web_surface": r"\b(?:80/tcp|443/tcp|8080/tcp|8000/tcp|8443/tcp|http|https|nginx|apache|iis|werkzeug|tomcat|php|http-title|http-server-header)\b",
            "ssh_surface": r"\b(?:22/tcp|ssh|openssh)\b",
            "ftp_surface": r"\b(?:21/tcp|ftp|vsftpd|proftpd|filezilla)\b",
            "smb_surface": r"\b(?:445/tcp|139/tcp|microsoft-ds|netbios-ssn|smb|cifs)\b",
            "ldap_visibility": r"\b(?:ldap|389/tcp|636/tcp|3268/tcp)\b",
            "rpc_surface": r"\b(?:135/tcp|msrpc|rpcbind|111/tcp)\b",
            "db_surface": r"\b(?:3306/tcp|5432/tcp|1433/tcp|1521/tcp|27017/tcp|mysql|mariadb|postgres|mssql|oracle|mongodb|redis|6379/tcp)\b",
            "mail_surface": r"\b(?:25/tcp|110/tcp|143/tcp|smtp|imap|pop3)\b",
            "dns_surface": r"\b(?:53/tcp|53/udp|domain\b|named|bind)\b",
            "winrm_surface": r"\b(?:5985/tcp|5986/tcp|winrm|wsman)\b",
            "kerberos_surface": r"\b(?:88/tcp|kerberos|krb5)\b",
        }
        for cap, pat in surface_patterns.items():
            if re.search(pat, text):
                capabilities.append(cap)
        # --- Generic exploitation-relevant signals --------------------------
        if re.search(r"\b(?:open|accessible|listing|read only|read/write|anonymous).{0,80}\b(?:smb|cifs|share|ftp)\b|\b(?:smb|cifs|ftp).{0,80}\b(?:accessible|anonymous|read)\b", text):
            capabilities.append("anonymous_access")
            if "smb_surface" in capabilities:  # alias kept for AD templates/grounding
                capabilities.append("smb_access")
        if "valid_cred:" in text or re.search(r"\b(?:authenticated|authentication|credential|password|cpassword|logon successful|login successful)\b", text):
            capabilities.append("authenticated_identity")
        if re.search(r"\b(?:objectclass=|sAMAccountName|active directory|domain controller)\b", text):
            capabilities.append("directory_enumeration")
        if re.search(r"\b(?:spn|serviceprincipalname|kerberos|cifs/|krb5tgs)\b", text):
            capabilities.append("service_relationship_visibility")
        if re.search(r"/[a-z0-9_.-]+\.(?:php|asp|aspx|jsp|cgi)|index of /|directory listing|/admin|/login|\bupload\b|\bparameter\b|\?[a-z_]+=|/api/", text):
            capabilities.append("web_content_discovered")
        if re.search(r"\b(?:cve-\d{4}-\d+|vulnerable|exploit|outdated|end of life|deprecated)\b", text):
            capabilities.append("known_vulnerability_signal")
        if re.search(r"\b(?:shell|session|wmiexec|psexec|winrm|evil-winrm|interactive|meterpreter|reverse shell|uid=|whoami)\b", text):
            capabilities.append("remote_session")
        if re.search(r"\b(?:administrator|nt authority|system|root|uid=0|sudo|privilege|seimpersonate|setuid)\b", text):
            capabilities.append("privilege_signal")
        if re.search(r"\b(?:gpo|groups\.xml|sysvol|replication|cpassword)\b", text):
            capabilities.append("policy_artifact_access")
        return cls._unique(capabilities, 32)

    # Optional LLM hypothesis engine, wired once by the runtime. When present it
    # supersedes the static AD templates so the agent generalizes to any target.
    _hypothesis_engine = None

    @classmethod
    def set_hypothesis_engine(cls, engine):
        cls._hypothesis_engine = engine

    @classmethod
    def _dynamic_hypotheses(cls, facts, capabilities, history, entities):
        """Prefer LLM-generated hypotheses; fall back to static templates."""
        engine = cls._hypothesis_engine
        if engine is not None and getattr(engine, "available", lambda: False)():
            world = {
                "facts": [str(f) for f in facts[-80:]],
                "capabilities": list(capabilities),
                "entities": entities,
                "recent_commands": [str(h.get("command", "")) for h in history[-8:] if h.get("event_type") == "action"],
            }
            try:
                raw = engine.generate(world)
            except Exception:
                raw = []
            hyps = []
            for h in raw or []:
                if not isinstance(h, dict) or not str(h.get("id") or "").strip():
                    continue
                hyps.append({
                    "id": str(h.get("id")).strip()[:48],
                    "statement": str(h.get("statement", ""))[:400],
                    "tests": [str(t)[:60] for t in (h.get("tests") or []) if str(t).strip()][:8],
                    "evidence": [],
                    "confidence": round(cls._clamp(h.get("confidence", 0.5)), 3),
                    "expected_information_gain": round(cls._clamp(h.get("expected_information_gain", 0.6)), 3),
                    "cost": round(cls._clamp(h.get("cost", 0.3)), 3),
                })
            if hyps:
                return hyps[:12]
        # Fallback: static AD-oriented templates (offline / no API key).
        return cls.generate_hypotheses(facts, capabilities, history)

    @staticmethod
    def _clamp(v, lo=0.0, hi=1.0):
        try:
            return max(lo, min(hi, float(v)))
        except (TypeError, ValueError):
            return 0.5

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
        if "ldapsearch" in text:
            base = "default"
            m = re.search(r"\s-b\s+([^\s]+)", text)
            if m:
                base = re.sub(r"[^a-z0-9=,._-]", "", m.group(1))
            scope = "base" if re.search(r"\s-s\s+base\b", text) else ("one" if re.search(r"\s-s\s+one\b", text) else "sub")
            filt = "none"
            m = re.search(r"\s(\([^)]{3,160}\))", text)
            if m:
                filt = re.sub(r"\s+", "", m.group(1))
            attrs = text.split()[-6:]
            attr_key = ",".join(sorted(a for a in attrs if re.fullmatch(r"[a-z][a-z0-9-]{1,40}", a)))
            return f"enumerate_ldap:{base}:{scope}:{filt}:{attr_key}"
        if any(x in text for x in ("rpcclient", "enum4linux", "smbmap")):
            return "enumerate_remote_surface"
        return text[:180]

    # smbclient recursive listing: a directory header line begins with a
    # backslash-rooted path; file entries follow, indented, with attribute
    # flags + size + date. Reconstructing full paths from this output is what
    # lets the planner issue an exact `get <path>` instead of guessing.
    _SMB_DIR_HEADER = re.compile(r"^\\[^\r\n]*$")
    _SMB_ENTRY = re.compile(r"^\s+(.+?)\s{2,}([DAHSRNI]+)\s+(\d+)\s+\w{3}\s+\w{3}\s+\d")

    @classmethod
    def parse_smb_listing(cls, output: str) -> List[str]:
        """Reconstruct full \\dir\\file paths from smbclient recursive listings.

        Directories are skipped; only file entries are returned. Content-based
        (not command-based) so it also works when the listing was saved to a
        file and later inspected.
        """
        paths: List[str] = []
        current = None
        for raw in str(output or "").splitlines():
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            if cls._SMB_DIR_HEADER.match(line) and "\\" in line[1:]:
                current = line.strip().rstrip("\\")
                continue
            m = cls._SMB_ENTRY.match(line)
            if m and current is not None:
                name, flags = m.group(1).strip(), m.group(2)
                if name in (".", "..") or "D" in flags:
                    continue
                paths.append(f"{current}\\{name}")
        return cls._unique(paths, 64)

    @staticmethod
    def extract_entities(output: str) -> Dict[str, List[str]]:
        """Extract stable resource/identity names without target-specific assumptions."""
        text = str(output or "")
        entities = {"identities": [], "groups": [], "shares": [], "artifacts": [], "services": []}
        patterns = {
            "identities": (r"(?im)^\s*(?:user|username|account|sAMAccountName)\s*[:=]\s*([A-Za-z0-9_.@\-]+)",),
            "groups": (r"(?im)^\s*(?:group|groupname|cn)\s*[:=]\s*([A-Za-z0-9_.@\-]+)",),
            "shares": (r"(?im)^\s*([A-Za-z0-9$_.-]{2,})\s+(?:Disk|IPC|Printer|Remote|Special|Unknown)\b",),
            "artifacts": (r"(?im)\b([A-Za-z0-9_.-]+\.(?:xml|ini|conf|config|txt|json|pcap))\b",),
            "services": (r"(?im)\b([A-Za-z0-9_.-]+/(?:[A-Za-z0-9_.-]+))\b",),
        }
        for kind, pats in patterns.items():
            for pat in pats:
                entities[kind].extend(re.findall(pat, text))
        # Full SMB paths (with directory context) are the most actionable
        # artifacts: they tell the planner exactly what to `get`.
        entities["artifacts"].extend(ReasoningState.parse_smb_listing(text))
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

        if re.search(r'anonymous|guest|unauthenticated|[\'"]%[\'"]|\b-u\s+[\'"]?[\'"]?|\s-n\b', text):
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

        if "smb_surface" in capabilities or "smb_access" in capabilities:
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
            "smb_surface": "enumerate_remote_resources",
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
                # Known tests get a friendly goal id; unknown (LLM-proposed)
                # tests are slugified so any surface produces actionable goals.
                goal = mapping.get(test) or ("investigate_" + re.sub(r"[^a-z0-9]+", "_", str(test).lower()).strip("_"))[:60]
                if goal and goal not in seen:
                    seen.add(goal)
                    goals.append({
                        "id": goal,
                        "source_hypothesis": hypothesis.get("id"),
                        "reason": hypothesis.get("statement", ""),
                        "status": "candidate",
                    })
        return goals[:16]

    def update(self, output: str, history: List[Dict[str, Any]], command: str = "") -> Dict[str, Any]:
        old_facts = list(self.old.get("facts", []))
        new_facts = self.extract_facts(output, command)
        # Surface reconstructed SMB file paths as first-class facts so the
        # planner can target an exact `get` and grounding recognizes them.
        smb_paths = [f"smb_file: {p}" for p in self.parse_smb_listing(output)]
        new_facts = self._unique(new_facts + smb_paths, 128)
        facts = self._unique(old_facts + new_facts, 256)
        capabilities = self.derive_capabilities(facts, history)
        entities = self.extract_entities(output)
        old_fact_set_pre = {x.lower() for x in old_facts}
        has_new_evidence = any(x.lower() not in old_fact_set_pre for x in new_facts)
        prior_hyps = list(self.old.get("hypotheses", []))
        # Regenerate hypotheses only when evidence changed (bounds LLM cost);
        # otherwise re-score the prior set so control/leases still update.
        if has_new_evidence or not prior_hyps:
            base_hyps = self._dynamic_hypotheses(facts, capabilities, history, entities)
        else:
            base_hyps = [{k: h.get(k) for k in ("id","statement","tests","evidence","confidence","expected_information_gain","cost")} for h in prior_hyps if h.get("id")]
        hypotheses = self.score_hypotheses(base_hyps, capabilities, history, self.old)
        control = self.control_signal(hypotheses)
        hypothesis_control = self.build_hypothesis_control(hypotheses, control, self.old)
        goals = self.generate_goals(hypotheses, capabilities)
        vulnerability_signals = self.derive_vulnerability_signals(facts, capabilities, history)
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
