from pathlib import Path
import os

from core.audit import AuditTrail
from core.kali_tools import KaliToolCatalog
from core.privesc_engine import PrivEscEngine
from core.session_manager import SessionManager
from core.failure_reasoner import FailureReasoner


def test_audit_uses_canonical_events_jsonl(tmp_path: Path):
    audit = AuditTrail(tmp_path)
    assert audit.events.name == "events.jsonl"


def test_kali_catalog_reads_executables_from_path(tmp_path: Path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    tool = bin_dir / "custom-kali-tool"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    catalog = KaliToolCatalog("10.129.1.2", tmp_path)
    items = catalog.discover()
    assert any(x["name"] == "custom-kali-tool" for x in items)


def test_privesc_engine_creates_evidence_backed_hypothesis():
    evidence = "sudo -l\nUser may run /usr/bin/find as root without password\n"
    hypotheses = PrivEscEngine().build_hypotheses(evidence)
    assert hypotheses
    assert hypotheses[0]["category"] == "sudo_misconfig"
    assert hypotheses[0]["evidence_lines"]


def test_session_manager_parses_structured_session():
    manager = SessionManager("10.129.1.2", lambda *_: '{"session_established": true, "session_id": "s1", "user": "htb"}')
    state = manager.establish({})
    assert state.connected
    assert state.session_id == "s1"
    assert state.user == "htb"


def test_failure_reasoner_has_nonempty_recovery_without_llm(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = FailureReasoner().reason({
        "failure_memory": [{
            "id": "1:exploit_candidate:cve",
            "action": "exploit_candidate",
            "candidate_id": "cve",
            "candidate": {"id": "cve"},
            "output": "exploit failed"
        }]
    })
    assert result["recovery_action"] in {"analyze_candidate", "replan"}
