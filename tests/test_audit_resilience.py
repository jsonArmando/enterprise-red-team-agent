import json

from core.audit import AuditTrail


def test_record_accepts_event_type_in_payload_and_positional(tmp_path):
    audit = AuditTrail(tmp_path)
    event = {"event_type": "execution", "action": "recon", "output": "ok"}

    # Regression: main.save historically called record(event_type, **event).
    audit.record(event.get("event_type", "state"), **event)

    rows = audit.events.read_text(encoding="utf-8").splitlines()
    assert len(rows) == 1
    saved = json.loads(rows[0])
    assert saved["event_type"] == "execution"
    assert saved["action"] == "recon"


def test_record_payload_only_event_type(tmp_path):
    audit = AuditTrail(tmp_path)
    audit.record(event_type="decision", action="replan")

    saved = json.loads(audit.events.read_text(encoding="utf-8").splitlines()[0])
    assert saved["event_type"] == "decision"
    assert saved["action"] == "replan"
