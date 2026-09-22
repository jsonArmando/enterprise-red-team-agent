from core.line_analyzer import analyze_all_lines, correlate_cves
from core.flags import mission_status
from pathlib import Path

def test_every_line_is_ledgered():
    text="1/tcp open ssh\n\nCVE-2024-1234 vulnerable\nother line"
    ledger=analyze_all_lines(text)
    assert [x["line"] for x in ledger]==[1,2,3,4]
    assert ledger[2]["cves"]==["CVE-2024-1234"]

def test_cve_keeps_nearby_evidence_lines():
    items=correlate_cves("10.129.1.2","22/tcp open ssh OpenSSH\nCVE-2024-1234 vulnerable","scanner")
    assert items[0]["cve"]=="CVE-2024-1234"
    assert any(x["line"]==1 for x in items[0]["evidence_lines"])

def test_completion_requires_both_flags(tmp_path:Path):
    user="a"*32
    root="b"*32
    out=[f"user.txt {user}", f"root.txt {root}"]
    status=mission_status(out,tmp_path)
    assert status["user_ok"] and status["root_ok"] and status["complete"]