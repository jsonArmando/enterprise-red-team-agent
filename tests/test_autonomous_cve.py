from core.cve_engine import extract_cves, build_inventory
from core.objective import next_objective

def test_extract_cves():
    assert extract_cves("CVE-2024-1234 and cve-2024-1234") == ["CVE-2024-1234"]

def test_inventory():
    items=build_inventory("10.129.1.2","445/tcp open smb CVE-2024-1234")
    assert items[0]["cve"]=="CVE-2024-1234"
    assert items[0]["port"]==445

def test_objective_progression():
    assert next_objective({"user_verified":False,"root_verified":False})=="obtain_user_flag"
    assert next_objective({"user_verified":True,"root_verified":False})=="obtain_root_flag"
    assert next_objective({"user_verified":True,"root_verified":True})=="complete"
