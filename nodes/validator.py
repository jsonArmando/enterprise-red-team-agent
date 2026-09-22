from core.state import RedTeamState
from tools.mcp_router import call_mcp_domain

def validator_node(state: RedTeamState) -> dict:
    """
    Validador estricto: Ejecuta una prueba de concepto mínima (PoC) para descartar falsos positivos.
    """
    print("[*] [Validator Node] Verificando evidencia de vulnerabilidad...")
    
    latest_finding = state["findings"][-1] if state["findings"] else {}
    target = latest_finding.get("target")
    
    # Invocar herramienta ligera de verificación vía Verification MCP
    validation_output = call_mcp_domain(
        domain="verify",
        tool_name="http_status_check",
        arguments={"target": target, "expected_behavior": "response_diff"}
    )
    
    # Criterio de validación booleano
    is_valid = "VULNERABILITY_CONFIRMED" in validation_output
    
    if is_valid:
        print(f"[+] [Validator] Evidencia CONFIRMADA para {target}.")
        status = "verified"
    else:
        print(f"[-] [Validator] Descartado: Falso positivo o vector cerrado en {target}.")
        status = "rejected"

    return {
        "current_phase": "grow" if is_valid else "plan",
        "logs": [f"Validación para {target}: {status}"]
    }