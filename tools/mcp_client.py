import requests
import os

MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:5000/mcp")

def call_kali_mcp_tool(tool_name: str, arguments: dict) -> str:
    """
    Envía una petición estructurada al servidor MCP de Kali Linux para ejecutar
    una herramienta de pentesting de forma controlada.
    """
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        },
        "id": 1
    }

    try:
        response = requests.post(MCP_SERVER_URL, json=payload, timeout=90)
        if response.status_code == 200:
            data = response.json()
            return data.get("result", {}).get("content", [{}])[0].get("text", "Sin respuesta estructurada")
        else:
            return f"[-] Error de comunicación MCP: HTTP {response.status_code}"
    except Exception as e:
        return f"[-] Error crítico conectando con el servidor MCP de Kali: {str(e)}"