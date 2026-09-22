# tools/mcp_router.py
import subprocess
import logging

logger = logging.getLogger("MCPRouter")

def call_kali_tool(tool_name: str, tool_args: str, timeout: int = 600) -> str:
    """
    Ejecuta herramientas de Kali Linux de forma segura con un timeout configurable (por defecto 10 min).
    """
    command = f"{tool_name} {tool_args}"
    logger.info(f"[*] [Kali Tool Execution] Lanzando comando: {command}")
    
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        output = result.stdout.strip() if result.stdout else ""
        error_output = result.stderr.strip() if result.stderr else ""
        
        if result.returncode != 0 and error_output:
            return f"Salida con código {result.returncode}.\nSTDOUT: {output}\nSTDERR: {error_output}"
            
        return output if output else f"Comando ejecutado con código de salida {result.returncode} (Sin salida estándar)."
        
    except subprocess.TimeoutExpired:
        logger.error(f"[-] Timeout de ejecución superado para el comando: {command}")
        return "ERROR: Timeout de ejecución superado para este comando."
    except Exception as e:
        logger.error(f"[-] Excepción ejecutando herramienta: {str(e)}")
        return f"ERROR: {str(e)}"