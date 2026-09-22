"""Low-level Kali process router with argument isolation."""
from __future__ import annotations
import logging
import shlex
import subprocess

logger=logging.getLogger("KaliRouter")

def call_kali_tool(tool_name:str, tool_args:str, timeout:int=600)->str:
    command=f"{tool_name} {tool_args}".strip()
    logger.info("[Kali Tool] %s",command)
    try:
        argv=shlex.split(command)
        result=subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output=result.stdout.strip() if result.stdout else ""
        error=result.stderr.strip() if result.stderr else ""
        if result.returncode != 0:
            return f"Salida con código {result.returncode}.\\nSTDOUT: {output}\\nSTDERR: {error}"
        return output if output else f"Comando ejecutado con código 0 (Sin salida estándar)."
    except subprocess.TimeoutExpired:
        logger.error("Timeout ejecutando %s",command)
        return "ERROR: Timeout de ejecución superado para este comando."
    except Exception as exc:
        logger.error("Excepción ejecutando %s: %s",command,exc)
        return f"ERROR: {exc}"
