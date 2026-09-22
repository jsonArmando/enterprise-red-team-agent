import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("KaliScanner")

def run_nmap_recon(target: str) -> str:
    """
    Ejecuta un escaneo seguro de puertos y servicios usando nmap en Kali Linux.
    """
    logger.info(f"[*] [KaliScanner] Iniciando reconocimiento sobre: {target}")
    
    # Comando nmap optimizado para velocidad y precisión en laboratorios
    command = ["nmap", "-sV", "--top-ports", "100", "-T4", target]
    
    try:
        result = subprocess.run(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            timeout=120
        )
        if result.returncode != 0:
            return f"Error ejecutando nmap: {result.stderr.strip()}"
        return result.stdout
    except subprocess.TimeoutExpired:
        return "[-] Error: El tiempo de ejecución del escaneo de nmap expiró."
    except Exception as e:
        return f"[-] Error crítico en la herramienta de escaneo: {str(e)}"
