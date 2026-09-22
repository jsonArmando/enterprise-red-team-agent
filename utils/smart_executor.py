import subprocess
import time
import logging

logger = logging.getLogger("EnterpriseAgent")

class SmartCommandExecutor:
    def __init__(self, timeout_minutes=20, poll_interval=30):
        self.timeout_minutes = timeout_minutes
        self.poll_interval = poll_interval

    def execute_with_polling(self, command: str) -> dict:
        """
        Ejecuta cualquier comando de Kali Linux de forma no bloqueante, monitoreándolo 
        cada `poll_interval` segundos. Si detecta un estado interactivo colgante (como smbclient sin -c),
        lo intercepta, y respeta el timeout máximo configurado en `timeout_minutes`.
        """
        logger.info(f"[*] [SmartExecutor] Lanzando comando: {command}")
        
        # Iniciar proceso en segundo plano de forma dinámica
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffered
        )

        start_time = time.time()
        max_duration = self.timeout_minutes * 60
        accumulated_stdout = ""
        accumulated_stderr = ""

        while True:
            elapsed_time = time.time() - start_time
            
            # 1. Comprobar si el proceso terminó por sí mismo de forma natural
            retcode = process.poll()
            if retcode is not None:
                remaining_out, remaining_err = process.communicate()
                accumulated_stdout += remaining_out
                accumulated_stderr += remaining_err
                logger.info(f"[+] [SmartExecutor] El proceso finalizó de manera natural con código {retcode}.")
                return {
                    "stdout": accumulated_stdout,
                    "stderr": accumulated_stderr,
                    "returncode": retcode,
                    "status": "completed"
                }

            # 2. Comprobar si se superó el límite de tiempo máximo
            if elapsed_time > max_duration:
                logger.warning(f"[-] [SmartExecutor] Timeout alcanzado ({self.timeout_minutes} min). Matando proceso PID {process.pid}...")
                process.kill()
                remaining_out, remaining_err = process.communicate()
                accumulated_stdout += remaining_out
                accumulated_stderr += remaining_err
                return {
                    "stdout": accumulated_stdout + "\n[!] Proceso terminado por timeout de seguridad del agente.",
                    "stderr": accumulated_stderr,
                    "returncode": -9,
                    "status": "timeout_killed"
                }

            # 3. Sondeo periódico (cada 30 segundos)
            time.sleep(self.poll_interval)
            logger.info(f"[*] [SmartExecutor] Monitoreando... Tiempo transcurrido: {int(elapsed_time)}s / {max_duration}s")

            # 4. Control inteligente para comandos interactivos colgados (ej. smbclient abierto sin argumentos de salida)
            if "smbclient" in command and elapsed_time > 60 and not "-c" in command:
                logger.warning(f"[!] [SmartExecutor] Detectado smbclient interactivo abierto por más de 60s sin salir. Forzando cierre...")
                process.terminate()
                time.sleep(2)
                if process.poll() is None:
                    process.kill()
                return {
                    "stdout": accumulated_stdout + "\n[!] smbclient cerrado preventivamente por el agente para evitar bloqueo interactivo.",
                    "stderr": accumulated_stderr,
                    "returncode": 0,
                    "status": "intercepted_interactive"
                }

# Bloque de prueba genérico (sin valores hardcodeados)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    executor = SmartCommandExecutor(timeout_minutes=20, poll_interval=30)
    logger.info("[*] SmartCommandExecutor inicializado correctamente y listo para importación.")
