import sys
from core.graph import build_redteam_graph

def main():
    # Validar que se proporcione el objetivo de forma obligatoria
    if len(sys.argv) < 2:
        print("[-] Error crítico: No se ha especificado ningún objetivo.")
        print("[*] Uso correcto: python3 main.py <IP_O_DOMINIO_OBJETIVO>")
        sys.exit(1)

    target_ip = sys.argv[1]

    print(f"[*] ----------------------------------------------------")
    print(f"[*] AGENTE RED TEAM LANGGRAPH (Arquitectura Grow) [KALI]")
    print(f"[*] Objetivo Autorizado: {target_ip}")
    print(f"[*] ----------------------------------------------------")

    # Compilar el grafo
    agent_app = build_redteam_graph()

    # Estado inicial de la misión
    initial_state = {
        "target": target_ip,
        "task_queue": [],
        "completed_targets": [],
        "findings": [],
        "current_phase": "recon",
        "logs": []
    }

    try:
        # Ejecución síncrona del grafo LangGraph
        final_state = agent_app.invoke(initial_state)

        print("\n[*] ========================================")
        print("[+] MISIÓN DE RECONOCIMIENTO Y GROW FINALIZADA")
        print(f"[*] ========================================")
        print(f"[+] Objetivos analizados: {final_state.get('completed_targets')}")
        print(f"[+] Total de hallazgos registrados: {len(final_state.get('findings'))}")
        
        print("\n[+] Resumen de Logs de Auditoría:")
        for log in final_state.get("logs", []):
            print(f"    - {log}")

    except Exception as e:
        print(f"[-] Error crítico durante la ejecución del grafo: {str(e)}")

if __name__ == "__main__":
    main()
