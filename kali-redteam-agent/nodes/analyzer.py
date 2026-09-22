import os
from core.state import RedTeamState
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from dotenv import load_dotenv

load_dotenv()

def analyzer_node(state: RedTeamState) -> dict:
    """
    Nodo analizador corregido para evitar la duplicación de esquemas HTTP en el bucle grow.
    """
    print("[*] [Analyzer Node] Procesando resultados del escaneo...")
    
    latest_finding = state["findings"][-1]["data"] if state["findings"] else ""
    current_target = state["completed_targets"][-1]

    # Limpiar el objetivo actual por si arrastra prefijos erróneos anteriores
    clean_base_target = current_target
    while "http://" in clean_base_target or "https://" in clean_base_target:
        clean_base_target = clean_base_target.replace("http://", "").replace("https://", "")

    # Configuración de la API LLM
    api_base = os.getenv("OPENAI_API_BASE")
    model_name = os.getenv("MODEL_NAME", "gpt-4o-mini")

    llm = ChatOpenAI(
        model=model_name,
        temperature=0,
        base_url=api_base if api_base else None
    )

    system_prompt = (
        "Eres un Agente de Red Team experto en análisis de vulnerabilidades. "
        "Analiza la siguiente salida de Nmap y determina si hay servicios web abiertos (puerto 80, 443, etc.). "
        "Si detectas un servicio web, devuelve únicamente la IP o dominio limpio base para expansión, o di 'NINGUNO'."
    )

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=f"Objetivo base: {clean_base_target}\n\nSalida del escaneo:\n{latest_finding}")
    ]

    response = llm.invoke(messages)
    ai_analysis = response.content.strip()
    
    discovered_endpoints = []
    
    # Heurística de seguridad: Si el escaneo muestra puertos web, añadimos la URL de forma limpia y única
    if "80/tcp" in latest_finding or "443/tcp" in latest_finding:
        target_url = f"http://{clean_base_target}"
        # Evitar re-añadir el objetivo si ya fue analizado
        if target_url not in state.get("completed_targets", []):
            discovered_endpoints.append(target_url)
            print(f"[+] [Analyzer] Nuevo endpoint limpio para expansión (grow): {target_url}")

    return {
        "current_phase": "grow",
        "logs": [f"Análisis completado. Nuevos endpoints limpios: {discovered_endpoints}"],
        "task_queue": discovered_endpoints 
    }
