import os
from core.state import RedTeamState
from core.knowledge import load_knowledge_base
from tools.exploit_finder import search_exploit_db
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from dotenv import load_dotenv

load_dotenv()

def analyzer_node(state: RedTeamState) -> dict:
    print("[*] [Analyzer Node] Consultando modelo cognitivo avanzado (Grok + RAG)...")
    
    latest_finding = state["findings"][-1]["data"] if state["findings"] else ""
    current_target = state["completed_targets"][-1]

    # 1. Recuperar contexto de la Base de Conocimiento (RAG)
    retriever = load_knowledge_base()
    rag_context = ""
    if retriever:
        docs = retriever.invoke(latest_finding[:200]) # Consultar basado en el escaneo
        rag_context = "\n".join([d.page_content for d in docs])

    # 2. Búsqueda automática en Exploit-DB (Searchsploit) si hay servicios detectados
    exploit_results = ""
    if "open" in latest_finding.lower():
        # Extraer una query general del escaneo para buscar exploits (ej. versión de servicio)
        exploit_results = search_exploit_db("service version") # En una implementación avanzada se parsea el servicio exacto

    # 3. Inicializar Grok (via API compatible con OpenAI)
    api_base = os.getenv("OPENAI_API_BASE", "https://api.x.ai/v1")
    model_name = os.getenv("MODEL_NAME", "grok-beta")

    llm = ChatOpenAI(
        model=model_name,
        temperature=0.1,
        base_url=api_base
    )

    system_prompt = (
        "Eres un Arquitecto de Red Team de Élite operando con modelos Grok. "
        "Analiza el escaneo de red y los datos de Exploit-DB proporcionados. "
        "Utiliza tu base de conocimiento técnica para correlacionar vectores de ataque. "
        "Decide si se requiere expansión (grow) y extrae objetivos web limpios o rutas de explotación."
    )

    human_content = (
        f"Objetivo: {current_target}\n\n"
        f"Salida de Escaneo:\n{latest_finding}\n\n"
        f"Contexto RAG Técnico:\n{rag_context}\n\n"
        f"Resultados Exploit-DB:\n{exploit_results}"
    )

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=human_content)
    ]

    response = llm.invoke(messages)
    ai_analysis = response.content.strip()
    
    print(f"[+] [Grok Intelligence Output]:\n{ai_analysis}")

    discovered_endpoints = []
    clean_base_target = current_target.replace("http://", "").replace("https://", "")

    if "80/tcp" in latest_finding or "443/tcp" in latest_finding:
        target_url = f"http://{clean_base_target}"
        if target_url not in state.get("completed_targets", []):
            discovered_endpoints.append(target_url)

    return {
        "current_phase": "grow",
        "logs": [f"Análisis Grok + Exploit-DB completado. Vectores: {discovered_endpoints}"],
        "task_queue": discovered_endpoints 
    }