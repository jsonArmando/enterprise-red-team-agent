# nodes/attack_planner.py
import os
import json
from core.state import RedTeamState
from core.policy_engine import evaluate_policy
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from dotenv import load_dotenv

load_dotenv()

def attack_planner_node(state: RedTeamState) -> dict:
    print("[*] [Attack Planner Node] Razonando sobre la evidencia y generando hipótesis...")

    target = state["mission_target"]
    scope = state["scope_policy"]

    # 1. Validar política antes de planificar
    if not evaluate_policy(target, scope):
        return {
            "current_phase": "planner",
            "logs": [f"Misión abortada por Policy Engine para el objetivo {target}"]
        }

    # 2. Inicializar Grok para razonamiento estratégico
    api_base = os.getenv("OPENAI_API_BASE", "https://api.x.ai/v1")
    model_name = os.getenv("MODEL_NAME", "grok-beta")

    llm = ChatOpenAI(
        model=model_name,
        temperature=0.2,
        base_url=api_base
    )

    system_prompt = (
        "Eres un Arquitecto de Red Team Senior. Analiza el acumulado de evidencias y el estado actual "
        "de los activos. Genera hipótesis de ataque formales (H1, H2...), determina la evidencia requerida "
        "y define la 'Siguiente Mejor Acción' (Next Best Action) en formato JSON estructurado."
    )

    evidence_summary = "\n".join([str(e) for e in state.get("evidence_ledger", [])])
    
    human_content = (
        f"Objetivo: {target}\n"
        f"Evidencias Actuales:\n{evidence_summary}\n\n"
        "Devuelve un JSON estrictamente con la estructura: "
        '{"hypotheses": [{"id": "H1", "description": "...", "probability": 0.8, "required_evidence": ["..."]}], "next_action": "..."}'
    )

    response = llm.invoke([SystemMessage(content=system_prompt), HumanMessage(content=human_content)])
    
    try:
        plan_data = json.loads(response.content.strip())
    except Exception:
        plan_data = {"hypotheses": [], "next_action": "reconnaissance"}

    print(f"[+] [Planner Output]: Hipótesis generadas -> {len(plan_data.get('hypotheses', []))}")

    return {
        "hypotheses": plan_data.get("hypotheses", []),
        "current_phase": "recon",
        "logs": [f"Plan de ataque actualizado. Próxima acción: {plan_data.get('next_action')}"]
    }