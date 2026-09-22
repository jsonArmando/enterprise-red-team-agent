from typing import List, Dict, Any, TypedDict
import operator
from typing_extensions import Annotated

class RedTeamState(TypedDict):
    target: str                              # Objetivo principal (ej. IP de HTB)
    task_queue: List[str]                    # Cola dinámica de sub-objetivos / endpoints (Grow)
    completed_targets: List[str]             # Objetivos y vectores ya analizados
    findings: Annotated[List[Dict[str, Any]], operator.add] # Hallazgos acumulados
    current_phase: str                       # Fase actual: recon, analyze, grow, exploit
    logs: Annotated[List[str], operator.add] # Registro de auditoría del agente
