from typing import TypedDict, List, Dict, Optional, Literal
from datetime import datetime

class Hypothesis(TypedDict):
    id: str
    description: str
    probability: float
    required_evidence: List[str]
    status: Literal["pending", "confirmed", "refuted"]

class Asset(TypedDict):
    ip: str
    ports: List[int]
    services: Dict[str, str]

class Evidence(TypedDict):
    source_tool: str
    timestamp: str
    confidence: float
    raw_output: str
    verified: bool

class RedTeamState(TypedDict):
    mission_target: str
    scope_policy: Dict[str, any]
    assets: List[Asset]
    hypotheses: List[Hypothesis]
    evidence_ledger: List[Evidence]
    attack_graph_nodes: List[Dict[str, any]]
    current_phase: Literal["planner", "recon", "exploit", "validator"]
    logs: List[str]