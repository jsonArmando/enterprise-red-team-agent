# core/policy_engine.py
import ipaddress
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PolicyEngine")

def evaluate_policy(target: str, scope_policy: dict) -> bool:
    """
    Evalúa si el objetivo se encuentra dentro del rango autorizado por la misión.
    Evita que el agente ejecute acciones fuera del scope definido.
    """
    allowed_networks = scope_policy.get("allowed_networks", [])
    forbidden_targets = scope_policy.get("forbidden_targets", [])

    if target in forbidden_targets:
        logger.warning(f"[-] [Policy Engine] BLOQUEADO: El objetivo {target} está en la lista negra.")
        return False

    try:
        target_ip = ipaddress.ip_address(target)
        for net in allowed_networks:
            if target_ip in ipaddress.ip_network(net, strict=False):
                logger.info(f"[+] [Policy Engine] APROBADO: {target} está dentro del rango {net}.")
                return True
    except ValueError:
        # Si es un dominio o URL, validar contra dominios permitidos
        allowed_domains = scope_policy.get("allowed_domains", [])
        if any(domain in target for domain in allowed_domains):
            logger.info(f"[+] [Policy Engine] APROBADO: Dominio {target} autorizado.")
            return True

    logger.warning(f"[-] [Policy Engine] RECHAZADO: {target} fuera de alcance autorizado.")
    return False