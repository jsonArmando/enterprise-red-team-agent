"""Authorize only in-scope lab targets before any command runs."""
from __future__ import annotations

import ipaddress
import logging
import os
import re

logger = logging.getLogger("PolicyEngine")

DEFAULT_NETS = [
    "10.10.0.0/16",    # HTB starting point / tun
    "10.129.0.0/16",   # HTB machines
    "10.13.0.0/16",
    "127.0.0.1/32",
]

DEFAULT_DOMAINS = (".htb", ".lab", ".local")


def _nets() -> list[str]:
    extra = os.getenv("ALLOWED_NETWORKS", "")
    nets = list(DEFAULT_NETS)
    if extra:
        nets.extend([n.strip() for n in extra.split(",") if n.strip()])
    return nets


def evaluate_policy(target: str, scope_policy: dict | None = None) -> bool:
    scope_policy = scope_policy or {}
    allowed_networks = scope_policy.get("allowed_networks") or _nets()
    forbidden = set(scope_policy.get("forbidden_targets") or [])
    allowed_domains = scope_policy.get("allowed_domains") or list(DEFAULT_DOMAINS)

    if not target or target in forbidden:
        logger.warning("[-] Policy BLOCKED empty/forbidden target")
        return False

    host = target.split("@")[-1]
    host = host.split("/")[0]
    host = host.split(":")[0]

    try:
        ip = ipaddress.ip_address(host)
        for net in allowed_networks:
            if ip in ipaddress.ip_network(net, strict=False):
                logger.info("[+] Policy ALLOW %s in %s", host, net)
                return True
        logger.warning("[-] Policy DENY IP %s not in allowed_networks", host)
        return False
    except ValueError:
        if any(host.endswith(d) or d in host for d in allowed_domains):
            logger.info("[+] Policy ALLOW domain %s", host)
            return True
        if re.match(r"^[A-Za-z0-9._-]+$", host):
            logger.warning("[-] Policy DENY host %s (not *.htb/*.lab)", host)
            return False
        logger.warning("[-] Policy DENY %s", target)
        return False
