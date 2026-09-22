"""Registered adapters for authorized HTB/lab execution."""
from __future__ import annotations
import json, os, shlex
from pathlib import Path
from typing import Any
from tools.mcp_client import call_kali_mcp_tool
from tools.mcp_router import call_kali_tool

ALLOWED_EXECUTABLES = {
    "nmap","nxc","smbclient","rpcclient","ldapsearch","kerbrute","gobuster","curl",
    "searchsploit","impacket-secretsdump","impacket-GetUserSPNs","impacket-GetNPUsers",
    "python3","ssh","sshpass","find","grep","cat","ls","id","whoami","uname","sudo","getcap",
}

def _q(value: str) -> str:
    return shlex.quote(str(value))

def run_shell_tool(tool: str, args: list[str], timeout: int = 900) -> str:
    if tool not in ALLOWED_EXECUTABLES:
        raise ValueError(f"tool_not_allowlisted:{tool}")
    return call_kali_tool(tool, " ".join(_q(a) for a in args), timeout=timeout)

def run_recon(target: str, out: Path) -> str:
    return run_shell_tool("nmap", ["-Pn","-p-","-sV","-sC","--open","-oN",str(out),target], timeout=1200)

def run_vulnerability_scan(target: str, out: Path) -> str:
    return run_shell_tool("nmap", ["-Pn","-sV","--script","vuln","--open","-oN",str(out),target], timeout=1800)

def run_cve_lookup(cve: str) -> str:
    return run_shell_tool("searchsploit", ["--json",cve], timeout=120)

def run_mcp_validate(target: str, candidate: dict[str,Any]) -> str:
    return call_kali_mcp_tool(os.getenv("MCP_VALIDATE_TOOL","validate_vulnerability"), {
        "target":target,"candidate":candidate,"evidence_lines":candidate.get("evidence_lines",[]),
        "mode":"authorized_lab"
    })

def run_mcp_exploit(target: str, candidate: dict[str,Any]) -> str:
    return call_kali_mcp_tool("execute_exploit_module", {
        "target":target,"cve":candidate.get("cve"),"port":candidate.get("port"),
        "service":candidate.get("service"),"version":candidate.get("version"),
        "candidate":candidate,"mode":"authorized_lab"
    })

def run_session_manager(target: str, operation: str, context: dict[str,Any] | None = None) -> str:
    return call_kali_mcp_tool(os.getenv("MCP_SESSION_TOOL","session_manager"), {
        "operation":operation,"target":target,"context":context or {},"mode":"authorized_lab"
    })

def run_reverse_shell(target: str, context: dict[str,Any] | None = None) -> str:
    return call_kali_mcp_tool(os.getenv("MCP_REVERSE_SHELL_TOOL","reverse_shell_manager"), {
        "operation":"establish",
        "target":target,
        "callback_host":os.getenv("LAB_CALLBACK_HOST","127.0.0.1"),
        "callback_port":int(os.getenv("LAB_CALLBACK_PORT","4444")),
        "context":context or {},
        "mode":"authorized_lab"
    })

def run_post_exploit(target: str, access: dict[str,Any] | None = None) -> str:
    return call_kali_mcp_tool(os.getenv("MCP_POST_ENUM_TOOL","post_exploitation_enum"), {
        "target":target,"access":access or {},"mode":"authorized_lab"
    })

def run_privilege_escalation(target: str, access: dict[str,Any] | None = None, hypotheses: list[dict[str,Any]] | None = None) -> str:
    return call_kali_mcp_tool(os.getenv("MCP_PRIVESC_TOOL","privilege_escalation"), {
        "target":target,
        "access":access or {},
        "hypotheses":hypotheses or [],
        "objective":"root.txt",
        "mode":"authorized_lab"
    })

def verify_flags_remote(target: str) -> str:
    return call_kali_mcp_tool("verify_flags", {"target":target,"filenames":["user.txt","root.txt"]})

def run_kali_tool_catalog(target: str) -> str:
    return call_kali_mcp_tool(os.getenv("MCP_LIST_TOOLS","list_kali_tools"), {
        "target":target,"mode":"authorized_lab"
    })
