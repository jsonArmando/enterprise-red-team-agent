# Capability matrix (authorized HTB / classroom only)

## Two frameworks (do not mix)

| Framework | What it covers | Role in this agent |
|---|---|---|
| MITRE ATT&CK | Recon, creds, lateral, priv-esc on Windows/Linux/AD | **Kill chain of the lab agent** |
| MITRE ATLAS | Attacks against AI (jailbreak, RAG poison, prompt injection) | **Hardening this agent**, not HTB boxes |

TrustFall, Certified, Active are ATT&CK problems. ATLAS does not give you CNEXT or ESC1.

## ATT&CK coverage (current vs target)

| Tactic | Now | Senior lab target |
|---|---|---|
| Reconnaissance | nmap, curl | + fingerprint playbook |
| Resource / enum | nxc, kerbrute, ldapsearch, smbmap | + GPP/Groups.xml, BloodHound collect |
| Initial Access | spray / AS-REP if creds appear | + web playbooks (LFI read, SQLi dump) per family |
| Execution | WinRM/SSH `-x` when creds exist | same |
| Persistence | no | out of scope for HTB flags |
| Privilege Escalation | no generic LPE | `sudo -l` / `whoami /priv` / ADCS find after foothold |
| Credential Access | harvest from output | GPP cpassword, SAM if authorized |
| Discovery | partial | shares + ACL writable |
| Collection | user.txt/root.txt | flags only |
| C2 / Exfil / Impact | no | never |

## ATLAS controls for THIS agent

- Policy allowlist (`10.10/16`, `10.129/16`) before every command
- No unattended Exploit-DB execution
- Prompt/LLM cannot skip policy
- Secrets stay in `testing/` (gitignored)
- STOP token instead of echo loops (no self-replication)

## TrustFall-class boxes

Need a **dedicated playbook** (osTicket + print + local file read), not ATLAS and not `searchsploit SMB`.
That playbook is not in `main.py` yet. Adding it is a separate module, scoped to `*.htb`.
