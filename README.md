# Enterprise Dynamic Red Team Agent

Authorized-lab agent for **Hack The Box / classroom ranges only**.

It runs a policy-gated playbook: recon → enum → optional assume-breach → loot `user.txt` / `root.txt`.

## Scope (hard gate)

Commands run only if the target IP is in:

- `10.10.0.0/16`
- `10.129.0.0/16`
- `10.13.0.0/16`

or a domain ending in `.htb` / `.lab` / `.local`.

Override with `ALLOWED_NETWORKS=cidr,cidr` for *your* lab. Do not point this at the public Internet.

## Run (Kali)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # optional SUDO_PASS for /etc/hosts

python3 main.py 10.129.x.x
python3 main.py 10.129.x.x --user rose --password 'labpass'
python3 main.py 10.129.x.x --dry-run
```

State and loot: `testing/<ip>/agent_state.json` and `testing/<ip>/loot/`.

## Layout

```text
main.py                 # policy + playbook loop
core/policy_engine.py   # allowlist
core/playbook.py        # nmap, nxc, kerbrute, gobuster, winrm/ssh loot
core/flags.py           # 32-hex HTB flags
core/state_manager.py
utils/smart_executor.py
nodes/                  # experimental LangGraph path (optional)
kali-redteam-agent/     # older compact copy
```

## What it will not do

- Skip the policy engine
- Commit VPN profiles (`.ovpn` gitignored)
- Treat the string `user.txt` as a flag (needs a 32-hex value)
- Use a hardcoded sudo password

Flags still require valid lab credentials or a working foothold. Pass `--user/--password` when the box is assume-breach (HTB Easy AD).
