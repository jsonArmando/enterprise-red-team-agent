# Enterprise Dynamic Red Team Agent

Agente **automático** para laboratorios autorizados (HTB).

```bash
python3 main.py 10.129.x.x
```

No pases usuario ni contraseña. El agente:

1. Escanea (nmap)
2. Enumera (nxc / kerbrute / gobuster)
3. Extrae usuarios y passwords de salidas y archivos
4. Hace spray y reutiliza credenciales válidas
5. Intenta leer flags por WinRM/SSH
6. Persiste todo en disco

## Dónde se guarda

```text
testing/<ip>/
  agent.log
  agent_state.json
  logs/step_01.log ...
  scans/
  loot/
    users.txt
    passwords.txt
    credentials.json
    user.flag
    root.flag
    flags.json
```

## Alcance

Solo IPs `10.10.0.0/16`, `10.129.0.0/16`, `10.13.0.0/16` o dominios `*.htb`.

## Límite

Si el lab exige una credencial que **no aparece** en shares/nmap/AS-REP, el spray no la inventa. En HTB Easy AD a veces la ficha da un user inicial: déjala en `testing/<ip>/loot/credentials.json` y relanza el mismo comando (sin flags).
