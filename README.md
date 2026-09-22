# 🛡️ Enterprise Dynamic Red Team Agent

Agente autónomo inteligente diseñado para automatizar fases de reconocimiento, enumeración y explotación en ejercicios de Red Team y pentesting (compatible con entornos corporativos y máquinas de laboratorios como Hack The Box).

## 🚀 Características Principales

* **Autonomía Adaptativa:** Utiliza un motor de decisión dinámico basado en estados para decidir el siguiente paso en la cadena de ataques (*Kill Chain*).
* **Auto-descubrimiento de Red:** Analiza automáticamente los resultados de los escaneos de `nmap` para detectar nombres de dominio (FQDN) y configurar el entorno (`/etc/hosts`) sobre la marcha.
* **Soporte Multi-entorno:** Capaz de adaptarse tanto a infraestructuras de **Active Directory** (Kerberos, SMB, RPC, LDAP) como a entornos genéricos de Linux/Web.
* **Correlación de Exploits:** Integra un módulo (`ExploitMatcher`) que contrasta las versiones de los servicios descubiertos con bases de datos de exploits.
* **Persistencia de Estado:** Guarda el historial de ejecución y verifica continuamente la captura de flags (`user.txt` / `root.txt`) para detenerse automáticamente al completar la misión.

---

## 📂 Estructura del Proyecto

```text
kali-redteam-agent/
│
├── core/
│   └── state_manager.py     # Gestor de estado y persistencia de la misión
├── utils/
│   ├── smart_executor.py    # Ejecutor seguro de comandos con control de tiempo
│   └── exploit_matcher.py   # Módulo de correlación de vulnerabilidades
├── testing/                 # Carpeta de salida (scans, loot y evidencias)
├── agent.py                 # Script principal del agente autónomo
├── .gitignore
└── README.md