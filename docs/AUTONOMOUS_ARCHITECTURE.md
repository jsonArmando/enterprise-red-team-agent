# Autonomous HTB/Lab Execution Architecture

## Objective

The agent is an evidence-driven autonomous supervisor for authorized HTB/lab targets. It does not treat \`potential_exploits.json\` as an executable command list. It creates a candidate inventory, reasons over evidence, validates preconditions, executes through registered adapters, observes the result, and replans after failure.

## Lifecycle

\`\`\`
RECON
  -> KALI TOOL CATALOG
  -> VULNERABILITY ENUMERATION
  -> potential_exploits.json
  -> candidate ANALYZE
  -> candidate VALIDATE
  -> candidate EXPLOIT
  -> FOOTHOLD
  -> STABLE SESSION
  -> REVERSE-SHELL RECOVERY (when required)
  -> POST-EXPLOITATION ENUMERATION
  -> PRIVESC ANALYZE
  -> PRIVESC VALIDATE
  -> PRIVESC EXECUTE
  -> FLAG VERIFY
  -> REPLAN on failure
  -> complete only when user.txt + root.txt are independently verified
\`\`\`

## Session model

State stores a structured session record:

- session_id
- session_type
- transport
- user
- host
- connected
- privilege
- evidence

The SessionManager adapter uses a single MCP tool configured by \`MCP_SESSION_TOOL\` and supports operations \`establish\`, \`inspect\`, and \`close\`.

## Reverse shell

Reverse shell handling is an orchestration capability, not an LLM-generated shell string. The registered adapter calls \`MCP_REVERSE_SHELL_TOOL\` with target, callback host/port, current foothold evidence, and current session state.

Configure:

- \`LAB_CALLBACK_HOST\`
- \`LAB_CALLBACK_PORT\`
- \`MCP_REVERSE_SHELL_TOOL\`

The MCP server is responsible for the lab-specific listener/session implementation.

## Privilege escalation

Privilege escalation is now a separate lifecycle:

\`\`\`
evidence
 -> hypothesis extraction
 -> deep reasoning
 -> validation
 -> execution
 -> observation
 -> root flag verification
\`\`\`

The local \`PrivEscEngine\` extracts evidence-backed hypotheses for Linux and Windows patterns including sudo misconfiguration, SUID, Linux capabilities, cron/timers, writable services/paths, kernel exposure, credential material, Windows privilege tokens, weak services, and scheduled tasks.

Configure:

- \`MCP_PRIVESC_VALIDATE_TOOL\`
- \`MCP_PRIVESC_TOOL\`

## Kali tool catalog

The agent discovers executable tools dynamically from the Kali runtime \`PATH\` and optionally merges the list returned by \`MCP_LIST_TOOLS\`. The complete catalog is persisted to:

\`\`\`
testing/<target>/kali_tool_catalog.json
\`\`\`

The planner receives the discovered tool names and may select the registered \`run_kali_tool\` action when a specialized Kali utility is required. Dynamic execution is limited to tools present in the discovered catalog; shell interpreter wrappers are not permitted through this generic action.

## Failure reasoning

Every material failure is stored in \`failure_memory\` and \`failed_paths\`. Before retrying, the FailureReasoner:

1. classifies the failure;
2. separates environment/tool failure from a bad hypothesis;
3. identifies missing evidence;
4. considers alternative hypotheses;
5. chooses one registered recovery action;
6. records the reasoning trace in the audit log.

The same failed action/candidate is not blindly retried without fresh evidence.

## Audit

The canonical audit file is:

\`\`\`
testing/<target>/audit/events.jsonl
\`\`\`

Legacy \`event.jsonl\` is migrated automatically when present.

## MCP contracts

Default tool names are configurable because the agent does not assume a specific MCP implementation:

- \`validate_vulnerability\`
- \`execute_exploit_module\`
- \`session_manager\`
- \`reverse_shell_manager\`
- \`post_exploitation_enum\`
- \`validate_privilege_escalation\`
- \`privilege_escalation\`
- \`verify_flags\`
- \`list_kali_tools\`

These adapters are intended for authorized HTB/lab environments only.
