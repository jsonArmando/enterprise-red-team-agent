import re
from typing import Any, Dict

_SECRET_PATTERNS = (
    (re.compile(r"(?i)(-u\s+[^\s]+%)[^\s'\"]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(password\s*[=:]\s*)[^\s'\"]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(passwd\s*[=:]\s*)[^\s'\"]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(pwd\s*[=:]\s*)[^\s'\"]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(--password(?:=|\s+))[^\s'\"]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(--pass(?:word)?(?:=|\s+))[^\s'\"]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(authorization:\s*(?:basic|bearer)\s+)[^\s]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(cpassword\s*=\s*\")([^\"]+)(\")"), r"\1<REDACTED>\3"),
)

def redact_secrets(value: Any) -> Any:
    if isinstance(value, str):
        result = value
        for pattern, replacement in _SECRET_PATTERNS:
            result = pattern.sub(replacement, result)
        return result
    if isinstance(value, dict):
        return {k: redact_secrets(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_secrets(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(v) for v in value)
    return value

def redact_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    return redact_secrets(dict(entry))
