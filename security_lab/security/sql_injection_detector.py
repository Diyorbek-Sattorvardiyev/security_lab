import re
from typing import Tuple

SQL_PATTERNS = [
    r"(\bOR\b\s*[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?)",
    r"(\bOR\b\s*[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?)",
    r"(\bUNION\b\s+\bSELECT\b)",
    r"(\bDROP\b\s+\bTABLE\b)",
    r"(\bDELETE\b\s+\bFROM\b)",
    r"(\bINSERT\b\s+\bINTO\b)",
    r"(\bSELECT\b.*\bFROM\b)",
    r"(--\s*$)",
    r"(/\*.*\*/)",
    r"(\bEXEC\b|\bEXECUTE\b)",
    r"(\bxp_\w+)",
    r"([\'\"];\s*\w+)",
    r"(\bWAITFOR\b\s+\bDELAY\b)",
    r"(\bSLEEP\b\s*\()",
    r"(1\s*=\s*1|true\s*=\s*true)",
]

XSS_PATTERNS = [
    r"(<script[\s\S]*?>[\s\S]*?</script>)",
    r"(<script[^>]*>)",
    r"(javascript\s*:)",
    r"(on\w+\s*=\s*['\"]?[^'\"]*['\"]?)",
    r"(<iframe[\s\S]*?>)",
    r"(<object[\s\S]*?>)",
    r"(<embed[\s\S]*?>)",
    r"(eval\s*\()",
    r"(document\.cookie)",
    r"(document\.write\s*\()",
    r"(window\.location)",
    r"(<img[^>]+onerror\s*=)",
    r"(alert\s*\()",
    r"(String\.fromCharCode)",
]


def detect_sql_injection(payload: str) -> Tuple[bool, str]:
    payload_upper = payload.upper()
    for pattern in SQL_PATTERNS:
        if re.search(pattern, payload_upper, re.IGNORECASE):
            return True, f"SQL Injection pattern detected: {pattern}"
    return False, ""


def detect_xss(payload: str) -> Tuple[bool, str]:
    for pattern in XSS_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, f"XSS pattern detected"
    return False, ""


def get_risk_level(payload: str) -> str:
    sql_found, _ = detect_sql_injection(payload)
    xss_found, _ = detect_xss(payload)

    if sql_found or xss_found:
        return "HIGH"

    suspicious = ["<", ">", "'", '"', ";", "--", "/*", "*/", "\\"]
    count = sum(1 for c in suspicious if c in payload)

    if count >= 3:
        return "MEDIUM"
    elif count >= 1:
        return "LOW"
    return "SAFE"
