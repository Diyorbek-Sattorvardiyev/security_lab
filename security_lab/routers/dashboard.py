from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from security.attack_logger import get_attack_stats
from database import get_db
from security.sql_injection_detector import get_risk_level

router = APIRouter()


@router.get("/stats")
async def get_stats():
    stats = get_attack_stats()
    return stats


@router.get("/score")
async def get_security_score():
    stats = get_attack_stats()
    total = stats["total"]
    blocked = stats["by_status"].get("blocked", 0)
    successful = stats["by_status"].get("successful", 0)

    if total == 0:
        score = 100
        level = "secure"
    else:
        score = int((blocked / total) * 100) if total > 0 else 100
        if score >= 70:
            level = "secure"
        elif score >= 30:
            level = "medium"
        else:
            level = "insecure"

    return {
        "score": score,
        "level": level,
        "total_attacks": total,
        "blocked": blocked,
        "successful": successful,
        "by_type": stats["by_type"]
    }


@router.post("/scan")
async def vulnerability_scan(request: Request):
    body = await request.json()
    target = body.get("input", "")

    risk = get_risk_level(target)

    findings = []
    if "<" in target or ">" in target:
        findings.append({"type": "XSS", "severity": "HIGH", "detail": "HTML tags detected"})
    if "'" in target or '"' in target:
        findings.append({"type": "SQL Injection", "severity": "MEDIUM", "detail": "Quote characters detected"})
    if ";" in target or "--" in target:
        findings.append({"type": "SQL Injection", "severity": "HIGH", "detail": "SQL comment/terminator detected"})
    if "javascript:" in target.lower():
        findings.append({"type": "XSS", "severity": "HIGH", "detail": "JavaScript protocol detected"})
    if "script" in target.lower():
        findings.append({"type": "XSS", "severity": "HIGH", "detail": "Script tag detected"})

    return {
        "input": target,
        "risk_level": risk,
        "findings": findings,
        "safe": len(findings) == 0,
        "recommendation": "Use parameterized queries and HTML escaping" if findings else "Input appears safe"
    }


@router.get("/logs")
async def get_logs():
    stats = get_attack_stats()
    return stats["recent"]
