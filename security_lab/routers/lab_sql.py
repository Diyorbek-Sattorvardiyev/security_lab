from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import sqlite3
from security_lab.database import get_db
from security_lab.security.sql_injection_detector import detect_sql_injection
from security_lab.security.attack_logger import log_attack

router = APIRouter()


@router.post("/login-vulnerable")
async def vulnerable_login(request: Request):
    """⚠️ VULNERABLE: Direct string concatenation - FOR DEMO ONLY"""
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")

    client_ip = request.client.host

    # Detect attack
    is_attack_u, _ = detect_sql_injection(username)
    is_attack_p, _ = detect_sql_injection(password)

    conn = sqlite3.connect("security_lab.db")
    conn.row_factory = sqlite3.Row

    # ⚠️ VULNERABLE QUERY - DO NOT USE IN PRODUCTION
    query = f"SELECT * FROM users WHERE username='{username}' AND password_hash='{password}'"

    try:
        result = conn.execute(query).fetchone()
        conn.close()

        if is_attack_u or is_attack_p:
            payload = username if is_attack_u else password
            log_attack(client_ip, "SQL_INJECTION", payload, "successful", "/lab/sql/login-vulnerable")
            return JSONResponse({
                "success": True,
                "attack_detected": True,
                "message": "🚨 SQL Injection SUCCESSFUL! Attacker bypassed login!",
                "query": query,
                "vulnerability": "String concatenation allows injection of SQL code",
                "user": dict(result) if result else {"username": "BYPASSED via injection"}
            })

        if result:
            return JSONResponse({"success": True, "message": "Login successful", "user": dict(result)})
        return JSONResponse({"success": False, "message": "Invalid credentials"})

    except Exception as e:
        conn.close()
        log_attack(client_ip, "SQL_INJECTION", username, "error", "/lab/sql/login-vulnerable")
        return JSONResponse({"success": False, "error": str(e), "query": query})


@router.post("/login-secure")
async def secure_login(request: Request):
    """✅ SECURE: Parameterized queries"""
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")

    client_ip = request.client.host

    is_attack, reason = detect_sql_injection(username)
    if is_attack:
        log_attack(client_ip, "SQL_INJECTION", username, "blocked", "/lab/sql/login-secure")
        return JSONResponse({
            "success": False,
            "attack_detected": True,
            "blocked": True,
            "message": "🛡️ SQL Injection BLOCKED! Parameterized query protected the system.",
            "reason": reason,
            "defense": "Parameterized queries treat input as DATA, not CODE"
        })

    conn = get_db()
    # ✅ SECURE: Parameterized query
    user = conn.execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
    ).fetchone()
    conn.close()

    if user:
        return JSONResponse({
            "success": True,
            "message": "Login successful (legitimate user)",
            "defense": "Parameterized queries prevent SQL injection"
        })
    return JSONResponse({"success": False, "message": "Invalid credentials"})


@router.get("/logs")
async def get_sql_logs(request: Request):
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM attack_logs WHERE attack_type='SQL_INJECTION' ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return [dict(log) for log in logs]
