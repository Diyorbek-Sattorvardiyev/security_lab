from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from database import get_db
from security.csrf_protection import generate_csrf_token, validate_csrf_token, get_token_for_session
from security.attack_logger import log_attack
import secrets

router = APIRouter()


@router.get("/token")
async def get_csrf_token(request: Request):
    session_id = request.cookies.get("session_id", secrets.token_hex(8))
    token = get_token_for_session(session_id)
    return {"csrf_token": token, "session_id": session_id}


@router.post("/update-vulnerable")
async def vulnerable_update(request: Request):
    """⚠️ VULNERABLE: No CSRF token check"""
    body = await request.json()
    email = body.get("email", "")
    bio = body.get("bio", "")
    user_id = body.get("user_id", 1)

    client_ip = request.client.host
    origin = request.headers.get("origin", "")
    referer = request.headers.get("referer", "")

    # Check if cross-origin
    is_csrf = origin and "evil" in origin.lower()

    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO csrf_profiles (user_id, email, bio) VALUES (?, ?, ?)",
        (user_id, email, bio)
    )
    conn.commit()
    conn.close()

    if is_csrf:
        log_attack(client_ip, "CSRF", f"email={email}", "successful", "/lab/csrf/update-vulnerable")
        return JSONResponse({
            "success": True,
            "attack_detected": True,
            "message": "🚨 CSRF Attack SUCCESSFUL! Profile updated from malicious site!",
            "updated_email": email,
            "vulnerability": "No CSRF token check - any site can submit this form"
        })

    return JSONResponse({
        "success": True,
        "message": f"Profile updated: {email}",
        "warning": "⚠️ This endpoint has no CSRF protection!"
    })


@router.post("/update-secure")
async def secure_update(request: Request):
    """✅ SECURE: CSRF token validation"""
    body = await request.json()
    email = body.get("email", "")
    bio = body.get("bio", "")
    csrf_token = body.get("csrf_token", "")
    session_id = request.cookies.get("session_id", "")

    client_ip = request.client.host

    if not csrf_token:
        log_attack(client_ip, "CSRF", "No token provided", "blocked", "/lab/csrf/update-secure")
        return JSONResponse({
            "success": False,
            "blocked": True,
            "attack_detected": True,
            "message": "🛡️ CSRF Attack BLOCKED! No token provided.",
            "defense": "All state-changing requests require a valid CSRF token"
        })

    if not validate_csrf_token(session_id, csrf_token):
        log_attack(client_ip, "CSRF", f"Invalid token: {csrf_token[:20]}", "blocked", "/lab/csrf/update-secure")
        return JSONResponse({
            "success": False,
            "blocked": True,
            "attack_detected": True,
            "message": "🛡️ CSRF Attack BLOCKED! Invalid or expired token.",
            "defense": "Token mismatch - request rejected. Attacker cannot forge valid token."
        })

    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO csrf_profiles (user_id, email, bio) VALUES (?, ?, ?)",
        (1, email, bio)
    )
    conn.commit()
    conn.close()

    return JSONResponse({
        "success": True,
        "message": f"Profile securely updated: {email}",
        "defense": "CSRF token validated successfully"
    })
