from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import JSONResponse
import bcrypt
import secrets
from security_lab.database import get_db
from security_lab.schemas import UserRegister, UserLogin
from security_lab.security.attack_logger import log_attack
from security_lab.security.csrf_protection import get_token_for_session
from security_lab.security.sql_injection_detector import detect_sql_injection
from security_lab.security.xss_filter import is_xss_payload

router = APIRouter()

# Simple session store (use Redis in production)
sessions = {}


def get_current_user(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        return None
    return sessions[session_id]


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def make_session(user) -> tuple[str, dict]:
    session_id = secrets.token_hex(32)
    session = {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "avatar_url": user["avatar_url"] if "avatar_url" in user.keys() else None,
        "score": user["score"] if "score" in user.keys() else 0,
        "is_blocked": bool(user["is_blocked"]),
    }
    sessions[session_id] = session
    return session_id, session


@router.post("/register")
async def register(data: UserRegister, request: Request):
    if len(data.username) < 3:
        raise HTTPException(400, "Username too short")
    if len(data.password) < 6:
        raise HTTPException(400, "Password too short")

    suspicious = [data.username, data.email]
    for value in suspicious:
        if is_xss_payload(value):
            log_attack(get_client_ip(request), "XSS", value, "blocked", "/auth/register", risk_level="high")
            raise HTTPException(400, "Suspicious input blocked")
        is_sql, _ = detect_sql_injection(value)
        if is_sql:
            log_attack(get_client_ip(request), "SQL Injection", value, "blocked", "/auth/register", risk_level="high")
            raise HTTPException(400, "Suspicious input blocked")

    conn = get_db()
    cursor = conn.cursor()

    existing = cursor.execute(
        "SELECT id FROM users WHERE username=? OR email=?",
        (data.username, data.email)
    ).fetchone()

    if existing:
        conn.close()
        raise HTTPException(400, "Username or email already exists")

    password_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()

    cursor.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (data.username, data.email, password_hash)
    )
    conn.commit()

    user_id = cursor.lastrowid
    conn.close()

    session_id = secrets.token_hex(32)
    sessions[session_id] = {
        "id": user_id,
        "username": data.username,
        "email": data.email,
        "role": "user",
        "avatar_url": None,
        "score": 0,
        "is_blocked": False,
    }

    response = JSONResponse({"success": True, "username": data.username, "role": "user"})
    response.set_cookie("session_id", session_id, httponly=True, secure=False, samesite="lax")
    return response


@router.post("/login")
async def login(data: UserLogin, request: Request, response: Response):
    for value in (data.username, data.password):
        is_sql, _ = detect_sql_injection(value)
        if is_sql:
            log_attack(get_client_ip(request), "SQL Injection", value, "blocked", "/auth/login", risk_level="high")
            raise HTTPException(403, "SQL Injection detected and blocked")

    conn = get_db()
    cursor = conn.cursor()

    user = cursor.execute(
        "SELECT * FROM users WHERE username=?",
        (data.username,)
    ).fetchone()
    conn.close()

    if not user:
        raise HTTPException(401, "Invalid credentials")

    anon = {"id": user["id"], "username": user["username"]}
    if user["is_blocked"]:
        log_attack(get_client_ip(request), "Blocked Login", data.username, "blocked", "/auth/login", anon, "medium")
        raise HTTPException(403, "User is blocked by security policy")

    if not bcrypt.checkpw(data.password.encode(), user["password_hash"].encode()):
        raise HTTPException(401, "Invalid credentials")

    session_id, session = make_session(user)

    resp = JSONResponse({"success": True, "username": user["username"], "role": user["role"], "csrf_token": get_token_for_session(session_id)})
    resp.set_cookie("session_id", session_id, httponly=True, secure=False, samesite="lax")
    return resp


@router.post("/logout")
async def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in sessions:
        del sessions[session_id]

    resp = JSONResponse({"success": True})
    resp.delete_cookie("session_id")
    return resp


@router.get("/me")
async def me(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return user


@router.get("/csrf")
async def csrf(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        raise HTTPException(401, "Not authenticated")
    return {"csrf_token": get_token_for_session(session_id)}
