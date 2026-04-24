from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import JSONResponse
import bcrypt
import secrets
from security_lab.database import get_db
from security_lab.schemas import UserRegister, UserLogin

router = APIRouter()

# Simple session store (use Redis in production)
sessions = {}


def get_current_user(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        return None
    return sessions[session_id]


@router.post("/register")
async def register(data: UserRegister, request: Request):
    if len(data.username) < 3:
        raise HTTPException(400, "Username too short")
    if len(data.password) < 6:
        raise HTTPException(400, "Password too short")

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
        "role": "user"
    }

    response = JSONResponse({"success": True, "username": data.username})
    response.set_cookie("session_id", session_id, httponly=True, samesite="lax")
    return response


@router.post("/login")
async def login(data: UserLogin, response: Response):
    conn = get_db()
    cursor = conn.cursor()

    user = cursor.execute(
        "SELECT * FROM users WHERE username=?",
        (data.username,)
    ).fetchone()
    conn.close()

    if not user:
        raise HTTPException(401, "Invalid credentials")

    if not bcrypt.checkpw(data.password.encode(), user["password_hash"].encode()):
        raise HTTPException(401, "Invalid credentials")

    session_id = secrets.token_hex(32)
    sessions[session_id] = {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"]
    }

    resp = JSONResponse({"success": True, "username": user["username"], "role": user["role"]})
    resp.set_cookie("session_id", session_id, httponly=True, samesite="lax")
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
