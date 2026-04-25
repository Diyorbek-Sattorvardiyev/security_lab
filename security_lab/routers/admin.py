from fastapi import APIRouter, HTTPException, Request

from security_lab.database import get_db
from security_lab.routers.auth import get_client_ip, get_current_user
from security_lab.security.attack_logger import log_attack
from security_lab.security.csrf_protection import validate_csrf_token

router = APIRouter()


def require_admin(request: Request) -> dict:
    user = get_current_user(request)
    if not user:
        raise HTTPException(401, "Login required")
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin only")
    return user


def require_csrf(request: Request, user: dict):
    token = request.headers.get("x-csrf-token", "")
    session_id = request.cookies.get("session_id", "")
    if not validate_csrf_token(session_id, token):
        log_attack(get_client_ip(request), "CSRF", token or "missing token", "blocked", request.url.path, user, "medium")
        raise HTTPException(403, "CSRF token missing or invalid")


@router.get("/dashboard")
async def dashboard(request: Request):
    require_admin(request)
    conn = get_db()
    stats = {
        "users": conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"],
        "posts": conn.execute("SELECT COUNT(*) AS c FROM posts").fetchone()["c"],
        "published": conn.execute("SELECT COUNT(*) AS c FROM posts WHERE status='published'").fetchone()["c"],
        "drafts": conn.execute("SELECT COUNT(*) AS c FROM posts WHERE status='draft'").fetchone()["c"],
        "attacks": conn.execute("SELECT COUNT(*) AS c FROM attack_logs").fetchone()["c"],
        "blocked_users": conn.execute("SELECT COUNT(*) AS c FROM users WHERE is_blocked=1").fetchone()["c"],
    }
    recent = conn.execute("SELECT * FROM attack_logs ORDER BY created_at DESC LIMIT 10").fetchall()
    attack_types = conn.execute(
        "SELECT attack_type, COUNT(*) AS count FROM attack_logs GROUP BY attack_type ORDER BY count DESC"
    ).fetchall()
    categories = conn.execute(
        "SELECT category, COUNT(*) AS count FROM posts GROUP BY category ORDER BY count DESC"
    ).fetchall()
    daily_attacks = conn.execute(
        """
        SELECT date(created_at) AS day, COUNT(*) AS count
        FROM attack_logs
        GROUP BY date(created_at)
        ORDER BY day DESC
        LIMIT 7
        """
    ).fetchall()
    conn.close()
    return {
        "stats": stats,
        "recent_attacks": [dict(row) for row in recent],
        "attack_types": [dict(row) for row in attack_types],
        "categories": [dict(row) for row in categories],
        "daily_attacks": [dict(row) for row in reversed(daily_attacks)],
    }


@router.get("/attack-logs")
async def attack_logs(
    request: Request,
    attack_type: str = "",
    username: str = "",
    status: str = "",
    date: str = "",
):
    require_admin(request)
    clauses = []
    params = []
    if attack_type:
        clauses.append("attack_type=?")
        params.append(attack_type)
    if username:
        clauses.append("username LIKE ?")
        params.append(f"%{username}%")
    if status:
        clauses.append("status=?")
        params.append(status)
    if date:
        clauses.append("date(created_at)=date(?)")
        params.append(date)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = get_db()
    logs = conn.execute(
        f"SELECT * FROM attack_logs {where} ORDER BY created_at DESC LIMIT 200",
        params,
    ).fetchall()
    conn.close()
    return [dict(row) for row in logs]


@router.get("/blocked-users")
async def blocked_users(request: Request):
    require_admin(request)
    conn = get_db()
    users = conn.execute(
        """
        SELECT u.id, u.username, u.email, u.blocked_at, u.blocked_reason,
               COUNT(a.id) AS attack_count
        FROM users u
        LEFT JOIN attack_logs a ON a.user_id=u.id
        WHERE u.is_blocked=1
        GROUP BY u.id
        ORDER BY u.blocked_at DESC
        """
    ).fetchall()
    conn.close()
    return [dict(row) for row in users]


@router.post("/users/{user_id}/block")
async def block_user(user_id: int, request: Request):
    admin = require_admin(request)
    require_csrf(request, admin)
    body = await request.json()
    reason = str(body.get("reason", "Admin manually blocked user")).strip()
    conn = get_db()
    conn.execute(
        "UPDATE users SET is_blocked=1, blocked_at=CURRENT_TIMESTAMP, blocked_reason=? WHERE id=? AND role!='admin'",
        (reason, user_id),
    )
    conn.commit()
    conn.close()
    return {"success": True}


@router.post("/users/{user_id}/unblock")
async def unblock_user(user_id: int, request: Request):
    admin = require_admin(request)
    require_csrf(request, admin)
    conn = get_db()
    conn.execute(
        "UPDATE users SET is_blocked=0, blocked_at=NULL, blocked_reason=NULL WHERE id=?",
        (user_id,),
    )
    conn.commit()
    conn.close()
    return {"success": True}


@router.get("/users/{user_id}")
async def user_detail(user_id: int, request: Request):
    require_admin(request)
    conn = get_db()
    user = conn.execute(
        "SELECT id, username, email, role, is_blocked, blocked_at, blocked_reason, created_at FROM users WHERE id=?",
        (user_id,),
    ).fetchone()
    if not user:
        conn.close()
        raise HTTPException(404, "User not found")
    posts = conn.execute("SELECT * FROM posts WHERE user_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
    comments = conn.execute("SELECT * FROM comments WHERE user_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
    attacks = conn.execute("SELECT * FROM attack_logs WHERE user_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
    conn.close()
    return {
        "user": dict(user),
        "posts": [dict(row) for row in posts],
        "comments": [dict(row) for row in comments],
        "attacks": [dict(row) for row in attacks],
    }


@router.get("/users")
async def users(request: Request, q: str = ""):
    require_admin(request)
    conn = get_db()
    rows = conn.execute(
        """
        SELECT u.id, u.username, u.email, u.role, u.is_blocked, u.blocked_at,
               COUNT(a.id) AS attack_count
        FROM users u
        LEFT JOIN attack_logs a ON a.user_id=u.id
        WHERE ?='' OR u.username LIKE ? OR u.email LIKE ?
        GROUP BY u.id
        ORDER BY u.created_at DESC
        """,
        (q, f"%{q}%", f"%{q}%"),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]
