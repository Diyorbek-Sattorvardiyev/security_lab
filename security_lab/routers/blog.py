from html import escape
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

from security_lab.database import get_db
from security_lab.routers.auth import get_client_ip, get_current_user
from security_lab.security.attack_logger import log_attack
from security_lab.security.csrf_protection import validate_csrf_token
from security_lab.security.sql_injection_detector import detect_sql_injection, get_risk_level
from security_lab.security.xss_filter import is_xss_payload

router = APIRouter()

UPLOAD_DIR = Path(__file__).resolve().parent.parent / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_IMAGE_TYPES = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/gif": ".gif"}


def require_user(request: Request) -> dict:
    user = get_current_user(request)
    if not user:
        raise HTTPException(401, "Login required")
    conn = get_db()
    fresh = conn.execute("SELECT is_blocked FROM users WHERE id=?", (user["id"],)).fetchone()
    conn.close()
    if fresh and fresh["is_blocked"]:
        user["is_blocked"] = True
        raise HTTPException(403, "User is blocked")
    return user


def require_csrf(request: Request, user: dict):
    session_id = request.cookies.get("session_id", "")
    token = request.headers.get("x-csrf-token", "")
    if not validate_csrf_token(session_id, token):
        log_attack(get_client_ip(request), "CSRF", token or "missing token", "blocked", request.url.path, user, "medium")
        raise HTTPException(403, "CSRF token missing or invalid")


def inspect_payload(request: Request, user: dict | None, payload: str):
    if is_xss_payload(payload):
        log_attack(get_client_ip(request), "XSS", payload, "blocked", request.url.path, user, "high")
        raise HTTPException(403, "XSS payload detected and blocked")

    is_sql, _ = detect_sql_injection(payload)
    if is_sql:
        log_attack(get_client_ip(request), "SQL Injection", payload, "blocked", request.url.path, user, "high")
        raise HTTPException(403, "SQL Injection payload detected and blocked")


def current_user_optional(request: Request) -> dict | None:
    return get_current_user(request)


@router.get("/posts")
async def posts(request: Request, q: str = "", category: str = "", status: str = "published"):
    inspect_payload_stub = {"id": None, "username": "anonymous"}
    if q:
        is_sql, _ = detect_sql_injection(q)
        if is_sql or is_xss_payload(q):
            attack_type = "SQL Injection" if is_sql else "XSS"
            risk = "high" if is_sql else "high"
            log_attack(get_client_ip(request), attack_type, q, "blocked", "/blog/posts", inspect_payload_stub, risk)
            raise HTTPException(403, "Suspicious search payload blocked")

    conn = get_db()
    user = current_user_optional(request)
    clauses = ["(?='' OR p.title LIKE ? OR p.content LIKE ? OR u.username LIKE ?)", "(?='' OR p.category=?)"]
    params = [q, f"%{q}%", f"%{q}%", f"%{q}%", category, category]
    if status == "drafts":
        if user:
            clauses.append("p.status='draft' AND p.user_id=?")
            params.append(user["id"])
        else:
            clauses.append("p.status='published'")
    elif status in {"draft", "published"}:
        clauses.append("p.status=?")
        params.append(status)
    else:
        clauses.append("p.status='published'")

    rows = conn.execute(
        """
        SELECT p.id, p.title, p.content, p.image_url, p.category, p.status, p.created_at,
               u.username, u.avatar_url,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comment_count,
               (SELECT COUNT(*) FROM post_reactions r WHERE r.post_id=p.id AND r.reaction_type='like') AS like_count,
               (SELECT COUNT(*) FROM post_reactions r WHERE r.post_id=p.id AND r.reaction_type='bookmark') AS bookmark_count
        FROM posts p
        JOIN users u ON u.id=p.user_id
        WHERE """ + " AND ".join(clauses) + """
        ORDER BY p.created_at DESC
        """,
        params,
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@router.get("/posts/{post_id}")
async def post_detail(post_id: int):
    conn = get_db()
    post = conn.execute(
        """
        SELECT p.*, u.username, u.avatar_url,
               (SELECT COUNT(*) FROM post_reactions r WHERE r.post_id=p.id AND r.reaction_type='like') AS like_count,
               (SELECT COUNT(*) FROM post_reactions r WHERE r.post_id=p.id AND r.reaction_type='bookmark') AS bookmark_count
        FROM posts p JOIN users u ON u.id=p.user_id
        WHERE p.id=?
        """,
        (post_id,),
    ).fetchone()
    comments = conn.execute(
        """
        SELECT c.*, u.username AS author
        FROM comments c LEFT JOIN users u ON u.id=c.user_id
        WHERE c.post_id=?
        ORDER BY c.created_at DESC
        """,
        (post_id,),
    ).fetchall()
    conn.close()
    if not post:
        raise HTTPException(404, "Post not found")
    return {"post": dict(post), "comments": [dict(row) for row in comments]}


@router.post("/posts")
async def create_post(request: Request):
    user = require_user(request)
    require_csrf(request, user)
    body = await request.json()
    title = str(body.get("title", "")).strip()
    content = str(body.get("content", "")).strip()
    image_url = str(body.get("image_url", "")).strip()
    category = str(body.get("category", "Security")).strip() or "Security"
    status = str(body.get("status", "published")).strip()
    if status not in {"draft", "published"}:
        status = "published"
    if len(title) < 3 or len(content) < 10:
        raise HTTPException(400, "Title yoki content juda qisqa")
    inspect_payload(request, user, title)
    inspect_payload(request, user, content)
    if image_url:
        inspect_payload(request, user, image_url)
    inspect_payload(request, user, category)
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO posts (user_id, title, content, image_url, category, status) VALUES (?, ?, ?, ?, ?, ?)",
        (user["id"], escape(title), escape(content), escape(image_url), escape(category), status),
    )
    conn.execute("UPDATE users SET score=score+? WHERE id=?", (15 if status == "published" else 5, user["id"]))
    if status == "published":
        conn.execute(
            "INSERT INTO notifications (user_id, message) VALUES (?, ?)",
            (user["id"], "Postingiz nashr qilindi va product feedga qo'shildi."),
        )
    conn.commit()
    post_id = cur.lastrowid
    conn.close()
    return {"success": True, "id": post_id}


@router.post("/uploads")
async def upload_image(request: Request, image: UploadFile = File(...)):
    user = require_user(request)
    require_csrf(request, user)
    if image.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(400, "Faqat JPG, PNG, WEBP yoki GIF rasm yuklash mumkin")
    content = await image.read()
    if len(content) > 3 * 1024 * 1024:
        raise HTTPException(400, "Rasm 3 MB dan katta bo'lmasin")
    ext = ALLOWED_IMAGE_TYPES[image.content_type]
    filename = f"{uuid4().hex}{ext}"
    path = UPLOAD_DIR / filename
    path.write_bytes(content)
    return {"image_url": f"/static/uploads/{filename}"}


@router.post("/avatar")
async def upload_avatar(request: Request, image: UploadFile = File(...)):
    user = require_user(request)
    require_csrf(request, user)
    if image.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(400, "Faqat rasm yuklash mumkin")
    content = await image.read()
    if len(content) > 2 * 1024 * 1024:
        raise HTTPException(400, "Avatar 2 MB dan katta bo'lmasin")
    ext = ALLOWED_IMAGE_TYPES[image.content_type]
    filename = f"avatar-{uuid4().hex}{ext}"
    path = UPLOAD_DIR / filename
    path.write_bytes(content)
    avatar_url = f"/static/uploads/{filename}"
    conn = get_db()
    conn.execute("UPDATE users SET avatar_url=? WHERE id=?", (avatar_url, user["id"]))
    conn.commit()
    conn.close()
    user["avatar_url"] = avatar_url
    return {"avatar_url": avatar_url}


@router.post("/posts/{post_id}/react")
async def react_to_post(post_id: int, request: Request):
    user = require_user(request)
    require_csrf(request, user)
    body = await request.json()
    reaction_type = str(body.get("reaction_type", "")).strip()
    if reaction_type not in {"like", "bookmark"}:
        raise HTTPException(400, "Invalid reaction")
    conn = get_db()
    post = conn.execute("SELECT id, user_id, title FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post:
        conn.close()
        raise HTTPException(404, "Post not found")
    existing = conn.execute(
        "SELECT id FROM post_reactions WHERE user_id=? AND post_id=? AND reaction_type=?",
        (user["id"], post_id, reaction_type),
    ).fetchone()
    active = False
    if existing:
        conn.execute("DELETE FROM post_reactions WHERE id=?", (existing["id"],))
    else:
        conn.execute(
            "INSERT INTO post_reactions (user_id, post_id, reaction_type) VALUES (?, ?, ?)",
            (user["id"], post_id, reaction_type),
        )
        conn.execute("UPDATE users SET score=score+2 WHERE id=?", (user["id"],))
        active = True
        if post["user_id"] != user["id"]:
            conn.execute(
                "INSERT INTO notifications (user_id, message) VALUES (?, ?)",
                (post["user_id"], f"{user['username']} sizning postingizga {reaction_type} qildi: {post['title']}"),
            )
    conn.commit()
    counts = {
        "like_count": conn.execute("SELECT COUNT(*) c FROM post_reactions WHERE post_id=? AND reaction_type='like'", (post_id,)).fetchone()["c"],
        "bookmark_count": conn.execute("SELECT COUNT(*) c FROM post_reactions WHERE post_id=? AND reaction_type='bookmark'", (post_id,)).fetchone()["c"],
        "active": active,
    }
    conn.close()
    return counts


@router.post("/posts/{post_id}/comments")
async def create_comment(post_id: int, request: Request):
    user = require_user(request)
    require_csrf(request, user)
    body = await request.json()
    comment = str(body.get("comment", "")).strip()
    if len(comment) < 2:
        raise HTTPException(400, "Comment juda qisqa")
    inspect_payload(request, user, comment)
    conn = get_db()
    exists = conn.execute("SELECT id FROM posts WHERE id=?", (post_id,)).fetchone()
    if not exists:
        conn.close()
        raise HTTPException(404, "Post not found")
    conn.execute(
        "INSERT INTO comments (user_id, post_id, username, comment, is_safe) VALUES (?, ?, ?, ?, 1)",
        (user["id"], post_id, user["username"], escape(comment)),
    )
    conn.commit()
    conn.close()
    return {"success": True}


@router.get("/profile")
async def profile(request: Request):
    user = require_user(request)
    conn = get_db()
    posts = conn.execute("SELECT * FROM posts WHERE user_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
    comments = conn.execute("SELECT * FROM comments WHERE user_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
    attacks = conn.execute("SELECT * FROM attack_logs WHERE user_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
    db_user = conn.execute("SELECT id, username, email, role, score, avatar_url, is_blocked, blocked_at, blocked_reason, created_at FROM users WHERE id=?", (user["id"],)).fetchone()
    bookmarks = conn.execute(
        """
        SELECT p.* FROM posts p
        JOIN post_reactions r ON r.post_id=p.id
        WHERE r.user_id=? AND r.reaction_type='bookmark'
        ORDER BY r.created_at DESC
        """,
        (user["id"],),
    ).fetchall()
    notifications = conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 8", (user["id"],)).fetchall()
    conn.close()
    return {
        "user": dict(db_user),
        "posts": [dict(row) for row in posts],
        "comments": [dict(row) for row in comments],
        "attacks": [dict(row) for row in attacks],
        "bookmarks": [dict(row) for row in bookmarks],
        "notifications": [dict(row) for row in notifications],
    }


@router.get("/chat")
async def chat_messages():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM chat_messages ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return [dict(row) for row in reversed(rows)]


@router.post("/chat")
async def send_chat_message(request: Request):
    user = require_user(request)
    require_csrf(request, user)
    body = await request.json()
    message = str(body.get("message", "")).strip()
    if len(message) < 1:
        raise HTTPException(400, "Xabar bo'sh bo'lmasin")
    if len(message) > 500:
        raise HTTPException(400, "Xabar 500 belgidan oshmasin")
    inspect_payload(request, user, message)
    conn = get_db()
    conn.execute(
        "INSERT INTO chat_messages (user_id, username, message) VALUES (?, ?, ?)",
        (user["id"], user["username"], escape(message)),
    )
    conn.commit()
    conn.close()
    return {"success": True}


@router.post("/security-test")
async def security_test(request: Request):
    user = get_current_user(request)
    body = await request.json()
    attack = str(body.get("attack_type", "Auto")).strip()
    payload = str(body.get("payload", "")).strip()
    if attack.upper() == "CSRF":
        require_csrf(request, user or {})
        return {"safe": True, "message": "CSRF token valid"}

    is_sql, _ = detect_sql_injection(payload)
    is_xss = is_xss_payload(payload)
    if is_xss or is_sql:
        attack_type = "XSS" if is_xss else "SQL Injection"
        log_attack(get_client_ip(request), attack_type, payload, "blocked", "/blog/security-test", user, "high")
        if user:
            conn = get_db()
            conn.execute("UPDATE users SET score=score+10 WHERE id=?", (user["id"],))
            conn.execute(
                "INSERT INTO notifications (user_id, message) VALUES (?, ?)",
                (user["id"], f"Security Lab: {attack_type} payload aniqlandi va bloklandi. +10 learning points"),
            )
            conn.commit()
            conn.close()
        return JSONResponse(
            {
                "safe": False,
                "detected": True,
                "blocked": True,
                "attack_type": attack_type,
                "risk_level": "high",
                "message": f"{attack_type} payload aniqlandi va bloklandi",
            },
            status_code=403,
        )

    risk = get_risk_level(payload).lower()
    return {"safe": True, "detected": False, "risk_level": risk, "message": "Payload xavfsiz ko'rindi"}
