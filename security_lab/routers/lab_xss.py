from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from database import get_db
from security.xss_filter import sanitize_input, is_xss_payload
from security.attack_logger import log_attack

router = APIRouter()


@router.post("/comment-vulnerable")
async def vulnerable_comment(request: Request):
    """⚠️ VULNERABLE: No sanitization"""
    body = await request.json()
    comment = body.get("comment", "")
    username = body.get("username", "anonymous")

    client_ip = request.client.host
    xss_detected = is_xss_payload(comment)

    conn = get_db()
    conn.execute(
        "INSERT INTO comments (username, comment, is_safe) VALUES (?, ?, 0)",
        (username, comment)
    )
    conn.commit()

    if xss_detected:
        log_attack(client_ip, "XSS", comment, "successful", "/lab/xss/comment-vulnerable")
        return JSONResponse({
            "success": True,
            "attack_detected": True,
            "message": "🚨 XSS Attack SUCCESSFUL! Script will execute in browser!",
            "comment": comment,  # Raw, unsanitized
            "vulnerability": "Comment stored without sanitization - script will run for all viewers"
        })

    # Return all comments (unsanitized - dangerous!)
    comments = conn.execute(
        "SELECT * FROM comments WHERE is_safe=0 ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    conn.close()

    return JSONResponse({
        "success": True,
        "comments": [dict(c) for c in comments],
        "message": "Comment posted (unsafe mode)"
    })


@router.post("/comment-secure")
async def secure_comment(request: Request):
    """✅ SECURE: HTML escaping and sanitization"""
    body = await request.json()
    comment = body.get("comment", "")
    username = body.get("username", "anonymous")

    client_ip = request.client.host
    xss_detected = is_xss_payload(comment)

    if xss_detected:
        log_attack(client_ip, "XSS", comment, "blocked", "/lab/xss/comment-secure")
        sanitized = sanitize_input(comment)
        return JSONResponse({
            "success": True,
            "attack_detected": True,
            "blocked": True,
            "message": "🛡️ XSS Attack BLOCKED! Input sanitized.",
            "original": comment,
            "sanitized": sanitized,
            "defense": "HTML escaping converts <script> to &lt;script&gt; - renders as text, not code"
        })

    sanitized_comment = sanitize_input(comment)
    conn = get_db()
    conn.execute(
        "INSERT INTO comments (username, comment, is_safe) VALUES (?, ?, 1)",
        (username, sanitized_comment)
    )
    conn.commit()

    comments = conn.execute(
        "SELECT * FROM comments WHERE is_safe=1 ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    conn.close()

    return JSONResponse({
        "success": True,
        "comments": [dict(c) for c in comments],
        "message": "Comment posted safely"
    })


@router.get("/comments")
async def get_comments():
    conn = get_db()
    safe = conn.execute("SELECT * FROM comments WHERE is_safe=1 ORDER BY created_at DESC LIMIT 5").fetchall()
    unsafe = conn.execute("SELECT * FROM comments WHERE is_safe=0 ORDER BY created_at DESC LIMIT 5").fetchall()
    conn.close()
    return {"safe": [dict(c) for c in safe], "unsafe": [dict(c) for c in unsafe]}
