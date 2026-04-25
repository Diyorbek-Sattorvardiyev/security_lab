from security_lab.database import get_db


def log_attack(
    ip_address: str,
    attack_type: str,
    payload: str,
    status: str,
    endpoint: str = "",
    user: dict | None = None,
    risk_level: str = "medium",
):
    try:
        conn = get_db()
        cursor = conn.cursor()
        user_id = user.get("id") if user else None
        username = user.get("username") if user else "anonymous"
        cursor.execute("""
            INSERT INTO attack_logs
                (user_id, username, ip_address, attack_type, payload, status, endpoint, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, ip_address, attack_type, payload[:500], status, endpoint, risk_level))
        conn.commit()
        if user_id:
            apply_auto_block(cursor, user_id)
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"Logging error: {e}")


def apply_auto_block(cursor, user_id: int):
    user = cursor.execute("SELECT is_blocked, role FROM users WHERE id=?", (user_id,)).fetchone()
    if not user or user["is_blocked"] or user["role"] == "admin":
        return

    high = cursor.execute(
        "SELECT COUNT(*) AS c FROM attack_logs WHERE user_id=? AND risk_level='high'",
        (user_id,),
    ).fetchone()["c"]
    medium = cursor.execute(
        "SELECT COUNT(*) AS c FROM attack_logs WHERE user_id=? AND risk_level='medium'",
        (user_id,),
    ).fetchone()["c"]
    total = cursor.execute(
        "SELECT COUNT(*) AS c FROM attack_logs WHERE user_id=?",
        (user_id,),
    ).fetchone()["c"]

    reason = None
    if high >= 1:
        reason = "1 ta high risk hujum"
    elif medium >= 3:
        reason = "3 ta medium risk hujum"
    elif total >= 5:
        reason = "5 ta suspicious request"

    if reason:
        cursor.execute(
            """
            UPDATE users
            SET is_blocked=1, blocked_at=CURRENT_TIMESTAMP, blocked_reason=?
            WHERE id=?
            """,
            (reason, user_id),
        )


def get_attack_stats():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM attack_logs")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT attack_type, COUNT(*) as count FROM attack_logs GROUP BY attack_type")
    by_type = {row["attack_type"]: row["count"] for row in cursor.fetchall()}

    cursor.execute("SELECT status, COUNT(*) as count FROM attack_logs GROUP BY status")
    by_status = {row["status"]: row["count"] for row in cursor.fetchall()}

    cursor.execute("SELECT * FROM attack_logs ORDER BY created_at DESC LIMIT 20")
    recent = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return {
        "total": total,
        "by_type": by_type,
        "by_status": by_status,
        "recent": recent
    }
