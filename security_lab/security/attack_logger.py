from datetime import datetime
from security_lab.database import get_db


def log_attack(ip_address: str, attack_type: str, payload: str, status: str, endpoint: str = ""):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attack_logs (ip_address, attack_type, payload, status, endpoint)
            VALUES (?, ?, ?, ?, ?)
        """, (ip_address, attack_type, payload[:500], status, endpoint))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Logging error: {e}")


def get_attack_stats():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM attack_logs")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT attack_type, COUNT(*) as count FROM attack_logs GROUP BY attack_type")
    by_type = {row["attack_type"]: row["count"] for row in cursor.fetchall()}

    cursor.execute("SELECT status, COUNT(*) as count FROM attack_logs GROUP BY status")
    by_status = {row["status"]: row["count"] for row in cursor.fetchall()}

    cursor.execute("""
        SELECT * FROM attack_logs ORDER BY created_at DESC LIMIT 20
    """)
    recent = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return {
        "total": total,
        "by_type": by_type,
        "by_status": by_status,
        "recent": recent
    }
