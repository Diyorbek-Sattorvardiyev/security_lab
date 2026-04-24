import secrets
import time
from typing import Optional

# In-memory token store (use Redis in production)
_csrf_tokens: dict = {}
TOKEN_EXPIRY = 3600  # 1 hour


def generate_csrf_token(session_id: str) -> str:
    token = secrets.token_hex(32)
    _csrf_tokens[session_id] = {
        "token": token,
        "created_at": time.time()
    }
    return token


def validate_csrf_token(session_id: str, token: str) -> bool:
    stored = _csrf_tokens.get(session_id)
    if not stored:
        return False

    if time.time() - stored["created_at"] > TOKEN_EXPIRY:
        del _csrf_tokens[session_id]
        return False

    return secrets.compare_digest(stored["token"], token)


def get_token_for_session(session_id: str) -> Optional[str]:
    stored = _csrf_tokens.get(session_id)
    if stored:
        return stored["token"]
    return generate_csrf_token(session_id)
