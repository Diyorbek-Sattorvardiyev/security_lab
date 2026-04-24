import html
import re


def sanitize_html(text: str) -> str:
    """Escape HTML special characters to prevent XSS"""
    return html.escape(text)


def strip_tags(text: str) -> str:
    """Remove all HTML tags"""
    clean = re.sub(r'<[^>]+>', '', text)
    return clean


def sanitize_input(text: str) -> str:
    """Full sanitization pipeline"""
    text = strip_tags(text)
    text = sanitize_html(text)
    return text


def is_xss_payload(text: str) -> bool:
    patterns = [
        r'<script', r'javascript:', r'onerror=',
        r'onload=', r'eval\(', r'document\.cookie',
        r'alert\(', r'<iframe', r'<object',
    ]
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False
