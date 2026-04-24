import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "security_lab.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            score INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            comment TEXT NOT NULL,
            is_safe INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            attack_type TEXT,
            payload TEXT,
            status TEXT,
            endpoint TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS csrf_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT,
            bio TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Insert demo user
    try:
        import bcrypt
        pwd = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            ("admin", "admin@seclab.io", pwd, "admin")
        )
        pwd2 = bcrypt.hashpw(b"user123", bcrypt.gensalt()).decode()
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            ("diyorbek", "diyorbek@seclab.io", pwd2, "user")
        )
    except Exception as e:
        print(f"Demo user error: {e}")

    conn.commit()
    conn.close()
    print("✅ Database initialized!")
