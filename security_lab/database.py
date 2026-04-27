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
            avatar_url TEXT,
            is_blocked INTEGER DEFAULT 0,
            blocked_at TIMESTAMP,
            blocked_reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            image_url TEXT,
            category TEXT DEFAULT 'Security',
            status TEXT DEFAULT 'published',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            post_id INTEGER,
            username TEXT,
            comment TEXT NOT NULL,
            is_safe INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(post_id) REFERENCES posts(id)
        );

        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            ip_address TEXT,
            attack_type TEXT,
            payload TEXT,
            status TEXT,
            endpoint TEXT,
            risk_level TEXT DEFAULT 'medium',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS csrf_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT,
            bio TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS post_reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            reaction_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, post_id, reaction_type),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(post_id) REFERENCES posts(id)
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)

    ensure_column(cursor, "users", "avatar_url", "TEXT")
    ensure_column(cursor, "users", "is_blocked", "INTEGER DEFAULT 0")
    ensure_column(cursor, "users", "blocked_at", "TIMESTAMP")
    ensure_column(cursor, "users", "blocked_reason", "TEXT")
    ensure_column(cursor, "posts", "image_url", "TEXT")
    ensure_column(cursor, "posts", "category", "TEXT DEFAULT 'Security'")
    ensure_column(cursor, "posts", "status", "TEXT DEFAULT 'published'")
    ensure_column(cursor, "comments", "post_id", "INTEGER")
    ensure_column(cursor, "attack_logs", "user_id", "INTEGER")
    ensure_column(cursor, "attack_logs", "username", "TEXT")
    ensure_column(cursor, "attack_logs", "risk_level", "TEXT DEFAULT 'medium'")

    # Insert demo user
    try:
        import bcrypt
        if not cursor.execute("SELECT id FROM users WHERE username='admin'").fetchone():
            pwd = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                ("admin", "admin@seclab.io", pwd, "admin")
            )
        old_user = cursor.execute("SELECT id FROM users WHERE username='diyorbek'").fetchone()
        user_exists = cursor.execute("SELECT id FROM users WHERE username='user'").fetchone()
        if old_user and not user_exists:
            cursor.execute(
                "UPDATE users SET username=?, email=? WHERE id=?",
                ("user", "user@secureblog.uz", old_user["id"]),
            )
        if not cursor.execute("SELECT id FROM users WHERE username='user'").fetchone():
            pwd2 = bcrypt.hashpw(b"user123", bcrypt.gensalt()).decode()
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                ("user", "user@secureblog.uz", pwd2, "user")
            )
        cursor.execute(
            "UPDATE users SET is_blocked=0, blocked_at=NULL, blocked_reason=NULL WHERE username='user'"
        )
        cursor.execute(
            "UPDATE users SET avatar_url=COALESCE(avatar_url, ?) WHERE username='admin'",
            ("https://images.unsplash.com/photo-1563986768494-4dee2763ff3f?auto=format&fit=crop&w=256&q=80",),
        )
        cursor.execute(
            "UPDATE users SET avatar_url=COALESCE(avatar_url, ?) WHERE username='user'",
            ("https://images.unsplash.com/photo-1516321318423-f06f85e504b3?auto=format&fit=crop&w=256&q=80",),
        )
    except Exception as e:
        print(f"Demo user error: {e}")

    admin = cursor.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    user = cursor.execute("SELECT id FROM users WHERE username='user'").fetchone()
    if admin:
        cursor.execute(
            "INSERT OR IGNORE INTO posts (id, user_id, title, content, image_url, category, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                admin["id"],
                "SecureBlog: xavfsiz kontent platformasi",
                "# SecureBlog\n\nSecureBlog zamonaviy blog tajribasi, real vaqt chat va xavfsizlik monitoringini bitta mahsulotga jamlaydi.\n\n- Xavfsiz autentifikatsiya\n- Rasmli postlar\n- Admin monitoring",
                "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1200&q=80",
                "Security",
                "published",
            ),
        )
    if user:
        cursor.execute(
            "INSERT OR IGNORE INTO posts (id, user_id, title, content, image_url, category, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                2,
                user["id"],
                "Jamoa bilan chatlashish va rasmli postlar",
                "Postga rasm yuklash, fikr qoldirish va umumiy chat orqali suhbatlashish blogni jonli mahsulotga aylantiradi.\n\n```python\nprint('secure publishing')\n```",
                "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1200&q=80",
                "Product",
                "published",
            ),
        )

    cursor.execute(
        "UPDATE posts SET image_url=? WHERE id=1",
        ("https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1200&q=80",),
    )
    cursor.execute(
        "UPDATE posts SET image_url=? WHERE id=2",
        ("https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1200&q=80",),
    )

    conn.commit()
    conn.close()
    print("✅ Database initialized!")


def ensure_column(cursor, table: str, column: str, definition: str):
    columns = [row["name"] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in columns:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
