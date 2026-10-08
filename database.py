import os
import psycopg2
from psycopg2.extras import RealDictCursor


DATABASE_URL = os.getenv("DATABASE_URL")


def get_db():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set."
        )

    return psycopg2.connect(DATABASE_URL)


def init_db():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) NOT NULL UNIQUE,
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS diaries (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name VARCHAR(200) NOT NULL,
            description TEXT,
            password_hash TEXT NOT NULL,
            salt BYTEA NOT NULL,
            created_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id SERIAL PRIMARY KEY,
            diary_id INTEGER NOT NULL,
            encrypted_title TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL,
            FOREIGN KEY (diary_id)
            REFERENCES diaries(id)
            ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS unlock_sessions (
            id SERIAL PRIMARY KEY,
            token TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL,
            diary_id INTEGER NOT NULL,
            encrypted_key TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE,
            FOREIGN KEY (diary_id)
            REFERENCES diaries(id)
            ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_unlock_token
        ON unlock_sessions(token)
    """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_unlock_user_diary
        ON unlock_sessions(user_id, diary_id)
    """)

    conn.commit()

    cur.close()
    conn.close()


def fetch_one(query, values=()):

    conn = get_db()

    cur = conn.cursor(
        cursor_factory=RealDictCursor
    )

    cur.execute(
        query,
        values
    )

    row = cur.fetchone()

    cur.close()
    conn.close()

    return row


def fetch_all(query, values=()):

    conn = get_db()

    cur = conn.cursor(
        cursor_factory=RealDictCursor
    )

    cur.execute(
        query,
        values
    )

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return rows


def execute(query, values=()):

    conn = get_db()

    cur = conn.cursor()

    cur.execute(
        query,
        values
    )

    conn.commit()

    cur.close()
    conn.close()


def execute_returning(query, values=()):

    conn = get_db()

    cur = conn.cursor(
        cursor_factory=RealDictCursor
    )

    cur.execute(
        query,
        values
    )

    row = cur.fetchone()

    conn.commit()

    cur.close()
    conn.close()

    return row