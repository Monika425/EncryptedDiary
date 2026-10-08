from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import InvalidToken
from datetime import datetime, timedelta
import secrets
import os

from database import (
    get_db,
    init_db,
    fetch_one,
    fetch_all,
    execute,
    execute_returning
)

from crypto import (
    encrypt_text,
    decrypt_text,
    create_key,
    protect_key,
    unprotect_key
)


app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "local-demo-secret-key"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

if os.getenv("VERCEL"):
    app.config["SESSION_COOKIE_SECURE"] = True


def current_time():
    return datetime.utcnow()


def logged_in():
    return session.get("user_id") is not None


def get_current_user():

    if not logged_in():
        return None

    return fetch_one(
        """
        SELECT *
        FROM users
        WHERE id = %s
        """,
        (session["user_id"],)
    )


def get_user_diary(diary_id):

    if not logged_in():
        return None

    return fetch_one(
        """
        SELECT *
        FROM diaries
        WHERE id = %s
        AND user_id = %s
        """,
        (
            diary_id,
            session["user_id"]
        )
    )


def remove_unlock_session(token):

    if not token:
        return

    execute(
        """
        DELETE FROM unlock_sessions
        WHERE token = %s
        """,
        (token,)
    )


def lock_current_diary():

    token = session.get("unlock_token")

    if token:
        remove_unlock_session(token)

    session.pop("unlock_token", None)
    session.pop("unlocked_diary", None)


def get_unlock_key(diary_id):

    token = session.get("unlock_token")

    if not token:
        return None

    data = fetch_one(
        """
        SELECT *
        FROM unlock_sessions
        WHERE token = %s
        AND user_id = %s
        AND diary_id = %s
        AND expires_at > %s
        """,
        (
            token,
            session["user_id"],
            diary_id,
            current_time()
        )
    )

    if not data:

        session.pop("unlock_token", None)
        session.pop("unlocked_diary", None)

        return None

    try:

        return unprotect_key(
            data["encrypted_key"]
        )

    except InvalidToken:

        remove_unlock_session(token)

        session.pop("unlock_token", None)
        session.pop("unlocked_diary", None)

        return None


def create_unlock_session(
    diary_id,
    key
):

    token = secrets.token_urlsafe(32)

    encrypted_key = protect_key(key)

    expires_at = (
        current_time()
        + timedelta(hours=2)
    )

    execute(
        """
        DELETE FROM unlock_sessions
        WHERE user_id = %s
        AND diary_id = %s
        """,
        (
            session["user_id"],
            diary_id
        )
    )

    execute(
        """
        INSERT INTO unlock_sessions
        (
            token,
            user_id,
            diary_id,
            encrypted_key,
            expires_at,
            created_at
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            token,
            session["user_id"],
            diary_id,
            encrypted_key,
            expires_at,
            current_time()
        )
    )

    session["unlock_token"] = token
    session["unlocked_diary"] = diary_id


init_db()


@app.route("/")
def dashboard():

    if not logged_in():

        return redirect(
            url_for("login")
        )

    user = get_current_user()

    diaries = fetch_all(
        """
        SELECT
            d.id,
            d.name,
            d.description,
            TO_CHAR(
                d.created_at,
                'YYYY-MM-DD'
            ) AS created_at,
            COUNT(e.id) AS entry_count
        FROM diaries d
        LEFT JOIN entries e
            ON d.id = e.diary_id
        WHERE d.user_id = %s
        GROUP BY
            d.id,
            d.name,
            d.description,
            d.created_at
        ORDER BY d.created_at DESC
        """,
        (session["user_id"],)
    )

    total_entries = sum(
        int(d["entry_count"])
        for d in diaries
    )

    return render_template(
        "dashboard.html",
        user=user,
        diaries=diaries,
        total_entries=total_entries
    )


@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if logged_in():

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm = request.form.get(
            "confirm",
            ""
        )

        if not username or not email or not password:

            flash(
                "All fields are required.",
                "error"
            )

            return render_template(
                "register.html"
            )

        if password != confirm:

            flash(
                "Passwords do not match.",
                "error"
            )

            return render_template(
                "register.html"
            )

        existing = fetch_one(
            """
            SELECT id
            FROM users
            WHERE username = %s
            OR email = %s
            """,
            (
                username,
                email
            )
        )

        if existing:

            flash(
                "Username or email already exists.",
                "error"
            )

            return render_template(
                "register.html"
            )

        password_hash = generate_password_hash(
            password
        )

        execute(
            """
            INSERT INTO users
            (
                username,
                email,
                password_hash,
                created_at
            )
            VALUES (%s, %s, %s, %s)
            """,
            (
                username,
                email,
                password_hash,
                current_time()
            )
        )

        flash(
            "Account created successfully. Please log in.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if logged_in():

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        user = fetch_one(
            """
            SELECT *
            FROM users
            WHERE email = %s
            """,
            (email,)
        )

        if not user:

            flash(
                "Invalid email or password.",
                "error"
            )

            return render_template(
                "login.html"
            )

        if not check_password_hash(
            user["password_hash"],
            password
        ):

            flash(
                "Invalid email or password.",
                "error"
            )

            return render_template(
                "login.html"
            )

        session.clear()

        session["user_id"] = user["id"]
        session["username"] = user["username"]

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )


@app.route("/logout")
def logout():

    lock_current_diary()

    session.clear()

    return redirect(
        url_for("login")
    )


@app.route(
    "/create-diary",
    methods=["GET", "POST"]
)
def create_diary():

    if not logged_in():

        return redirect(
            url_for("login")
        )

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm = request.form.get(
            "confirm",
            ""
        )

        if not name or not password:

            flash(
                "Diary name and password are required.",
                "error"
            )

            return render_template(
                "create_diary.html"
            )

        if password != confirm:

            flash(
                "Diary passwords do not match.",
                "error"
            )

            return render_template(
                "create_diary.html"
            )

        password_hash = generate_password_hash(
            password
        )

        salt = os.urandom(16)

        execute(
            """
            INSERT INTO diaries
            (
                user_id,
                name,
                description,
                password_hash,
                salt,
                created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                session["user_id"],
                name,
                description,
                password_hash,
                salt,
                current_time()
            )
        )

        flash(
            "Diary created successfully.",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "create_diary.html"
    )


@app.route(
    "/diary/<int:diary_id>"
)
def locked_diary(diary_id):

    if not logged_in():

        return redirect(
            url_for("login")
        )

    diary = get_user_diary(
        diary_id
    )

    if not diary:

        flash(
            "Diary not found.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    entries = fetch_all(
        """
        SELECT
            id,
            encrypted_title,
            encrypted_content,
            created_at
        FROM entries
        WHERE diary_id = %s
        ORDER BY created_at DESC
        """,
        (diary_id,)
    )

    return render_template(
        "locked_diary.html",
        diary=diary,
        entries=entries
    )


@app.route(
    "/diary/<int:diary_id>/unlock",
    methods=["GET", "POST"]
)
def unlock_diary(diary_id):

    if not logged_in():

        return redirect(
            url_for("login")
        )

    diary = get_user_diary(
        diary_id
    )

    if not diary:

        flash(
            "Diary not found.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        if not check_password_hash(
            diary["password_hash"],
            password
        ):

            flash(
                "Incorrect diary password.",
                "error"
            )

            return render_template(
                "unlock.html",
                diary=diary
            )

        salt = bytes(
            diary["salt"]
        )

        key = create_key(
            password,
            salt
        )

        entries = fetch_all(
            """
            SELECT encrypted_title
            FROM entries
            WHERE diary_id = %s
            LIMIT 1
            """,
            (diary_id,)
        )

        try:

            if entries:

                decrypt_text(
                    entries[0]["encrypted_title"],
                    password,
                    salt
                )

        except InvalidToken:

            flash(
                "Unable to decrypt diary.",
                "error"
            )

            return render_template(
                "unlock.html",
                diary=diary
            )

        create_unlock_session(
            diary_id,
            key
        )

        return redirect(
            url_for(
                "unlocked_diary",
                diary_id=diary_id
            )
        )

    return render_template(
        "unlock.html",
        diary=diary
    )


@app.route(
    "/diary/<int:diary_id>/unlocked"
)
def unlocked_diary(diary_id):

    if not logged_in():

        return redirect(
            url_for("login")
        )

    diary = get_user_diary(
        diary_id
    )

    if not diary:

        return redirect(
            url_for("dashboard")
        )

    key = get_unlock_key(
        diary_id
    )

    if not key:

        return redirect(
            url_for(
                "locked_diary",
                diary_id=diary_id
            )
        )

    entries = fetch_all(
        """
        SELECT *
        FROM entries
        WHERE diary_id = %s
        ORDER BY created_at DESC
        """,
        (diary_id,)
    )

    decrypted_entries = []

    cipher = Fernet(key)

    for entry in entries:

        try:

            title = cipher.decrypt(
                entry["encrypted_title"].encode()
            ).decode()

            content = cipher.decrypt(
                entry["encrypted_content"].encode()
            ).decode()

            decrypted_entries.append({
                "id": entry["id"],
                "title": title,
                "content": content,
                "created_at": entry["created_at"],
                "updated_at": entry["updated_at"]
            })

        except InvalidToken:

            continue

    return render_template(
        "diary.html",
        diary=diary,
        entries=decrypted_entries
    )


@app.route(
    "/diary/<int:diary_id>/entry",
    methods=["GET", "POST"]
)
def create_entry(diary_id):

    if not logged_in():

        return redirect(
            url_for("login")
        )

    diary = get_user_diary(
        diary_id
    )

    if not diary:

        return redirect(
            url_for("dashboard")
        )

    key = get_unlock_key(
        diary_id
    )

    if not key:

        return redirect(
            url_for(
                "locked_diary",
                diary_id=diary_id
            )
        )

    if request.method == "POST":

        title = request.form.get(
            "title",
            ""
        ).strip()

        content = request.form.get(
            "content",
            ""
        ).strip()

        if not title or not content:

            flash(
                "Title and content are required.",
                "error"
            )

            return render_template(
                "entry.html",
                diary=diary,
                entry=None
            )

        cipher = Fernet(key)

        encrypted_title = cipher.encrypt(
            title.encode()
        ).decode()

        encrypted_content = cipher.encrypt(
            content.encode()
        ).decode()

        now = current_time()

        execute(
            """
            INSERT INTO entries
            (
                diary_id,
                encrypted_title,
                encrypted_content,
                created_at,
                updated_at
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                diary_id,
                encrypted_title,
                encrypted_content,
                now,
                now
            )
        )

        flash(
            "Entry encrypted and saved.",
            "success"
        )

        return redirect(
            url_for(
                "unlocked_diary",
                diary_id=diary_id
            )
        )

    return render_template(
        "entry.html",
        diary=diary,
        entry=None
    )


@app.route(
    "/diary/<int:diary_id>/entry/<int:entry_id>"
)
def view_entry(
    diary_id,
    entry_id
):

    if not logged_in():

        return redirect(
            url_for("login")
        )

    diary = get_user_diary(
        diary_id
    )

    key = get_unlock_key(
        diary_id
    )

    if not diary or not key:

        return redirect(
            url_for(
                "locked_diary",
                diary_id=diary_id
            )
        )

    entry = fetch_one(
        """
        SELECT *
        FROM entries
        WHERE id = %s
        AND diary_id = %s
        """,
        (
            entry_id,
            diary_id
        )
    )

    if not entry:

        flash(
            "Entry not found.",
            "error"
        )

        return redirect(
            url_for(
                "unlocked_diary",
                diary_id=diary_id
            )
        )

    cipher = Fernet(key)

    try:

        title = cipher.decrypt(
            entry["encrypted_title"].encode()
        ).decode()

        content = cipher.decrypt(
            entry["encrypted_content"].encode()
        ).decode()

    except InvalidToken:

        flash(
            "Unable to decrypt entry.",
            "error"
        )

        return redirect(
            url_for(
                "unlocked_diary",
                diary_id=diary_id
            )
        )

    entry_data = {
        "id": entry["id"],
        "title": title,
        "content": content,
        "created_at": entry["created_at"],
        "updated_at": entry["updated_at"]
    }

    return render_template(
        "entry.html",
        diary=diary,
        entry=entry_data
    )


@app.route(
    "/diary/<int:diary_id>/entry/<int:entry_id>/delete",
    methods=["GET", "POST"]
)
def delete_entry(
    diary_id,
    entry_id
):

    if not logged_in():

        return redirect(
            url_for("login")
        )

    diary = get_user_diary(
        diary_id
    )

    key = get_unlock_key(
        diary_id
    )

    if not diary or not key:

        return redirect(
            url_for(
                "locked_diary",
                diary_id=diary_id
            )
        )

    execute(
        """
        DELETE FROM entries
        WHERE id = %s
        AND diary_id = %s
        """,
        (
            entry_id,
            diary_id
        )
    )

    flash(
        "Entry deleted.",
        "success"
    )

    return redirect(
        url_for(
            "unlocked_diary",
            diary_id=diary_id
        )
    )


@app.route(
    "/diary/<int:diary_id>/lock"
)
def lock_diary(diary_id):

    lock_current_diary()

    return redirect(
        url_for(
            "locked_diary",
            diary_id=diary_id
        )
    )


@app.route("/lock")
def lock():

    lock_current_diary()

    return redirect(
        url_for("dashboard")
    )


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=True
    )
