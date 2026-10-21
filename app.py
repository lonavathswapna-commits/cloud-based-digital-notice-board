import os
import re
from datetime import date
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor

from flask import (
    Flask,
    jsonify,
    request,
    session,
    send_from_directory,
    redirect
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# --------------------------------------------------
# Application configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DATABASE_URL = os.environ.get("DATABASE_URL")

app = Flask(__name__, static_folder=None)

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

if not app.secret_key:
    if os.environ.get("RENDER"):
        raise RuntimeError(
            "FLASK_SECRET_KEY must be configured in Render."
        )

    # Development-only secret for local testing.
    app.secret_key = "local-development-secret-change-before-deployment"

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Enable secure cookies when deployed over HTTPS.
app.config["SESSION_COOKIE_SECURE"] = bool(
    os.environ.get("RENDER")
)

ALLOWED_PAGES = {
    "index.html",
    "login.html",
    "register.html",
    "add-notice.html",
    "my-notices.html",
    "profile.html",
    "logout.html",
}


# --------------------------------------------------
# PostgreSQL database connection
# --------------------------------------------------

class DatabaseConnection:
    """
    Small compatibility wrapper that provides execute(),
    commit(), rollback(), and close() operations.
    """

    def __init__(self, connection):
        self.connection = connection

    def execute(self, query, params=None):
        cursor = self.connection.cursor(
            cursor_factory=RealDictCursor
        )

        cursor.execute(query, params or ())
        return cursor

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


def get_db():
    """
    Connect to the PostgreSQL database configured through
    the DATABASE_URL environment variable.
    """

    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is missing. Configure it in Render "
            "or in your local environment."
        )

    connection = psycopg2.connect(DATABASE_URL)

    return DatabaseConnection(connection)


# --------------------------------------------------
# Common error response
# --------------------------------------------------

def json_error(message, status=400):
    return jsonify({
        "success": False,
        "message": message
    }), status


# --------------------------------------------------
# Database initialization
# --------------------------------------------------

def ensure_database_schema():
    """
    Create the required PostgreSQL tables if they do not
    already exist. Add missing notice columns when needed.
    """

    conn = get_db()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                phone TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS notices (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                date TEXT,
                user_id INTEGER
            )
        """)

        # Inspect the existing notices table.
        columns = {
            row["column_name"]
            for row in conn.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'notices'
            """).fetchall()
        }

        # Add missing columns without deleting existing data.
        if "date" not in columns:
            conn.execute("""
                ALTER TABLE notices
                ADD COLUMN date TEXT
            """)

        if "user_id" not in columns:
            conn.execute("""
                ALTER TABLE notices
                ADD COLUMN user_id INTEGER
            """)

        if "created_at" not in columns:
            conn.execute("""
                ALTER TABLE notices
                ADD COLUMN created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
            """)

        conn.commit()

        app.logger.info(
            "PostgreSQL database initialized successfully."
        )

    except psycopg2.Error:
        conn.rollback()
        app.logger.exception(
            "PostgreSQL database initialization failed."
        )
        raise

    finally:
        conn.close()


# Initialize the database when the application starts.
# This also runs when Gunicorn starts the application on Render.
try:
    ensure_database_schema()
except Exception:
    app.logger.exception(
        "Application database initialization failed."
    )
    raise


# --------------------------------------------------
# Page routes
# --------------------------------------------------

@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "register.html")


@app.route("/<path:page>")
def serve_page(page):
    if page in ALLOWED_PAGES:
        return send_from_directory(BASE_DIR, page)

    return "Page not found", 404


# --------------------------------------------------
# Registration
# --------------------------------------------------

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}

    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    phone = str(data.get("phone", "")).strip()
    password = str(data.get("password", ""))

    if not name or not email or not phone or not password:
        return json_error(
            "Please fill in all required fields."
        )

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return json_error(
            "Please enter a valid email address."
        )

    if not re.fullmatch(r"[0-9]{10}", phone):
        return json_error(
            "Please enter a valid 10-digit phone number."
        )

    if len(password) < 8:
        return json_error(
            "Password must contain at least 8 characters."
        )

    conn = get_db()

    try:
        conn.execute("""
            INSERT INTO users (
                name,
                email,
                password_hash,
                phone
            )
            VALUES (%s, %s, %s, %s)
        """, (
            name,
            email,
            generate_password_hash(password),
            phone
        ))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Registration successful. You can now log in."
        }), 201

    except psycopg2.errors.UniqueViolation:
        conn.rollback()

        return json_error(
            "This email is already registered. Please log in.",
            409
        )

    except psycopg2.Error:
        conn.rollback()

        app.logger.exception(
            "Registration database error."
        )

        return json_error(
            "Unable to register. Please check the database.",
            500
        )

    finally:
        conn.close()


# --------------------------------------------------
# Login
# --------------------------------------------------

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return json_error(
            "Please enter your email and password."
        )

    conn = get_db()

    try:
        user = conn.execute("""
            SELECT
                id,
                name,
                email,
                password_hash,
                phone
            FROM users
            WHERE email = %s
        """, (email,)).fetchone()

    except psycopg2.Error:
        app.logger.exception("Login database error.")

        return json_error(
            "Unable to access the users table.",
            500
        )

    finally:
        conn.close()

    if user is None or not check_password_hash(
        user["password_hash"], password
    ):
        return json_error(
            "Incorrect email or password.",
            401
        )

    session.clear()
    session["user_id"] = user["id"]

    return jsonify({
        "success": True,
        "message": "Login successful.",
        "redirect": "/index.html"
    })


# --------------------------------------------------
# Current user
# --------------------------------------------------

@app.route("/api/me", methods=["GET"])
def api_me():
    if "user_id" not in session:
        return json_error(
            "Please log in first.",
            401
        )

    conn = get_db()

    try:
        user = conn.execute("""
            SELECT id, name, email, phone
            FROM users
            WHERE id = %s
        """, (session["user_id"],)).fetchone()

    except psycopg2.Error:
        app.logger.exception(
            "Unable to load current user."
        )

        return json_error(
            "Unable to load user details.",
            500
        )

    finally:
        conn.close()

    if user is None:
        session.clear()

        return json_error(
            "Please log in again.",
            401
        )

    user_data = dict(user)

    return jsonify({
        "success": True,
        "user": user_data,
        **user_data
    })


# --------------------------------------------------
# Profile
# --------------------------------------------------

@app.route("/api/profile", methods=["GET", "PUT"])
def api_profile():
    if "user_id" not in session:
        return json_error(
            "Please log in first.",
            401
        )

    user_id = session["user_id"]
    conn = get_db()

    try:
        if request.method == "GET":

            user = conn.execute("""
                SELECT id, name, email, phone
                FROM users
                WHERE id = %s
            """, (user_id,)).fetchone()

            if user is None:
                session.clear()

                return json_error(
                    "Please log in again.",
                    401
                )

            user_data = dict(user)

            return jsonify({
                "success": True,
                "user": user_data,
                **user_data
            })

        data = request.get_json(silent=True) or {}

        name = str(data.get("name", "")).strip()
        email = str(data.get("email", "")).strip().lower()
        phone = str(data.get("phone", "")).strip()

        if not name or not email or not phone:
            return json_error(
                "Please fill in all three fields."
            )

        if not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+", email
        ):
            return json_error(
                "Please enter a valid email address."
            )

        if not re.fullmatch(r"[0-9]{10}", phone):
            return json_error(
                "Please enter a valid 10-digit phone number."
            )

        duplicate = conn.execute("""
            SELECT id
            FROM users
            WHERE email = %s AND id != %s
        """, (email, user_id)).fetchone()

        if duplicate:
            return json_error(
                "This email is already registered to another account.",
                409
            )

        cursor = conn.execute("""
            UPDATE users
            SET name = %s,
                email = %s,
                phone = %s
            WHERE id = %s
        """, (name, email, phone, user_id))

        if cursor.rowcount == 0:
            conn.rollback()
            session.clear()

            return json_error(
                "Please log in again.",
                401
            )

        conn.commit()

        user = conn.execute("""
            SELECT id, name, email, phone
            FROM users
            WHERE id = %s
        """, (user_id,)).fetchone()

        user_data = dict(user)

        return jsonify({
            "success": True,
            "message": "Profile updated successfully.",
            "user": user_data,
            **user_data
        })

    except psycopg2.errors.UniqueViolation:
        conn.rollback()

        return json_error(
            "This email is already registered.",
            409
        )

    except psycopg2.Error:
        conn.rollback()

        app.logger.exception(
            "Profile database error."
        )

        return json_error(
            "Unable to update the profile.",
            500
        )

    finally:
        conn.close()


# --------------------------------------------------
# Add notice and retrieve all notices
# --------------------------------------------------

@app.route("/api/notices", methods=["GET", "POST"])
def api_notices():

    # ----------------------------------------------
    # POST: Save a new notice
    # ----------------------------------------------

    if request.method == "POST":

        if "user_id" not in session:
            return json_error(
                "Please log in before adding a notice.",
                401
            )

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return json_error(
                "Invalid request. Please submit the notice form again."
            )

        title = str(data.get("title", "")).strip()
        category = str(data.get("category", "")).strip()
        description = str(data.get("description", "")).strip()
        notice_date = str(data.get("date", "")).strip()

        allowed_categories = {
            "Academic",
            "Event",
            "Important",
            "Placement",
            "General"
        }

        if not title or not category or not description or not notice_date:
            return json_error(
                "Please fill in all required fields."
            )

        if category not in allowed_categories:
            return json_error(
                "Please select a valid category."
            )

        try:
            parsed_date = date.fromisoformat(notice_date)
        except ValueError:
            return json_error(
                "Please select a valid date."
            )

        if parsed_date < date.today():
            return json_error(
                "Past dates are not allowed. Please select today or a future date."
            )

        conn = get_db()

        try:
            cursor = conn.execute("""
                INSERT INTO notices (
                    title,
                    description,
                    category,
                    date,
                    user_id
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (
                title,
                description,
                category,
                notice_date,
                session["user_id"]
            ))

            notice_id = cursor.fetchone()["id"]

            conn.commit()

            app.logger.info(
                "Notice %s saved successfully by user %s",
                notice_id,
                session["user_id"]
            )

            return jsonify({
                "success": True,
                "message": "Notice submitted successfully!",
                "notice_id": notice_id
            }), 201

        except psycopg2.Error:
            conn.rollback()

            app.logger.exception(
                "Notice database error."
            )

            return json_error(
                "Unable to save the notice. Please check the database.",
                500
            )

        finally:
            conn.close()

    # ----------------------------------------------
    # GET: Return all notices for the Home page
    # ----------------------------------------------

    conn = get_db()

    try:
        rows = conn.execute("""
            SELECT
                n.id,
                n.title,
                n.description,
                n.category,
                n.date,
                n.created_at,
                n.user_id,
                u.name AS author_name
            FROM notices AS n
            LEFT JOIN users AS u
                ON u.id = n.user_id
            ORDER BY
                COALESCE(
                    NULLIF(n.date, '')::date,
                    n.created_at::date
                ) DESC NULLS LAST,
                n.id DESC
        """).fetchall()

        return jsonify({
            "success": True,
            "notices": [dict(row) for row in rows]
        })

    except psycopg2.Error:
        app.logger.exception(
            "Unable to retrieve notices."
        )

        return json_error(
            "Unable to retrieve notices.",
            500
        )

    finally:
        conn.close()


# --------------------------------------------------
# My Notices
# --------------------------------------------------

@app.route("/api/my-notices", methods=["GET"])
def api_my_notices():

    if "user_id" not in session:
        return json_error(
            "Please log in first.",
            401
        )

    conn = get_db()

    try:
        rows = conn.execute("""
            SELECT
                id,
                title,
                description,
                category,
                date,
                created_at,
                user_id
            FROM notices
            WHERE user_id = %s
            ORDER BY
                COALESCE(
                    NULLIF(date, '')::date,
                    created_at::date
                ) DESC NULLS LAST,
                id DESC
        """, (session["user_id"],)).fetchall()

        return jsonify({
            "success": True,
            "notices": [dict(row) for row in rows]
        })

    except psycopg2.Error:
        app.logger.exception(
            "Unable to retrieve user's notices."
        )

        return json_error(
            "Unable to retrieve your notices.",
            500
        )

    finally:
        conn.close()


# --------------------------------------------------
# Edit an existing notice
# --------------------------------------------------

@app.route("/api/notices/<int:notice_id>", methods=["PUT"])
def edit_notice(notice_id):

    if "user_id" not in session:
        return json_error(
            "Please log in first.",
            401
        )

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return json_error(
            "Invalid request data."
        )

    title = str(data.get("title", "")).strip()
    category = str(data.get("category", "")).strip()
    description = str(data.get("description", "")).strip()
    notice_date = str(data.get("date", "")).strip()

    allowed_categories = {
        "Academic",
        "Event",
        "Important",
        "Placement",
        "General"
    }

    if not title or not category or not description or not notice_date:
        return json_error(
            "Please fill in all required fields."
        )

    if category not in allowed_categories:
        return json_error(
            "Please select a valid category."
        )

    try:
        date.fromisoformat(notice_date)
    except ValueError:
        return json_error(
            "Please enter a valid date."
        )

    conn = get_db()

    try:
        cursor = conn.execute("""
            UPDATE notices
            SET title = %s,
                category = %s,
                description = %s,
                date = %s
            WHERE id = %s
              AND user_id = %s
        """, (
            title,
            category,
            description,
            notice_date,
            notice_id,
            session["user_id"]
        ))

        conn.commit()

        if cursor.rowcount == 0:
            return json_error(
                "Notice not found or you do not have permission to edit it.",
                404
            )

        return jsonify({
            "success": True,
            "message": "Notice updated successfully!"
        })

    except psycopg2.Error:
        conn.rollback()

        app.logger.exception(
            "Error updating notice."
        )

        return json_error(
            "Unable to update the notice. Please try again.",
            500
        )

    finally:
        conn.close()


# --------------------------------------------------
# Delete an existing notice
# --------------------------------------------------

@app.route("/api/notices/<int:notice_id>", methods=["DELETE"])
def delete_notice(notice_id):

    if "user_id" not in session:
        return json_error(
            "Please log in first.",
            401
        )

    conn = get_db()

    try:
        cursor = conn.execute("""
            DELETE FROM notices
            WHERE id = %s
              AND user_id = %s
        """, (
            notice_id,
            session["user_id"]
        ))

        conn.commit()

        if cursor.rowcount == 0:
            return json_error(
                "Notice not found or you do not have permission to delete it.",
                404
            )

        return jsonify({
            "success": True,
            "message": "Notice deleted successfully!"
        })

    except psycopg2.Error:
        conn.rollback()

        app.logger.exception(
            "Error deleting notice."
        )

        return json_error(
            "Unable to delete the notice. Please try again.",
            500
        )

    finally:
        conn.close()


# --------------------------------------------------
# Logout
# --------------------------------------------------

@app.route("/api/logout", methods=["POST"])
def api_logout():

    session.clear()

    return jsonify({
        "success": True,
        "message": "Logged out successfully.",
        "redirect": "/login.html"
    })


@app.route("/logout")
def logout_page():

    session.clear()

    return redirect("/login.html")


# --------------------------------------------------
# Start application locally
# --------------------------------------------------

if __name__ == "__main__":

    print("=" * 50)
    print("Cloud-Based Digital Notice Board")
    print("Database: PostgreSQL")
    print("Open: http://127.0.0.1:5000")
    print("=" * 50)

    app.run(debug=True)