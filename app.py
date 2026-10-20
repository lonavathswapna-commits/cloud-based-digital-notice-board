
import os
import re
import sqlite3
from datetime import date
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    request,
    session,
    send_from_directory,
    redirect
)
from werkzeug.security import generate_password_hash, check_password_hash


# --------------------------------------------------
# Application and database configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "digital_notice_board.db"

app = Flask(__name__, static_folder=None)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "development-only-change-this-secret-key"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

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
# Database connection
# --------------------------------------------------

def get_db():
    """Connect to the project's SQLite database."""
    conn = sqlite3.connect(str(DATABASE))
    conn.row_factory = sqlite3.Row
    return conn


def json_error(message, status=400):
    return jsonify({
        "success": False,
        "message": message
    }), status


# --------------------------------------------------
# Database initialization and migration
# --------------------------------------------------

def ensure_database_schema():
    conn = get_db()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                phone TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS notices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                date TEXT,
                user_id INTEGER
            )
        """)

        # Check existing notices table columns.
        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(notices)"
            ).fetchall()
        }

        # Add missing columns without deleting existing notices.
        if "date" not in columns:
            conn.execute(
                "ALTER TABLE notices ADD COLUMN date TEXT"
            )

        if "user_id" not in columns:
            conn.execute(
                "ALTER TABLE notices ADD COLUMN user_id INTEGER"
            )

        if "created_at" not in columns:
            conn.execute(
                "ALTER TABLE notices ADD COLUMN created_at TEXT"
            )

        conn.commit()

        app.logger.info("Database initialized: %s", DATABASE)

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Database initialization failed")
        raise

    finally:
        conn.close()


# --------------------------------------------------
# Page routes
# --------------------------------------------------

@app.route("/")
def home():
    # Open the registration page first.
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
        return json_error("Please fill in all required fields.")

    # Correct email validation.
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return json_error("Please enter a valid email address.")

    if not re.fullmatch(r"[0-9]{10}", phone):
        return json_error("Please enter a valid 10-digit phone number.")

    if len(password) < 8:
        return json_error("Password must contain at least 8 characters.")

    conn = get_db()

    try:
        conn.execute(
            """
            INSERT INTO users (name, email, password_hash, phone)
            VALUES (?, ?, ?, ?)
            """,
            (
                name,
                email,
                generate_password_hash(password),
                phone
            )
        )

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Registration successful. You can now log in."
        }), 201

    except sqlite3.IntegrityError:
        return json_error(
            "This email is already registered. Please log in.",
            409
        )

    except sqlite3.Error:
        app.logger.exception("Registration database error")
        return json_error("Unable to register. Check the database.", 500)

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
        return json_error("Please enter your email and password.")

    conn = get_db()

    try:
        user = conn.execute(
            """
            SELECT id, name, email, password_hash, phone
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

    except sqlite3.Error:
        app.logger.exception("Login database error")
        return json_error("Unable to access the users table.", 500)

    finally:
        conn.close()

    if user is None or not check_password_hash(
        user["password_hash"], password
    ):
        return json_error("Incorrect email or password.", 401)

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
        return json_error("Please log in first.", 401)

    conn = get_db()

    try:
        user = conn.execute(
            """
            SELECT id, name, email, phone
            FROM users
            WHERE id = ?
            """,
            (session["user_id"],)
        ).fetchone()

    except sqlite3.Error:
        app.logger.exception("Unable to load current user")
        return json_error("Unable to load user details.", 500)

    finally:
        conn.close()

    if user is None:
        session.clear()
        return json_error("Please log in again.", 401)

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
        return json_error("Please log in first.", 401)

    user_id = session["user_id"]
    conn = get_db()

    try:
        if request.method == "GET":
            user = conn.execute(
                """
                SELECT id, name, email, phone
                FROM users
                WHERE id = ?
                """,
                (user_id,)
            ).fetchone()

            if user is None:
                session.clear()
                return json_error("Please log in again.", 401)

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
            return json_error("Please fill in all three fields.")

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return json_error("Please enter a valid email address.")

        if not re.fullmatch(r"[0-9]{10}", phone):
            return json_error("Please enter a valid 10-digit phone number.")

        duplicate = conn.execute(
            """
            SELECT id FROM users
            WHERE email = ? AND id != ?
            """,
            (email, user_id)
        ).fetchone()

        if duplicate:
            return json_error(
                "This email is already registered to another account.",
                409
            )

        cursor = conn.execute(
            """
            UPDATE users
            SET name = ?, email = ?, phone = ?
            WHERE id = ?
            """,
            (name, email, phone, user_id)
        )

        if cursor.rowcount == 0:
            session.clear()
            return json_error("Please log in again.", 401)

        conn.commit()

        user = conn.execute(
            """
            SELECT id, name, email, phone
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        user_data = dict(user)

        return jsonify({
            "success": True,
            "user": user_data,
            **user_data
        })

    except sqlite3.IntegrityError:
        conn.rollback()
        return json_error("This email is already registered.", 409)

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Profile database error")
        return json_error("Unable to update the profile.", 500)

    finally:
        conn.close()


# --------------------------------------------------
# Add Notice and retrieve all notices
# --------------------------------------------------

@app.route("/api/notices", methods=["GET", "POST"])
def api_notices():

    # ----------------------------------------------
    # POST: Save a new notice
    # ----------------------------------------------

    if request.method == "POST":

        if "user_id" not in session:
            return json_error("Please log in before adding a notice.", 401)

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
            return json_error("Please fill in all required fields.")

        if category not in allowed_categories:
            return json_error("Please select a valid category.")

        # Validate the actual calendar date.
        try:
            parsed_date = date.fromisoformat(notice_date)
        except ValueError:
            return json_error("Please select a valid date.")

        if parsed_date < date.today():
            return json_error(
                "Past dates are not allowed. Please select today or a future date."
            )

        conn = get_db()

        try:
            cursor = conn.execute(
                """
                INSERT INTO notices
                    (title, description, category, date, user_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    title,
                    description,
                    category,
                    notice_date,
                    session["user_id"]
                )
            )

            conn.commit()

            notice_id = cursor.lastrowid

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

        except sqlite3.Error:
            conn.rollback()
            app.logger.exception("Notice database error")

            return json_error(
                "Unable to save the notice. Check the database and notices table.",
                500
            )

        finally:
            conn.close()

    # ----------------------------------------------
    # GET: Return all notices for the Home page
    # ----------------------------------------------

    conn = get_db()

    try:
        rows = conn.execute(
            """
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
            LEFT JOIN users AS u ON u.id = n.user_id
            ORDER BY
                COALESCE(n.date, n.created_at) DESC,
                n.id DESC
            """
        ).fetchall()

        return jsonify({
            "success": True,
            "notices": [dict(row) for row in rows]
        })

    except sqlite3.Error:
        app.logger.exception("Unable to retrieve notices")
        return json_error("Unable to retrieve notices.", 500)

    finally:
        conn.close()


# --------------------------------------------------
# My Notices
# --------------------------------------------------

@app.route("/api/my-notices", methods=["GET"])
def api_my_notices():

    if "user_id" not in session:
        return json_error("Please log in first.", 401)

    conn = get_db()

    try:
        rows = conn.execute(
            """
            SELECT
                id,
                title,
                description,
                category,
                date,
                created_at,
                user_id
            FROM notices
            WHERE user_id = ?
            ORDER BY
                COALESCE(date, created_at) DESC,
                id DESC
            """,
            (session["user_id"],)
        ).fetchall()

        return jsonify({
            "success": True,
            "notices": [dict(row) for row in rows]
        })

    except sqlite3.Error:
        app.logger.exception("Unable to retrieve user's notices")
        return json_error("Unable to retrieve your notices.", 500)

    finally:
        conn.close()


# --------------------------------------------------
# Edit an existing notice
# --------------------------------------------------
@app.route("/api/notices/<int:notice_id>", methods=["PUT"])
def edit_notice(notice_id):
    # Check whether the user is logged in.
    if "user_id" not in session:
        return json_error("Please log in first.", 401)

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return json_error("Invalid request data.")

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

    # Validate the submitted fields.
    if not title or not category or not description or not notice_date:
        return json_error("Please fill in all required fields.")

    if category not in allowed_categories:
        return json_error("Please select a valid category.")

    # Validate the date.
    try:
        date.fromisoformat(notice_date)
    except ValueError:
        return json_error("Please enter a valid date.")

    conn = get_db()

    try:
        # Update only a notice owned by the logged-in user.
        cursor = conn.execute(
            """
            UPDATE notices
            SET title = ?,
                category = ?,
                description = ?,
                date = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                title,
                category,
                description,
                notice_date,
                notice_id,
                session["user_id"]
            )
        )

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

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Error updating notice")

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
    # Check whether the user is logged in.
    if "user_id" not in session:
        return json_error("Please log in first.", 401)

    conn = get_db()

    try:
        # Delete only a notice owned by the logged-in user.
        cursor = conn.execute(
            """
            DELETE FROM notices
            WHERE id = ? AND user_id = ?
            """,
            (
                notice_id,
                session["user_id"]
            )
        )

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

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Error deleting notice")

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
# Start application
# --------------------------------------------------

if __name__ == "__main__":
    ensure_database_schema()

    print("=" * 50)
    print("Digital Notice Board is starting...")
    print("Database:", DATABASE)
    print("Open: http://127.0.0.1:5000")
    print("=" * 50)

    app.run(debug=True)
