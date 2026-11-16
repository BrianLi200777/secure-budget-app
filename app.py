import os
import sqlite3
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv
from flask import Flask, flash, g, redirect, render_template, request, session, url_for

load_dotenv()

app = Flask(__name__)
# Signs the session cookie so users can't forge a "logged in" cookie.
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
# Browser won't send the cookie on most cross-site requests.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DATABASE = "budget.db"
password_hasher = PasswordHasher()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )"""
        )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
@login_required
def home():
    user = get_db().execute(
        "SELECT username FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    return render_template("home.html", username=user["username"])


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        if not 3 <= len(username) <= 30:
            flash("Username must be 3 to 30 characters.")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.")
        else:
            try:
                db = get_db()
                # "?" placeholders keep user input from being run as SQL (SQL injection).
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hasher.hash(password)),
                )
                db.commit()
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is taken.")

    return render_template("auth.html", title="Create account", other="login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

        try:
            if user is None:
                raise VerifyMismatchError
            password_hasher.verify(user["password_hash"], password)
        except VerifyMismatchError:
            # Same message either way, so attackers can't tell which usernames exist.
            flash("Invalid username or password.")
            return render_template("auth.html", title="Log in", other="register")

        if password_hasher.check_needs_rehash(user["password_hash"]):
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hasher.hash(password), user["id"]),
            )
            db.commit()

        # Start a fresh session so an attacker can't plant a session ID beforehand.
        session.clear()
        session["user_id"] = user["id"]
        return redirect(url_for("home"))

    return render_template("auth.html", title="Log in", other="register")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


init_db()

if __name__ == "__main__":
    app.run(debug=True, port=5001)
