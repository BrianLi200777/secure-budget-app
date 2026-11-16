import os
import sqlite3
import time
from functools import wraps

import plaid
import urllib3
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for
from plaid.api import plaid_api
from plaid.model.country_code import CountryCode
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.products import Products
from plaid.model.transactions_sync_request import TransactionsSyncRequest

load_dotenv()

app = Flask(__name__)
# Signs the session cookie so users can't forge a "logged in" cookie.
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
# Browser won't send the cookie on most cross-site requests.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DATABASE = "budget.db"
password_hasher = PasswordHasher()
# Encrypts Plaid access tokens at rest. A stolen database is useless without this key.
fernet = Fernet(os.environ["FERNET_KEY"])

plaid_client = plaid_api.PlaidApi(
    plaid.ApiClient(
        plaid.Configuration(
            host=plaid.Environment.Sandbox,
            api_key={
                "clientId": os.environ["PLAID_CLIENT_ID"],
                "secret": os.environ["PLAID_SECRET"],
            },
        )
    )
)
# Plaid rejected the request, or we couldn't reach Plaid at all.
PLAID_ERRORS = (plaid.ApiException, urllib3.exceptions.HTTPError)


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
        db.execute(
            """CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                plaid_item_id TEXT NOT NULL,
                access_token_encrypted BLOB NOT NULL,
                cursor TEXT
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                item_id INTEGER NOT NULL REFERENCES items(id),
                date TEXT NOT NULL,
                name TEXT NOT NULL,
                amount REAL NOT NULL,
                category TEXT
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
    db = get_db()
    user = db.execute(
        "SELECT username FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    transactions = db.execute(
        "SELECT date, name, amount, category FROM transactions WHERE user_id = ? "
        "ORDER BY date DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template(
        "home.html", username=user["username"], transactions=transactions
    )


@app.route("/plaid/link_token", methods=["POST"])
@login_required
def create_link_token():
    request_body = LinkTokenCreateRequest(
        user=LinkTokenCreateRequestUser(client_user_id=str(session["user_id"])),
        client_name="Secure Budget",
        products=[Products("transactions")],
        country_codes=[CountryCode("US")],
        language="en",
    )
    try:
        response = plaid_client.link_token_create(request_body)
    except PLAID_ERRORS:
        app.logger.exception("Plaid link_token_create failed")
        return jsonify(error="Could not start bank connection."), 502
    return jsonify(link_token=response["link_token"])


@app.route("/plaid/exchange", methods=["POST"])
@login_required
def exchange_public_token():
    public_token = (request.get_json(silent=True) or {}).get("public_token")
    if not public_token:
        return jsonify(error="Missing public token."), 400
    try:
        response = plaid_client.item_public_token_exchange(
            ItemPublicTokenExchangeRequest(public_token=public_token)
        )
    except PLAID_ERRORS:
        app.logger.exception("Plaid token exchange failed")
        return jsonify(error="Could not connect bank."), 502

    # The access token is encrypted before it ever touches the database.
    encrypted = fernet.encrypt(response["access_token"].encode())
    db = get_db()
    db.execute(
        "INSERT INTO items (user_id, plaid_item_id, access_token_encrypted) "
        "VALUES (?, ?, ?)",
        (session["user_id"], response["item_id"], encrypted),
    )
    db.commit()
    try:
        sync_transactions(session["user_id"])
    except PLAID_ERRORS:
        # The bank is connected; "Refresh transactions" can try again later.
        app.logger.exception("Initial Plaid transactions sync failed")
    return jsonify(ok=True)


@app.route("/plaid/sync", methods=["POST"])
@login_required
def refresh_transactions():
    try:
        sync_transactions(session["user_id"])
    except PLAID_ERRORS:
        app.logger.exception("Plaid transactions sync failed")
        flash("Could not refresh transactions. Try again later.")
    return redirect(url_for("home"))


def sync_transactions(user_id):
    db = get_db()
    items = db.execute(
        "SELECT id, access_token_encrypted, cursor FROM items WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    for item in items:
        access_token = fernet.decrypt(item["access_token_encrypted"]).decode()
        cursor = item["cursor"]
        for attempt in range(10):
            request_args = {"access_token": access_token}
            if cursor:
                request_args["cursor"] = cursor
            response = plaid_client.transactions_sync(
                TransactionsSyncRequest(**request_args)
            )

            for t in response["added"] + response["modified"]:
                category = t.get("personal_finance_category")
                db.execute(
                    "INSERT OR REPLACE INTO transactions "
                    "(id, user_id, item_id, date, name, amount, category) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        t["transaction_id"],
                        user_id,
                        item["id"],
                        str(t["date"]),
                        t["name"],
                        t["amount"],
                        category["primary"] if category else None,
                    ),
                )
            for t in response["removed"]:
                db.execute(
                    "DELETE FROM transactions WHERE id = ? AND user_id = ?",
                    (t["transaction_id"], user_id),
                )

            cursor = response["next_cursor"]
            if response["has_more"]:
                continue
            # A brand-new bank connection can take a few seconds before Plaid has data.
            if not cursor:
                time.sleep(2)
                continue
            break

        db.execute("UPDATE items SET cursor = ? WHERE id = ?", (cursor, item["id"]))
        db.commit()


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
