import os
import secrets
import sqlite3
import time
from datetime import date, datetime, timedelta
from functools import wraps

import plaid
import urllib3
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect
from plaid.api import plaid_api
from plaid.model.country_code import CountryCode
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.products import Products
from plaid.model.transactions_sync_request import TransactionsSyncRequest
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

app = Flask(__name__)
# Signs the session cookie so users can't forge a "logged in" cookie.
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
# Browser won't send the cookie on most cross-site requests.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# JavaScript can't read the login cookie, so an injected script can't steal it.
app.config["SESSION_COOKIE_HTTPONLY"] = True
# Set APP_ENV=production once the app is online with HTTPS.
PRODUCTION = os.environ.get("APP_ENV") == "production"
# Only send the login cookie over HTTPS. Off locally, where there's no HTTPS.
app.config["SESSION_COOKIE_SECURE"] = PRODUCTION
if PRODUCTION:
    # Online, the host's proxy (one hop) forwards each request. Trust its headers for
    # the visitor's real IP (so rate limits are per visitor) and for HTTPS. Not trusted
    # locally, where anyone could fake these headers to dodge the rate limit.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Every form and POST request must carry a secret token that only our own pages have,
# so other websites can't submit requests as a logged-in user (CSRF).
csrf = CSRFProtect(app)
# Counts requests per IP address to slow down password guessing.
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

# Tells the browser what this page may load. Scripts only from us and Plaid, and
# no inline scripts, so injected <script> tags won't run. Inline styles are allowed
# because the progress bars set their width with style="...".
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self' https://cdn.plaid.com",
    "frame-src https://cdn.plaid.com",
    "connect-src 'self' https://sandbox.plaid.com https://production.plaid.com",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])

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

# Optional shared "demo" account so visitors can try the app without signing up.
# Its password is public on purpose (it's shown on the login page), so only set
# DEMO_PASSWORD on a demo site with fake data.
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "")
DEMO_ITEM_ID = "demo-sample-data"
# (days ago, name, amount, category). Positive = money out, like Plaid.
DEMO_TRANSACTIONS = [
    (0, "Starbucks", 4.75, "FOOD_AND_DRINK"),
    (1, "Whole Foods", 86.40, "FOOD_AND_DRINK"),
    (2, "Uber", 18.20, "TRANSPORTATION"),
    (3, "Chipotle", 13.75, "FOOD_AND_DRINK"),
    (4, "Gusto Payroll", -2400.00, "INCOME"),
    (5, "SparkFun", 89.40, "GENERAL_MERCHANDISE"),
    (6, "Trader Joe's", 112.90, "FOOD_AND_DRINK"),
    (8, "Touchstone Climbing", 78.50, "PERSONAL_CARE"),
    (9, "Eversource Energy", 64.10, "RENT_AND_UTILITIES"),
    (11, "United Airlines refund", -120.00, "TRAVEL"),
    (12, "AMC Theatres", 28.00, "ENTERTAINMENT"),
    (14, "Rent", 900.00, "RENT_AND_UTILITIES"),
    (20, "Gusto Payroll", -2400.00, "INCOME"),
    (25, "Target", 120.45, "GENERAL_MERCHANDISE"),
    (33, "Whole Foods", 95.10, "FOOD_AND_DRINK"),
    (40, "Rent", 900.00, "RENT_AND_UTILITIES"),
    (48, "Madison Bicycle Shop", 240.00, "TRANSPORTATION"),
    (61, "KFC", 22.10, "FOOD_AND_DRINK"),
    (70, "Rent", 900.00, "RENT_AND_UTILITIES"),
    (88, "Amazon", 210.00, "GENERAL_MERCHANDISE"),
    (100, "Rent", 900.00, "RENT_AND_UTILITIES"),
    (115, "McDonald's", 31.00, "FOOD_AND_DRINK"),
    (130, "Rent", 900.00, "RENT_AND_UTILITIES"),
    (150, "AMC Theatres", 28.00, "ENTERTAINMENT"),
]
DEMO_BUDGETS = {
    "FOOD_AND_DRINK": 300, "GENERAL_MERCHANDISE": 100,
    "TRANSPORTATION": 150, "ENTERTAINMENT": 60,
}

# Money moving between your own accounts isn't spending. A credit card payment would
# double-count purchases already made on the card.
NOT_SPENDING = ("INCOME", "TRANSFER_IN", "TRANSFER_OUT", "LOAN_PAYMENTS")
BUDGET_CATEGORIES = (
    "BANK_FEES",
    "ENTERTAINMENT",
    "FOOD_AND_DRINK",
    "GENERAL_MERCHANDISE",
    "GENERAL_SERVICES",
    "GOVERNMENT_AND_NON_PROFIT",
    "HOME_IMPROVEMENT",
    "MEDICAL",
    "PERSONAL_CARE",
    "RENT_AND_UTILITIES",
    "TRANSPORTATION",
    "TRAVEL",
    "OTHER",
)


@app.template_filter("money")
def money(amount):
    return f"${abs(amount):,.2f}"


@app.template_filter("category_label")
def category_label(category):
    return (category or "OTHER").replace("_", " ").capitalize()


@app.template_filter("short_date")
def short_date(iso_date):
    day = datetime.strptime(iso_date, "%Y-%m-%d")
    return f"{day:%b} {day.day}"


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    # Don't let the browser guess file types (stops some file-upload tricks).
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Older browsers' version of frame-ancestors: no embedding this site (clickjacking).
    response.headers["X-Frame-Options"] = "DENY"
    # Don't leak full page URLs to other sites.
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Financial data shouldn't be saved in the browser's cache.
    response.headers["Cache-Control"] = "no-store"
    if PRODUCTION:
        # Browser must always use HTTPS for this site from now on.
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(CSRFError)
def csrf_failed(error):
    if request.path.startswith("/plaid/"):
        return jsonify(error="Security check failed. Refresh the page and try again."), 400
    flash("Security check failed. Please try again.")
    return redirect(url_for("home"))


@app.errorhandler(429)
def too_many_requests(error):
    flash("Too many attempts. Please wait a minute and try again.")
    if request.endpoint == "register":
        return render_template("auth.html", title="Create account", other="login"), 429
    return render_template("auth.html", title="Log in", other="register"), 429


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
                password_hash TEXT NOT NULL,
                session_token TEXT
            )"""
        )
        # Databases made before session_token existed get the column added.
        columns = [row[1] for row in db.execute("PRAGMA table_info(users)")]
        if "session_token" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN session_token TEXT")
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
        db.execute(
            """CREATE TABLE IF NOT EXISTS budgets (
                user_id INTEGER NOT NULL REFERENCES users(id),
                category TEXT NOT NULL,
                monthly_limit REAL NOT NULL,
                PRIMARY KEY (user_id, category)
            )"""
        )


def seed_demo_account(password):
    """Create the demo account with sample data, unless it already exists."""
    with sqlite3.connect(DATABASE) as db:
        if db.execute("SELECT 1 FROM users WHERE username = 'demo'").fetchone():
            return
        user_id = db.execute(
            "INSERT INTO users (username, password_hash, session_token) VALUES ('demo', ?, ?)",
            (password_hasher.hash(password), secrets.token_hex(32)),
        ).lastrowid
        # A stand-in bank connection that holds the sample data. Sync skips it.
        item_id = db.execute(
            "INSERT INTO items (user_id, plaid_item_id, access_token_encrypted) VALUES (?, ?, ?)",
            (user_id, DEMO_ITEM_ID, fernet.encrypt(b"no-real-bank")),
        ).lastrowid
        today = date.today()
        db.executemany(
            "INSERT INTO transactions (id, user_id, item_id, date, name, amount, category) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(f"demo-{user_id}-{n}", user_id, item_id,
              (today - timedelta(days=days_ago)).isoformat(), name, amount, category)
             for n, (days_ago, name, amount, category) in enumerate(DEMO_TRANSACTIONS)],
        )
        db.executemany(
            "INSERT INTO budgets (user_id, category, monthly_limit) VALUES (?, ?, ?)",
            [(user_id, category, limit) for category, limit in DEMO_BUDGETS.items()],
        )


@app.context_processor
def demo_login_hint():
    return {"demo_password": DEMO_PASSWORD}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = None
        if "user_id" in session:
            user = get_db().execute(
                "SELECT id, username, session_token FROM users WHERE id = ?",
                (session["user_id"],),
            ).fetchone()
        # The login cookie must match this account's random token, not just its ID.
        # Otherwise, after a database reset, an old cookie could open whichever new
        # account reused that ID. Also catches accounts that no longer exist.
        if user is None or not secrets.compare_digest(
            user["session_token"] or "", session.get("session_token", "")
        ):
            if "user_id" in session:
                # Throw away the stale login, but keep the CSRF token of visitors who
                # were never logged in.
                session.clear()
            return redirect(url_for("login"))
        g.user = user
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
@login_required
def home():
    db = get_db()
    user_id = g.user["id"]
    transactions = db.execute(
        "SELECT date, name, amount, category FROM transactions WHERE user_id = ? "
        "ORDER BY date DESC",
        (user_id,),
    ).fetchall()

    month_start = date.today().replace(day=1).isoformat()
    # "Spent" counts purchases only (amount > 0). Refunds count under "money in" instead,
    # so they're never counted twice.
    # One "?" per excluded category, so the values still go in as safe parameters.
    # Only these "?" marks are added to the query text (never user input), which is why
    # the bandit SQL-injection warning below is marked as a reviewed false positive.
    not_spending = ",".join("?" * len(NOT_SPENDING))
    spent_by_category = {
        row[0]: row[1]
        for row in db.execute(
            "SELECT COALESCE(category, 'OTHER'), SUM(amount) FROM transactions "  # nosec B608
            f"WHERE user_id = ? AND date >= ? AND amount > 0 AND COALESCE(category, 'OTHER') NOT IN ({not_spending}) "
            "GROUP BY 1",
            (user_id, month_start, *NOT_SPENDING),
        )
    }
    money_in = db.execute(
        "SELECT COALESCE(SUM(-amount), 0) FROM transactions "
        "WHERE user_id = ? AND date >= ? AND amount < 0",
        (user_id, month_start),
    ).fetchone()[0]
    budgets = {
        row["category"]: row["monthly_limit"]
        for row in db.execute(
            "SELECT category, monthly_limit FROM budgets WHERE user_id = ?", (user_id,)
        )
    }

    budget_rows = []
    for category in set(spent_by_category) | set(budgets):
        spent = spent_by_category.get(category, 0)
        limit = budgets.get(category)
        percent = spent / limit * 100 if limit else None
        if percent is None:
            status = None
        elif percent >= 100:
            status = "over"
        elif percent >= 80:
            status = "near"
        else:
            status = "ok"
        budget_rows.append(
            {"category": category, "spent": spent, "limit": limit,
             "percent": percent, "status": status}
        )
    budget_rows.sort(key=lambda row: row["spent"], reverse=True)

    monthly = db.execute(
        "SELECT substr(date, 1, 7) AS month, SUM(amount) AS spent FROM transactions "  # nosec B608
        f"WHERE user_id = ? AND amount > 0 AND COALESCE(category, 'OTHER') NOT IN ({not_spending}) "
        "GROUP BY month ORDER BY month DESC LIMIT 6",
        (user_id, *NOT_SPENDING),
    ).fetchall()
    biggest_month = max((row["spent"] for row in monthly), default=0)
    chart = [
        {
            "label": datetime.strptime(row["month"], "%Y-%m").strftime("%b"),
            "spent": row["spent"],
            "height": row["spent"] / biggest_month * 100,
        }
        for row in reversed(monthly)
    ]

    budgeted = [row for row in budget_rows if row["limit"]]
    budget_total = sum(row["limit"] for row in budgeted)
    budget_left = budget_total - sum(row["spent"] for row in budgeted)

    return render_template(
        "home.html",
        title="Dashboard",
        budget_total=budget_total,
        budget_left=budget_left,
        current_month=date.today().strftime("%b"),
        username=g.user["username"],
        transactions=transactions,
        total_spent=sum(row["spent"] for row in budget_rows),
        money_in=money_in,
        budget_rows=budget_rows,
        chart=chart,
        # Categories with no spending or budget yet, for "Add a budget".
        other_categories=[c for c in BUDGET_CATEGORIES
                          if c not in {row["category"] for row in budget_rows}],
    )


@app.route("/budgets", methods=["POST"])
@login_required
def set_budget():
    category = request.form.get("category", "")
    limit_text = request.form.get("limit", "").strip()
    if category not in BUDGET_CATEGORIES:
        flash("Pick a category from the list.")
        return redirect(url_for("home"))

    db = get_db()
    if request.form.get("action") == "remove" or limit_text in ("", "0"):
        db.execute(
            "DELETE FROM budgets WHERE user_id = ? AND category = ?",
            (session["user_id"], category),
        )
        db.commit()
        flash(f"Budget removed for {category_label(category)}.")
        return redirect(url_for("home"))

    try:
        limit = round(float(limit_text), 2)
    except ValueError:
        limit = -1
    # Also rejects "nan" and "inf", which float() would otherwise accept.
    if not 0 < limit <= 1_000_000:
        flash("Budget must be a number between 0 and 1,000,000.")
        return redirect(url_for("home"))

    db.execute(
        "INSERT INTO budgets (user_id, category, monthly_limit) VALUES (?, ?, ?) "
        "ON CONFLICT (user_id, category) DO UPDATE SET monthly_limit = excluded.monthly_limit",
        (session["user_id"], category, limit),
    )
    db.commit()
    flash(f"Budget set: {category_label(category)}, {money(limit)} a month.")
    return redirect(url_for("home"))


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
        "SELECT id, access_token_encrypted, cursor FROM items "
        "WHERE user_id = ? AND plaid_item_id != ?",
        (user_id, DEMO_ITEM_ID),
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
@limiter.limit("10 per hour", methods=["POST"])
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
                    "INSERT INTO users (username, password_hash, session_token) VALUES (?, ?, ?)",
                    (username, password_hasher.hash(password), secrets.token_hex(32)),
                )
                db.commit()
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is taken.")

    return render_template("auth.html", title="Create account", other="login")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT id, password_hash, session_token FROM users WHERE username = ?", (username,)
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

        session_token = user["session_token"]
        if session_token is None:
            # Accounts created before session tokens existed get one now.
            session_token = secrets.token_hex(32)
            db.execute(
                "UPDATE users SET session_token = ? WHERE id = ?", (session_token, user["id"])
            )
            db.commit()

        # Start a fresh session so an attacker can't plant a session ID beforehand.
        session.clear()
        session["user_id"] = user["id"]
        session["session_token"] = session_token
        return redirect(url_for("home"))

    return render_template("auth.html", title="Log in", other="register")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


init_db()
if DEMO_PASSWORD:
    seed_demo_account(DEMO_PASSWORD)

if __name__ == "__main__":
    # Debug mode (auto-reload, error pages that can run code) only on your own computer.
    app.run(debug=not PRODUCTION, port=5001)
