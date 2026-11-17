import os
import re
import sqlite3
from datetime import date

import pytest
from cryptography.fernet import Fernet

# Fake keys, set before the app loads, so tests never use real secrets or reach Plaid.
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key")
os.environ.setdefault("FERNET_KEY", Fernet.generate_key().decode())
os.environ.setdefault("PLAID_CLIENT_ID", "test-client-id")
os.environ.setdefault("PLAID_SECRET", "test-secret")

import plaid  # noqa: E402

import app as app_module  # noqa: E402

PASSWORD = "correct-horse"


class FakePlaid:
    """Stands in for Plaid's API so tests run offline and predictably."""

    def __init__(self):
        self.pending = []

    def link_token_create(self, request):
        return {"link_token": "link-sandbox-fake"}

    def item_public_token_exchange(self, request):
        return {"access_token": "access-sandbox-fake-token", "item_id": "item-1"}

    def transactions_sync(self, request):
        added, self.pending = self.pending, []
        return {"added": added, "modified": [], "removed": [],
                "next_cursor": "cursor-1", "has_more": False}


@pytest.fixture
def fake_plaid(monkeypatch):
    fake = FakePlaid()
    monkeypatch.setattr(app_module, "plaid_client", fake)
    return fake


@pytest.fixture
def client(tmp_path, monkeypatch, fake_plaid):
    monkeypatch.setattr(app_module, "DATABASE", str(tmp_path / "test.db"))
    app_module.init_db()
    app_module.limiter.reset()
    return app_module.app.test_client()


def csrf_token(client, path="/login"):
    page = client.get(path).data.decode()
    return re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)


def register(client, username="tester", password=PASSWORD):
    return client.post("/register", data={
        "username": username, "password": password, "csrf_token": csrf_token(client, "/register"),
    }, follow_redirects=True)


def login(client, username="tester", password=PASSWORD):
    return client.post("/login", data={
        "username": username, "password": password, "csrf_token": csrf_token(client),
    }, follow_redirects=True)


@pytest.fixture
def logged_in(client):
    register(client)
    login(client)
    return client


def db():
    return sqlite3.connect(app_module.DATABASE)


def add_transactions(rows, user_id=1):
    """rows: (id, day_of_this_month, name, amount, category)."""
    month = date.today().replace(day=1)
    conn = db()
    conn.execute("INSERT INTO items (user_id, plaid_item_id, access_token_encrypted) "
                 "VALUES (?, 'item', x'00')", (user_id,))
    conn.executemany(
        "INSERT INTO transactions VALUES (?, ?, 1, ?, ?, ?, ?)",
        [(tid, user_id, month.replace(day=day).isoformat(), name, amount, category)
         for tid, day, name, amount, category in rows],
    )
    conn.commit()


# ---------- Login ----------

def test_home_requires_login(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.location


def test_register_and_login(client):
    assert b"Account created" in register(client).data
    assert b"Welcome, tester" in login(client).data


def test_password_stored_as_argon2_hash(client):
    register(client)
    stored = db().execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_wrong_password_and_unknown_user_get_same_message(client):
    register(client)
    wrong_password = login(client, password="wrong-password")
    unknown_user = login(client, username="nobody")
    assert b"Invalid username or password" in wrong_password.data
    assert b"Invalid username or password" in unknown_user.data


def test_duplicate_username_rejected(client):
    register(client)
    assert b"taken" in register(client, username="TESTER").data


def test_short_password_rejected(client):
    assert b"at least 8" in register(client, password="short").data


def test_logout(logged_in):
    logged_in.post("/logout", data={"csrf_token": csrf_token(logged_in, "/")})
    assert logged_in.get("/").status_code == 302


def reset_database():
    os.remove(app_module.DATABASE)
    app_module.init_db()


def test_old_login_cookie_after_database_reset_goes_to_login(logged_in):
    reset_database()
    response = logged_in.get("/")
    assert response.status_code == 302
    assert "/login" in response.location


def test_old_login_cookie_cannot_open_new_account_with_same_id(client):
    register(client, username="alice")
    login(client, username="alice")
    reset_database()
    bob = app_module.app.test_client()
    register(bob, username="bob")  # bob now has alice's old user ID
    login(bob, username="bob")

    response = client.get("/")  # alice's old cookie
    assert response.status_code == 302
    assert "/login" in response.location
    assert b"Welcome, bob" in bob.get("/").data


# ---------- Demo account ----------

DEMO_PASS = "demo-test-pass"


def test_demo_account_has_sample_data(client):
    app_module.seed_demo_account(DEMO_PASS)
    page = login(client, username="demo", password=DEMO_PASS).data
    assert b"Welcome, demo" in page
    assert b"Gusto Payroll" in page
    assert b"Change budget" in page


def test_demo_account_is_only_created_once(client):
    app_module.seed_demo_account(DEMO_PASS)
    app_module.seed_demo_account(DEMO_PASS)
    conn = db()
    assert conn.execute("SELECT COUNT(*) FROM users WHERE username = 'demo'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == len(app_module.DEMO_TRANSACTIONS)


def test_refresh_skips_demo_sample_data(client, fake_plaid, monkeypatch):
    def fail(request):
        raise AssertionError("should not ask Plaid about the sample data")

    monkeypatch.setattr(fake_plaid, "transactions_sync", fail)
    app_module.seed_demo_account(DEMO_PASS)
    login(client, username="demo", password=DEMO_PASS)
    response = client.post("/plaid/sync", data={"csrf_token": csrf_token(client, "/")},
                           follow_redirects=True)
    assert b"Could not refresh" not in response.data


def test_login_page_shows_demo_hint_only_when_enabled(client, monkeypatch):
    assert b"Just looking?" not in client.get("/login").data
    monkeypatch.setattr(app_module, "DEMO_PASSWORD", DEMO_PASS)
    page = client.get("/login").data
    assert b"Just looking?" in page and DEMO_PASS.encode() in page
    assert b"Just looking?" not in client.get("/register").data


def test_cannot_register_as_demo(client):
    app_module.seed_demo_account(DEMO_PASS)
    assert b"taken" in register(client, username="demo").data


# ---------- Plaid ----------

def test_plaid_routes_require_login(client):
    # Valid CSRF token, so it's the login check (not the CSRF check) that stops these.
    token = csrf_token(client)
    for path in ["/plaid/link_token", "/plaid/exchange", "/plaid/sync"]:
        response = client.post(path, headers={"X-CSRFToken": token})
        assert response.status_code == 302
        assert "/login" in response.location


def test_connect_bank_stores_access_token_encrypted(logged_in):
    response = logged_in.post("/plaid/exchange", json={"public_token": "public-fake"},
                              headers={"X-CSRFToken": csrf_token(logged_in, "/")})
    assert response.status_code == 200

    stored = db().execute("SELECT access_token_encrypted FROM items").fetchone()[0]
    assert b"access-sandbox-fake-token" not in stored
    assert app_module.fernet.decrypt(stored) == b"access-sandbox-fake-token"


def test_transactions_synced_and_shown(logged_in, fake_plaid):
    fake_plaid.pending = [{"transaction_id": "t1", "date": date.today(), "name": "Starbucks",
                           "amount": 4.33, "personal_finance_category": {"primary": "FOOD_AND_DRINK"}}]
    token = csrf_token(logged_in, "/")
    logged_in.post("/plaid/exchange", json={"public_token": "public-fake"},
                   headers={"X-CSRFToken": token})
    page = logged_in.get("/").data
    assert b"Starbucks" in page and b"$4.33" in page

    logged_in.post("/plaid/sync", data={"csrf_token": token})
    assert db().execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == 1


def test_plaid_error_shows_generic_message(logged_in, fake_plaid, monkeypatch):
    def fail(request):
        raise plaid.ApiException(status=400, reason="INVALID_API_KEYS")

    monkeypatch.setattr(fake_plaid, "link_token_create", fail)
    app_module.app.logger.disabled = True
    response = logged_in.post("/plaid/link_token", headers={"X-CSRFToken": csrf_token(logged_in, "/")})
    app_module.app.logger.disabled = False
    assert response.status_code == 502
    assert response.get_json() == {"error": "Could not start bank connection."}


# ---------- Budgets ----------

def test_spending_excludes_transfers_and_refunds(logged_in):
    add_transactions([
        ("a", 2, "Starbucks", 150.00, "FOOD_AND_DRINK"),
        ("b", 3, "Uber", 20.00, "TRANSPORTATION"),
        ("c", 4, "Airline refund", -500.00, "TRAVEL"),
        ("d", 4, "Card payment", 999.00, "LOAN_PAYMENTS"),
    ])
    page = logged_in.get("/").data.decode()
    spent = re.search(r"Spent this month</span>\s*<strong>([^<]+)", page).group(1)
    assert spent == "$170.00"
    assert "+$500.00" in page
    assert "$-" not in page


@pytest.mark.parametrize("limit, label", [("160", b"Close to limit"), ("100", b"Over budget")])
def test_budget_warnings(logged_in, limit, label):
    add_transactions([("a", 2, "Starbucks", 150.00, "FOOD_AND_DRINK")])
    response = logged_in.post("/budgets", data={
        "category": "FOOD_AND_DRINK", "limit": limit, "csrf_token": csrf_token(logged_in, "/"),
    }, follow_redirects=True)
    assert label in response.data


@pytest.mark.parametrize("bad_limit", ["abc", "-5", "nan", "inf", "99999999"])
def test_invalid_budget_limits_rejected(logged_in, bad_limit):
    response = logged_in.post("/budgets", data={
        "category": "TRAVEL", "limit": bad_limit, "csrf_token": csrf_token(logged_in, "/"),
    }, follow_redirects=True)
    assert b"must be a number" in response.data


def test_change_budget_box_is_prefilled_with_current_limit(logged_in):
    add_transactions([("a", 2, "Starbucks", 150.00, "FOOD_AND_DRINK")])
    response = logged_in.post("/budgets", data={
        "category": "FOOD_AND_DRINK", "limit": "250", "csrf_token": csrf_token(logged_in, "/"),
    }, follow_redirects=True)
    assert b"Change budget" in response.data
    assert b'value="250.00"' in response.data


@pytest.mark.parametrize("limit, expected", [
    ("200", b"$50.00</strong>\n        <small>left of $200.00 budgeted"),
    ("100", b"$50.00 over</strong>"),
])
def test_budget_left_summary(logged_in, limit, expected):
    add_transactions([("a", 2, "Starbucks", 150.00, "FOOD_AND_DRINK")])
    response = logged_in.post("/budgets", data={
        "category": "FOOD_AND_DRINK", "limit": limit, "csrf_token": csrf_token(logged_in, "/"),
    }, follow_redirects=True)
    assert expected in response.data


def test_remove_button_deletes_budget(logged_in):
    token = csrf_token(logged_in, "/")
    logged_in.post("/budgets", data={"category": "TRAVEL", "limit": "300", "csrf_token": token})
    response = logged_in.post("/budgets", data={
        "category": "TRAVEL", "limit": "300", "action": "remove", "csrf_token": token,
    }, follow_redirects=True)
    assert b"Budget removed for Travel" in response.data
    assert db().execute("SELECT COUNT(*) FROM budgets").fetchone()[0] == 0


def test_add_budget_list_skips_categories_already_shown(logged_in):
    add_transactions([("a", 2, "Starbucks", 150.00, "FOOD_AND_DRINK")])
    page = logged_in.get("/").data.decode()
    add_form = page.split("Add a budget for another category")[1]
    assert 'value="FOOD_AND_DRINK"' not in add_form
    assert 'value="TRAVEL"' in add_form


def test_made_up_budget_category_rejected(logged_in):
    response = logged_in.post("/budgets", data={
        "category": "HACKED", "limit": "50", "csrf_token": csrf_token(logged_in, "/"),
    }, follow_redirects=True)
    assert b"Pick a category" in response.data


def test_users_cannot_see_each_others_data(logged_in):
    add_transactions([("a", 2, "Starbucks", 150.00, "FOOD_AND_DRINK")])
    logged_in.post("/logout", data={"csrf_token": csrf_token(logged_in, "/")})
    register(logged_in, username="other")
    login(logged_in, username="other")
    assert b"Starbucks" not in logged_in.get("/").data


# ---------- Security hardening ----------

def test_forms_require_csrf_token(client):
    response = client.post("/register", data={"username": "tester", "password": PASSWORD},
                           follow_redirects=True)
    assert b"Security check failed" in response.data
    assert db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_forged_csrf_token_rejected(client):
    response = client.post("/register", data={
        "username": "tester", "password": PASSWORD, "csrf_token": "forged",
    }, follow_redirects=True)
    assert b"Security check failed" in response.data


def test_plaid_requests_require_csrf_header(logged_in):
    response = logged_in.post("/plaid/link_token")
    assert response.status_code == 400


def test_security_headers(client):
    headers = client.get("/login").headers
    csp = headers["Content-Security-Policy"]
    script_rules = csp.split("script-src")[1].split(";")[0]
    assert "'unsafe-inline'" not in script_rules
    assert "frame-ancestors 'none'" in csp
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Cache-Control"] == "no-store"


def test_session_cookie_is_httponly(client):
    register(client)
    response = client.post("/login", data={
        "username": "tester", "password": PASSWORD, "csrf_token": csrf_token(client),
    })
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_login_rate_limited(client):
    statuses = [login(client, username="nobody").status_code for _ in range(6)]
    assert statuses == [200] * 5 + [429]
