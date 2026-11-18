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
        self.accounts = []

    def link_token_create(self, request):
        return {"link_token": "link-sandbox-fake"}

    def item_public_token_exchange(self, request):
        return {"access_token": "access-sandbox-fake-token", "item_id": "item-1"}

    def transactions_sync(self, request):
        added, self.pending = self.pending, []
        return {"added": added, "modified": [], "removed": [], "accounts": self.accounts,
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
        "INSERT INTO transactions (id, user_id, item_id, date, name, amount, category) "
        "VALUES (?, ?, 1, ?, ?, ?, ?)",
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
    assert b"Change budget" in page
    assert b"Everyday Checking" in page and b"Cash in your accounts" in page
    assert b"Gusto Payroll" in client.get("/transactions").data


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
    page = logged_in.get("/transactions").data
    assert b"Starbucks" in page and b"$4.33" in page

    logged_in.post("/plaid/sync", data={"csrf_token": token})
    assert db().execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == 1


def plaid_account(account_id, name, kind, balance):
    return {"account_id": account_id, "name": name, "type": kind, "balances": {"current": balance}}


def connect_bank(client):
    client.post("/plaid/exchange", json={"public_token": "public-fake"},
                headers={"X-CSRFToken": csrf_token(client, "/")})


def test_balances_shown_with_cash_total(logged_in, fake_plaid):
    fake_plaid.accounts = [plaid_account("a1", "Plaid Checking", "depository", 110.0),
                           plaid_account("a2", "Plaid Saving", "depository", 210.0),
                           plaid_account("a3", "Plaid Credit Card", "credit", 410.0)]
    connect_bank(logged_in)
    page = logged_in.get("/").data.decode()
    cash = re.search(r"Cash in your accounts</span>\s*<strong>([^<]+)", page).group(1)
    assert cash == "$320.00"  # Checking + savings. The card's balance is money owed.
    assert "$410.00 owed" in page


def test_refresh_updates_balance_without_duplicates(logged_in, fake_plaid):
    fake_plaid.accounts = [plaid_account("a1", "Plaid Checking", "depository", 110.0)]
    connect_bank(logged_in)
    fake_plaid.accounts = [plaid_account("a1", "Plaid Checking", "depository", 95.5)]
    logged_in.post("/plaid/sync", headers={"X-CSRFToken": csrf_token(logged_in, "/")})
    assert db().execute("SELECT balance FROM accounts").fetchall() == [(95.5,)]


def test_no_cash_card_without_a_bank(logged_in):
    assert b"Cash in your accounts" not in logged_in.get("/").data


def test_users_cannot_see_each_others_balances(logged_in, fake_plaid):
    fake_plaid.accounts = [plaid_account("a1", "Plaid Checking", "depository", 110.0)]
    connect_bank(logged_in)
    logged_in.post("/logout", data={"csrf_token": csrf_token(logged_in, "/")})
    register(logged_in, username="other")
    login(logged_in, username="other")
    assert b"Plaid Checking" not in logged_in.get("/").data


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


def set_budget(client, category, limit):
    return client.post("/budgets", data={
        "category": category, "limit": limit, "csrf_token": csrf_token(client, "/"),
    }, follow_redirects=True)


def move_transaction(client, transaction_id, category="", action=None, apply_all=False):
    data = {"category": category, "csrf_token": csrf_token(client, "/")}
    if action:
        data["action"] = action
    if apply_all:
        data["apply_all"] = "1"
    return client.post(f"/transactions/{transaction_id}/category", data=data,
                       follow_redirects=True)


def test_search_box_suggests_built_in_and_custom_categories(logged_in):
    set_budget(logged_in, "Coffee", "40")
    suggestions = logged_in.get("/").data.decode().split('<datalist id="category-options">')[1]
    assert '<option value="Travel">' in suggestions
    assert '<option value="Coffee">' in suggestions


def test_typed_built_in_name_uses_plaid_category(logged_in):
    add_transactions([("a", 2, "Starbucks", 150.00, "FOOD_AND_DRINK")])
    set_budget(logged_in, "food AND drink", "100")
    assert db().execute("SELECT category FROM budgets").fetchone()[0] == "FOOD_AND_DRINK"


def test_custom_category_keeps_first_spelling(logged_in):
    set_budget(logged_in, "Coffee", "40")
    set_budget(logged_in, "  coffee ", "50")
    assert db().execute("SELECT category, monthly_limit FROM budgets").fetchall() == [("Coffee", 50.0)]


@pytest.mark.parametrize("bad_name", ["", "   ", "x" * 31, "bad\x00name"])
def test_bad_category_names_rejected(logged_in, bad_name):
    response = set_budget(logged_in, bad_name, "50")
    assert b"Type a category name" in response.data
    assert db().execute("SELECT COUNT(*) FROM budgets").fetchone()[0] == 0


def test_income_cannot_have_a_budget(logged_in):
    response = set_budget(logged_in, "Income", "50")
    assert b"can&#39;t have a budget" in response.data


def test_custom_category_name_is_escaped(logged_in):
    set_budget(logged_in, "<script>x</script>", "10")
    page = logged_in.get("/").data
    assert b"<script>x</script>" not in page
    assert b"&lt;script&gt;" in page


def test_moved_purchase_counts_toward_custom_budget(logged_in):
    add_transactions([("a", 2, "Starbucks", 6.00, "FOOD_AND_DRINK"),
                      ("b", 3, "Chipotle", 12.00, "FOOD_AND_DRINK")])
    set_budget(logged_in, "Coffee", "40")
    assert "Starbucks: moved to Coffee" in move_transaction(logged_in, "a", "Coffee").data.decode()
    page = logged_in.get("/").data.decode()
    assert re.search(r"Coffee</span>\s*<span class=\"budget-amount\">\s*<b>\$6.00</b> of \$40.00", page)
    assert re.search(r"Food and drink</span>\s*<span class=\"budget-amount\">\s*<b>\$12.00</b>", page)


def test_undo_puts_purchase_back_in_bank_category(logged_in):
    add_transactions([("a", 2, "Starbucks", 6.00, "FOOD_AND_DRINK")])
    move_transaction(logged_in, "a", "Coffee")
    response = move_transaction(logged_in, "a", action="reset")
    assert b"changed back" in response.data
    assert db().execute("SELECT custom_category FROM transactions").fetchone()[0] is None


def test_pages_have_tabs_and_transactions_live_on_their_own_page(logged_in):
    add_transactions([("a", 2, "Starbucks", 6.00, "FOOD_AND_DRINK")])
    budget_page = logged_in.get("/").data
    transactions_page = logged_in.get("/transactions").data
    assert b">Transactions</a>" in budget_page and b"Starbucks" not in budget_page
    assert b"Starbucks" in transactions_page and b"Change category" in transactions_page


def all_custom_categories():
    return [row[0] for row in db().execute("SELECT custom_category FROM transactions ORDER BY id")]


def test_apply_all_moves_every_purchase_with_that_name(logged_in):
    add_transactions([("a", 2, "Starbucks", 6.00, "FOOD_AND_DRINK"),
                      ("b", 3, "Starbucks", 5.00, "FOOD_AND_DRINK"),
                      ("c", 4, "Chipotle", 12.00, "FOOD_AND_DRINK")])
    response = move_transaction(logged_in, "a", "Coffee", apply_all=True)
    assert b"2 Starbucks purchases: moved to Coffee" in response.data
    assert all_custom_categories() == ["Coffee", "Coffee", None]


def test_without_apply_all_only_one_purchase_moves(logged_in):
    add_transactions([("a", 2, "Starbucks", 6.00, "FOOD_AND_DRINK"),
                      ("b", 3, "Starbucks", 5.00, "FOOD_AND_DRINK")])
    move_transaction(logged_in, "a", "Coffee")
    assert all_custom_categories() == ["Coffee", None]
    assert db().execute("SELECT COUNT(*) FROM category_rules").fetchone()[0] == 0


def test_new_purchases_follow_the_rule(logged_in, fake_plaid):
    def starbucks(tid):
        return {"transaction_id": tid, "date": date.today(), "name": "Starbucks",
                "amount": 4.33, "personal_finance_category": {"primary": "FOOD_AND_DRINK"}}
    fake_plaid.pending = [starbucks("t1")]
    token = csrf_token(logged_in, "/")
    logged_in.post("/plaid/exchange", json={"public_token": "public-fake"},
                   headers={"X-CSRFToken": token})
    move_transaction(logged_in, "t1", "Coffee", apply_all=True)
    fake_plaid.pending = [starbucks("t2")]  # A new Starbucks purchase arrives.
    logged_in.post("/plaid/sync", headers={"X-CSRFToken": token})
    assert all_custom_categories() == ["Coffee", "Coffee"]


def test_undo_with_apply_all_removes_the_rule(logged_in):
    add_transactions([("a", 2, "Starbucks", 6.00, "FOOD_AND_DRINK"),
                      ("b", 3, "Starbucks", 5.00, "FOOD_AND_DRINK")])
    move_transaction(logged_in, "a", "Coffee", apply_all=True)
    move_transaction(logged_in, "a", action="reset", apply_all=True)
    assert all_custom_categories() == [None, None]
    assert db().execute("SELECT COUNT(*) FROM category_rules").fetchone()[0] == 0


def test_rules_only_affect_your_own_purchases(logged_in):
    add_transactions([("mine", 2, "Starbucks", 6.00, "FOOD_AND_DRINK")])
    add_transactions([("theirs", 3, "Starbucks", 5.00, "FOOD_AND_DRINK")], user_id=99)
    move_transaction(logged_in, "mine", "Coffee", apply_all=True)
    assert all_custom_categories() == ["Coffee", None]


def test_cannot_move_someone_elses_transaction(logged_in):
    add_transactions([("theirs", 2, "Starbucks", 6.00, "FOOD_AND_DRINK")], user_id=99)
    response = move_transaction(logged_in, "theirs", "Coffee")
    assert b"Transaction not found" in response.data
    assert db().execute("SELECT custom_category FROM transactions").fetchone()[0] is None


def test_refresh_keeps_moved_category(logged_in, fake_plaid):
    starbucks = {"transaction_id": "t1", "date": date.today(), "name": "Starbucks",
                 "amount": 4.33, "personal_finance_category": {"primary": "FOOD_AND_DRINK"}}
    fake_plaid.pending = [starbucks]
    token = csrf_token(logged_in, "/")
    logged_in.post("/plaid/exchange", json={"public_token": "public-fake"},
                   headers={"X-CSRFToken": token})
    move_transaction(logged_in, "t1", "Coffee")
    fake_plaid.pending = [{**starbucks, "amount": 5.00}]  # Plaid sends an update for it.
    logged_in.post("/plaid/sync", headers={"X-CSRFToken": token})
    assert db().execute("SELECT amount, custom_category FROM transactions").fetchone() == (5.0, "Coffee")


def test_users_cannot_see_each_others_data(logged_in):
    add_transactions([("a", 2, "Starbucks", 150.00, "FOOD_AND_DRINK")])
    logged_in.post("/logout", data={"csrf_token": csrf_token(logged_in, "/")})
    register(logged_in, username="other")
    login(logged_in, username="other")
    assert b"Starbucks" not in logged_in.get("/transactions").data


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
