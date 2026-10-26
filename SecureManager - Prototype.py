#!/usr/bin/env python3
"""
SecureManager: the whole app in ONE file.

    python securemanager.py            start the app (first time: sets itself up and asks for your first account)

What is in this file, top to bottom:
    1. Settings
    2. Database and security helpers
    3. Web pages and the data API (the server)
    4. Admin commands (add people, read feedback, back up)
    5. Built-in self-test
    6. Embedded files: the app screen (HTML/CSS/JavaScript), sign-in page, service worker,
       manifest and icons. They live at the bottom so the code above stays readable.
    7. The launcher

Admin commands (run in the same folder):
    python securemanager.py add-user jimmy@example.com        add a person (asks for a password)
    python securemanager.py set-password jimmy@example.com    change a password
    python securemanager.py remove-user staff1@example.com    remove a person (signed out at once)
    python securemanager.py list-users
    python securemanager.py feedback [--limit 50]             read what people sent with "Send feedback"
    python securemanager.py export data.json                  save all app data as readable JSON
    python securemanager.py backup backup.db                  copy the whole database safely
    python securemanager.py selftest                          check that everything works
    python securemanager.py run --port 8000 --host 0.0.0.0    start with options

Needs Python 3.9+. Flask is installed automatically the first time if it is missing.
Settings (environment variables): SM_DATA_DIR, SM_SECRET_KEY, SM_HTTPS, SM_TRUST_PROXY,
SM_DEFAULT_LANG, SM_HOST, PORT. The data (database, secret key) is kept in a "data" folder
next to this file unless SM_DATA_DIR says otherwise.
"""

import argparse
import base64
import getpass
import hmac
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path


# ====================================================================
# 0. Install Flask automatically if it is missing (only when run directly)
# ====================================================================

def _ensure_dependencies():
    """If Flask is missing, installs it (and waitress, a better server) for THIS Python. Otherwise does nothing."""
    if sys.version_info < (3, 9):
        sys.exit(f"You have Python {sys.version.split()[0]}, but SecureManager needs 3.9 or newer.\n"
                 "Install the latest Python from https://www.python.org/downloads/ "
                 "(tick 'Add Python to PATH') and try again.")
    try:
        import flask  # noqa: F401
        return                                              # waitress is optional; never reinstall for it
    except ImportError:
        pass
    if os.environ.get("SM_BOOTSTRAPPED") == "1":            # we already tried once; don't loop
        sys.exit("Flask could not be installed. Try:  " + sys.executable + " -m pip install flask waitress")

    print("Setting up (first time only): installing Flask. This needs internet and takes a minute...")
    base = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check"]
    if subprocess.call(base + ["flask", "waitress"]) != 0 and \
            subprocess.call(base + ["--user", "flask", "waitress"]) != 0:
        sys.exit("\nInstalling Flask failed. Check your internet connection and run this again.\n"
                 "Or install it yourself with:  " + sys.executable + " -m pip install flask waitress")
    # Start again so the new packages are picked up cleanly.
    sys.exit(subprocess.call([sys.executable] + sys.argv, env={**os.environ, "SM_BOOTSTRAPPED": "1"}))


if __name__ == "__main__":
    _ensure_dependencies()

from flask import (Flask, Response, abort, g, jsonify, make_response, redirect,  # noqa: E402
                   render_template_string, request, session)
from werkzeug.security import check_password_hash, generate_password_hash        # noqa: E402


# ====================================================================
# 1. Settings
# ====================================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("SM_DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "securemanager.db"

# The only data keys the app may store (the app screen uses exactly these).
LIST_KEYS = {"cn_priorities", "cn_staff", "cn_campaigns", "cn_ideas",
             "cn_security", "cn_incidents", "cn_menu", "cn_reviews"}
OBJECT_KEYS = {"cn_sop_checks", "cn_dash_finance", "cn_settings"}
ALLOWED_KEYS = LIST_KEYS | OBJECT_KEYS

MAX_VALUE_BYTES = 1_000_000
MAX_LOGIN_FAILS = 5          # failed sign-ins allowed ...
LOGIN_WINDOW_SECONDS = 600   # ... within this many seconds, per email and per address

# Languages. The app screen switches language in the browser; the sign-in page is translated here.
LANGS = ("en", "vi")
DEFAULT_LANG = os.environ.get("SM_DEFAULT_LANG", "en")
if DEFAULT_LANG not in LANGS:
    DEFAULT_LANG = "en"

LOGIN_TEXT = {
    "en": {
        "page_title": "Sign in — SecureManager",
        "intro": "Sign in with the email and password your manager set up for you.",
        "email": "Email", "password": "Password", "button": "Sign in",
        "forgot": "Forgot your password? Ask the manager to reset it.",
        "language": "Language",
        "err_expired": "Your page expired. Please try again.",
        "err_throttled": "Too many attempts. Please wait a few minutes and try again.",
        "err_bad": "That email or password isn't right.",
    },
    "vi": {
        "page_title": "Đăng nhập — SecureManager",
        "intro": "Đăng nhập bằng email và mật khẩu mà quản lý đã tạo cho bạn.",
        "email": "Email", "password": "Mật khẩu", "button": "Đăng nhập",
        "forgot": "Quên mật khẩu? Hãy nhờ quản lý đặt lại.",
        "language": "Ngôn ngữ",
        "err_expired": "Trang đã hết hạn. Vui lòng thử lại.",
        "err_throttled": "Thử quá nhiều lần. Vui lòng chờ vài phút rồi thử lại.",
        "err_bad": "Email hoặc mật khẩu không đúng.",
    },
}


# ====================================================================
# 2. Database and security helpers
# ====================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS appdata (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    rev        INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
INSERT OR IGNORE INTO meta (name, value) VALUES ('rev', 0);
CREATE TABLE IF NOT EXISTS feedback (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    user_email TEXT NOT NULL,
    rating     INTEGER,
    page       TEXT,
    version    TEXT,
    message    TEXT NOT NULL
);
"""


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def load_secret_key():
    """Session-signing key: from SM_SECRET_KEY, or generated once and kept in the data folder."""
    env_key = os.environ.get("SM_SECRET_KEY")
    if env_key:
        return env_key
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    key_file = DATA_DIR / "secret_key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
        try:
            key_file.chmod(0o600)
        except OSError:
            pass
    return key_file.read_text().strip()


app = Flask(__name__, static_folder=None)      # all files are embedded below; nothing is read from disk
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SM_HTTPS") == "1",   # set SM_HTTPS=1 when served over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    MAX_CONTENT_LENGTH=2_000_000,
)
if os.environ.get("SM_TRUST_PROXY") == "1":
    # Behind a reverse proxy (nginx, a hosting platform): trust its forwarded headers.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

init_db()
# Used so a wrong email takes about as long to reject as a wrong password.
DUMMY_HASH = generate_password_hash("not-a-real-password")


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)  # autocommit; we use BEGIN explicitly
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


_fails = {}   # (kind, value) -> [timestamps of recent failed sign-ins]


def _recent_fails(key):
    now = time.time()
    recent = [t for t in _fails.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    _fails[key] = recent
    return recent


def login_throttled(keys):
    return any(len(_recent_fails(k)) >= MAX_LOGIN_FAILS for k in keys)


def record_login_failure(keys):
    for k in keys:
        _recent_fails(k).append(time.time())


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def safe_next(target):
    """Only allow redirects to a path on this site (never to another website)."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/"


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    # Looked up on every request, so removing a user locks them out immediately.
    return get_db().execute("SELECT id, email FROM users WHERE id = ?", (uid,)).fetchone()


def page_login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return redirect("/login?next=" + request.path)
        return view(*args, **kwargs)
    return wrapper


def api_login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return jsonify(error="signed_out"), 401
        g.user = user
        return view(*args, **kwargs)
    return wrapper


@app.before_request
def require_custom_header_for_api_writes():
    # A web page on another site cannot add this header without our permission,
    # which blocks cross-site request forgery against the JSON API.
    if (request.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS")
            and request.headers.get("X-SM") != "1"):
        abort(403)


@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if request.path.startswith("/api/") or request.path == "/login":
        resp.headers["Cache-Control"] = "no-store"
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


def resolve_lang():
    """?lang=vi wins, then the saved choice, then the server default."""
    asked = request.values.get("lang")
    if asked in LANGS:
        return asked
    saved = request.cookies.get("sm_lang")
    return saved if saved in LANGS else DEFAULT_LANG


def with_lang_cookie(resp, lang):
    # Readable by the app screen, which uses the same choice. Not a secret.
    if request.cookies.get("sm_lang") != lang:
        resp.set_cookie("sm_lang", lang, max_age=31536000, samesite="Lax",
                        secure=app.config["SESSION_COOKIE_SECURE"], httponly=False)
    return resp


# ====================================================================
# 3. Web pages and the data API
# ====================================================================

@app.get("/healthz")
def healthz():
    return "ok"


@app.get("/")
@page_login_required
def index():
    resp = Response(APP_HTML, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-cache"
    return with_lang_cookie(resp, resolve_lang())


@app.get("/sw.js")
def service_worker():
    # Served from the site root so it can control the whole app.
    resp = Response(SERVICE_WORKER_JS, mimetype="application/javascript")
    resp.headers["Service-Worker-Allowed"] = "/"
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.get("/static/manifest.json")
def web_manifest():
    return Response(json.dumps(MANIFEST, ensure_ascii=False), mimetype="application/manifest+json")


@app.get("/static/icons/<name>")
def icon(name):
    data = ICON_FILES.get(name)
    if data is None:
        abort(404)
    resp = Response(data, mimetype="image/png")
    resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    lang = resolve_lang()
    tx = LOGIN_TEXT[lang]
    error = None
    next_url = safe_next(request.values.get("next"))
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        expected = session.get("csrf", "")
        if not expected or not hmac.compare_digest(sent.encode("utf-8"), expected.encode("utf-8")):
            error = tx["err_expired"]
        else:
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            throttle_keys = [("ip", request.remote_addr), ("email", email)]
            if login_throttled(throttle_keys):
                error = tx["err_throttled"]
            else:
                row = get_db().execute(
                    "SELECT id, password_hash FROM users WHERE email = ?", (email,)).fetchone()
                password_ok = check_password_hash(row["password_hash"] if row else DUMMY_HASH, password)
                if row is not None and password_ok:
                    session.clear()
                    session["uid"] = row["id"]
                    session.permanent = True
                    _fails.pop(("email", email), None)
                    return with_lang_cookie(redirect(next_url), lang)
                record_login_failure(throttle_keys)
                error = tx["err_bad"]
    resp = make_response(render_template_string(LOGIN_HTML, csrf=csrf_token(), error=error,
                                                next_url=next_url, tx=tx, lang=lang))
    return with_lang_cookie(resp, lang)


@app.get("/api/me")
@api_login_required
def api_me():
    return jsonify(email=g.user["email"])


@app.get("/api/changes")
@api_login_required
def api_changes():
    """Everything that changed after revision `since`, plus the newest revision."""
    since = request.args.get("since", default=0, type=int) or 0
    rows = get_db().execute(
        "SELECT key, value, rev FROM appdata WHERE rev > ? ORDER BY rev", (since,)).fetchall()
    newest = rows[-1]["rev"] if rows else since
    return jsonify(rev=newest, items=[{"key": r["key"], "value": r["value"], "rev": r["rev"]} for r in rows])


@app.put("/api/data/<key>")
@api_login_required
def api_put(key):
    if key not in ALLOWED_KEYS:
        abort(404)
    body = request.get_json(silent=True) or {}
    value = body.get("value")
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_VALUE_BYTES:
        return jsonify(error="bad_value"), 400
    try:
        parsed = json.loads(value)
    except ValueError:
        return jsonify(error="bad_json"), 400
    if isinstance(parsed, list) != (key in LIST_KEYS):
        return jsonify(error="wrong_shape"), 400

    db = get_db()
    db.execute("BEGIN IMMEDIATE")          # one writer at a time, so revisions are committed in order
    try:
        db.execute("UPDATE meta SET value = value + 1 WHERE name = 'rev'")
        rev = db.execute("SELECT value FROM meta WHERE name = 'rev'").fetchone()["value"]
        db.execute(
            "INSERT INTO appdata (key, value, rev, updated_at, updated_by) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, rev = excluded.rev, "
            "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
            (key, value, rev, utc_now(), g.user["email"]))
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return jsonify(rev=rev)


@app.post("/api/feedback")
@api_login_required
def api_feedback():
    body = request.get_json(silent=True) or {}
    message = str(body.get("message") or "").strip()[:2000]
    rating = body.get("rating")
    rating = rating if isinstance(rating, int) and 1 <= rating <= 5 else None
    if not message and rating is None:
        return jsonify(error="empty"), 400
    get_db().execute(
        "INSERT INTO feedback (created_at, user_email, rating, page, version, message) VALUES (?, ?, ?, ?, ?, ?)",
        (utc_now(), g.user["email"], rating,
         str(body.get("page") or "")[:40], str(body.get("version") or "")[:20], message))
    return jsonify(ok=True)


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify(ok=True)


# ====================================================================
# 4. Admin commands
# ====================================================================

def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def read_new_password(supplied):
    if supplied:
        password = supplied
    else:
        password = getpass.getpass("Password (at least 8 characters): ")
        if password != getpass.getpass("Repeat password: "):
            sys.exit("Passwords didn't match. Nothing was changed.")
    if len(password) < 8:
        sys.exit("Password must be at least 8 characters. Nothing was changed.")
    return password


def clean_email(raw):
    email = raw.strip().lower()
    if "@" not in email or " " in email:
        sys.exit(f"'{raw}' doesn't look like an email address.")
    return email


def cmd_add_user(args):
    email = clean_email(args.email)
    password = read_new_password(args.password)
    with connect() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            sys.exit(f"{email} already exists. Use set-password to change their password.")
        conn.execute("INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                     (email, generate_password_hash(password), utc_now()))
    print(f"Added {email}.")


def cmd_set_password(args):
    email = clean_email(args.email)
    password = read_new_password(args.password)
    with connect() as conn:
        cur = conn.execute("UPDATE users SET password_hash = ? WHERE email = ?",
                           (generate_password_hash(password), email))
        if cur.rowcount == 0:
            sys.exit(f"No user {email}.")
    print(f"Password changed for {email}. (They stay signed in on devices that are already signed in;"
          " remove and re-add the user if you need to force a sign-out.)")


def cmd_remove_user(args):
    email = clean_email(args.email)
    with connect() as conn:
        cur = conn.execute("DELETE FROM users WHERE email = ?", (email,))
        if cur.rowcount == 0:
            sys.exit(f"No user {email}.")
    print(f"Removed {email}. They are signed out immediately.")


def cmd_list_users(_args):
    with connect() as conn:
        rows = conn.execute("SELECT email, created_at FROM users ORDER BY email").fetchall()
    if not rows:
        print("No users yet. Add one with: python securemanager.py add-user you@example.com")
    for r in rows:
        print(f"{r['email']}   (added {r['created_at']})")


def cmd_feedback(args):
    with connect() as conn:
        rows = conn.execute(
            "SELECT created_at, user_email, rating, page, version, message FROM feedback "
            "ORDER BY id DESC LIMIT ?", (args.limit,)).fetchall()
    if not rows:
        print("No feedback yet.")
    for r in rows:
        rating = f"{r['rating']}/5" if r["rating"] else "no rating"
        print(f"[{r['created_at']}] {r['user_email']} · {rating} · page: {r['page'] or '-'} · v{r['version'] or '?'}")
        print(f"    {r['message'] or '(no message)'}\n")


def cmd_export(args):
    with connect() as conn:
        rows = conn.execute("SELECT key, value, updated_at, updated_by FROM appdata ORDER BY key").fetchall()
    out = {r["key"]: {"data": json.loads(r["value"]), "updated_at": r["updated_at"],
                      "updated_by": r["updated_by"]} for r in rows}
    with open(args.file, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"Saved {len(out)} data sets to {args.file}")


def cmd_backup(args):
    src = connect()
    dest = sqlite3.connect(args.file)
    with dest:
        src.backup(dest)
    dest.close()
    src.close()
    print(f"Database copied to {args.file}")


def ensure_first_user():
    """True if at least one account exists (offers to create the first one when run by hand)."""
    with connect() as conn:
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return True
    if not sys.stdin.isatty():
        print("There are no accounts yet. Create one with:  python securemanager.py add-user you@example.com")
        return False
    print("\nThere are no accounts yet. Let's create the first one (you'll use it to sign in).")
    try:
        while True:
            email = input("Email address: ").strip()
            try:
                cmd_add_user(argparse.Namespace(email=email, password=None))
                return True
            except SystemExit as err:                      # bad email, short password, ...
                print(err.code if isinstance(err.code, str) else "Let's try that again.")
    except (EOFError, KeyboardInterrupt):
        print("\nNo account was created. Run this again when you're ready.")
        return False


def cmd_run(args):
    if not ensure_first_user():
        sys.exit(1)
    host = args.host or os.environ.get("SM_HOST", "127.0.0.1")
    port = int(args.port or os.environ.get("PORT", "5000"))
    local = host in ("127.0.0.1", "localhost")
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}"
    print(f"\nSecureManager is running at {url}")
    print("Leave this window open while you use it. Press Ctrl+C here to stop.\n")
    if local and not args.no_browser:
        threading.Timer(2.0, lambda: webbrowser.open(url)).start()
    try:
        from waitress import serve
    except ImportError:
        app.run(host=host, port=port, debug=False)
    else:
        try:
            serve(app, host=host, port=port, threads=8)
        except KeyboardInterrupt:
            pass


# ====================================================================
# 5. Built-in self-test:  python securemanager.py selftest
# ====================================================================

def cmd_selftest(_args):
    """Runs the checks against a throw-away database (your real data is never touched)."""
    import tempfile
    env = {**os.environ, "SM_DATA_DIR": tempfile.mkdtemp(prefix="sm-selftest-")}
    env.pop("SM_SECRET_KEY", None)
    sys.exit(subprocess.call([sys.executable, str(Path(__file__).resolve()), "_selftest"], env=env))


def _run_selftest():
    import re
    import unittest

    me = sys.modules[__name__]
    H = {"X-SM": "1"}

    def add_user(email, password):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT OR REPLACE INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                     (email, generate_password_hash(password), utc_now()))
        conn.commit()
        conn.close()

    def sign_in(client, email="jimmy@example.com", password="correct-horse"):
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        return client.post("/login", data={"csrf": token, "email": email, "password": password})

    class SelfTest(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            add_user("jimmy@example.com", "correct-horse")
            add_user("staff@example.com", "battery-staple")

        def setUp(self):
            me._fails.clear()
            self.client = app.test_client()

        def test_signed_out_visitor_is_sent_to_sign_in(self):
            r = self.client.get("/")
            self.assertEqual(r.status_code, 302)
            self.assertTrue(r.headers["Location"].startswith("/login"))
            self.assertEqual(self.client.get("/api/changes").status_code, 401)

        def test_sign_in_serves_the_app_with_sign_out_and_no_greeting(self):
            r = sign_in(self.client)
            self.assertEqual((r.status_code, r.headers["Location"]), (302, "/"))
            page = self.client.get("/").get_data(as_text=True)
            self.assertIn("SecureManager", page)
            self.assertIn("data-signout", page)
            self.assertNotIn("Chào Jimmy", page)
            self.assertEqual(self.client.get("/api/me").get_json()["email"], "jimmy@example.com")

        def test_wrong_password_and_unknown_user_look_the_same(self):
            a = sign_in(self.client, password="nope").get_data(as_text=True)
            b = sign_in(self.client, email="nobody@example.com", password="nope").get_data(as_text=True)
            self.assertIn("email or password", a)
            self.assertIn("email or password", b)
            self.assertEqual(self.client.get("/api/me").status_code, 401)

        def test_sign_in_needs_the_csrf_token(self):
            self.client.post("/login", data={"email": "jimmy@example.com", "password": "correct-horse"})
            self.assertEqual(self.client.get("/api/me").status_code, 401)
            self.client.post("/login", data={"csrf": "", "email": "jimmy@example.com", "password": "correct-horse"})
            self.assertEqual(self.client.get("/api/me").status_code, 401)

        def test_lockout_after_repeated_failures(self):
            for _ in range(MAX_LOGIN_FAILS):
                sign_in(self.client, password="wrong")
            self.assertIn("Too many attempts", sign_in(self.client).get_data(as_text=True))

        def test_redirects_cannot_leave_the_site(self):
            for bad in ("//evil.example", "https://evil.example", "/\\evil"):
                self.assertEqual(safe_next(bad), "/")
            self.assertEqual(safe_next("/api/me"), "/api/me")

        def test_removed_user_is_locked_out_immediately(self):
            add_user("temp@example.com", "temporary-pass")
            sign_in(self.client, email="temp@example.com", password="temporary-pass")
            self.assertEqual(self.client.get("/api/me").status_code, 200)
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM users WHERE email = 'temp@example.com'")
            conn.commit()
            conn.close()
            self.assertEqual(self.client.get("/api/me").status_code, 401)

        def test_sign_out(self):
            sign_in(self.client)
            self.assertEqual(self.client.post("/api/logout", headers=H).status_code, 200)
            self.assertEqual(self.client.get("/api/me").status_code, 401)

        def test_writes_without_the_custom_header_are_rejected(self):
            sign_in(self.client)
            self.assertEqual(self.client.put("/api/data/cn_staff", json={"value": "[]"}).status_code, 403)

        def test_data_is_shared_between_two_devices(self):
            a, b = app.test_client(), app.test_client()
            sign_in(a)
            sign_in(b, email="staff@example.com", password="battery-staple")
            before = b.get("/api/changes?since=0").get_json()["rev"]
            staff = json.dumps([{"name": "Mai", "role": "Cook", "stage": "New", "sopFlag": True}])
            self.assertEqual(a.put("/api/data/cn_staff", json={"value": staff}, headers=H).status_code, 200)
            changes = b.get(f"/api/changes?since={before}").get_json()
            self.assertEqual([i["key"] for i in changes["items"]], ["cn_staff"])
            self.assertEqual(json.loads(changes["items"][0]["value"])[0]["name"], "Mai")
            again = b.get(f"/api/changes?since={changes['rev']}").get_json()
            self.assertEqual(again["items"], [])

        def test_menu_reviews_and_links_can_be_saved(self):
            sign_in(self.client)
            put = lambda key, value: self.client.put(f"/api/data/{key}", json={"value": value}, headers=H)
            menu = json.dumps([{"id": "m1", "name": "Phở bò", "category": "Noodles", "price": 16.5,
                                "description": "", "available": True}])
            self.assertEqual(put("cn_menu", menu).status_code, 200)
            self.assertEqual(put("cn_reviews", json.dumps([{"id": "r1", "rating": 5}])).status_code, 200)
            self.assertEqual(put("cn_settings", json.dumps({"websiteUrl": "https://example.com"})).status_code, 200)
            self.assertEqual(put("cn_menu", "{}").status_code, 400)
            self.assertEqual(put("cn_settings", "[]").status_code, 400)
            self.assertEqual(put("not_a_real_key", "[]").status_code, 404)
            self.assertEqual(put("cn_staff", "{not json").status_code, 400)
            items = {i["key"]: i["value"] for i in self.client.get("/api/changes?since=0").get_json()["items"]}
            self.assertEqual(json.loads(items["cn_menu"])[0]["name"], "Phở bò")

        def test_feedback_is_stored(self):
            sign_in(self.client)
            r = self.client.post("/api/feedback", headers=H,
                                 json={"message": "Finance page is confusing", "rating": 3, "page": "finance", "version": "2.1.0"})
            self.assertEqual(r.status_code, 200)
            conn = sqlite3.connect(DB_PATH)
            row = conn.execute("SELECT user_email, rating, page, message FROM feedback ORDER BY id DESC LIMIT 1").fetchone()
            conn.close()
            self.assertEqual(row, ("jimmy@example.com", 3, "finance", "Finance page is confusing"))
            self.assertEqual(self.client.post("/api/feedback", headers=H, json={}).status_code, 400)

        def test_sign_in_page_in_english_and_vietnamese(self):
            self.assertIn("Sign in", self.client.get("/login").get_data(as_text=True))
            vi = self.client.get("/login?lang=vi")
            self.assertIn("Đăng nhập", vi.get_data(as_text=True))
            self.assertIn("sm_lang=vi", vi.headers.get("Set-Cookie", ""))
            self.assertIn("Mật khẩu", self.client.get("/login").get_data(as_text=True))     # remembered
            page = self.client.get("/login").get_data(as_text=True)
            token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
            r = self.client.post("/login", data={"csrf": token, "email": "jimmy@example.com", "password": "x"})
            self.assertIn("Email hoặc mật khẩu không đúng", r.get_data(as_text=True))
            self.assertIn("Sign in", app.test_client().get("/login?lang=xx").get_data(as_text=True))

        def test_embedded_files_are_served(self):
            sw = self.client.get("/sw.js")
            self.assertEqual((sw.status_code, sw.headers["Service-Worker-Allowed"]), (200, "/"))
            self.assertEqual(self.client.get("/static/manifest.json").get_json()["short_name"], "SecureManager")
            icon_resp = self.client.get("/static/icons/icon-512.png")
            self.assertEqual((icon_resp.status_code, icon_resp.mimetype), (200, "image/png"))
            self.assertTrue(icon_resp.data.startswith(b"\x89PNG"))
            self.assertEqual(self.client.get("/static/icons/nope.png").status_code, 404)
            self.assertEqual(self.client.get("/healthz").get_data(as_text=True), "ok")

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SelfTest)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    print("\nAll checks passed." if result.wasSuccessful() else "\nSome checks FAILED.")
    sys.exit(0 if result.wasSuccessful() else 1)


# ====================================================================
# 6. Embedded files (the app screen, sign-in page, service worker, manifest, icons)
#    Edit the app screen right here: search for APP_VERSION to change the version number,
#    and for CACHE_NAME in SERVICE_WORKER_JS when you release an update.
# ====================================================================

# ---- The app screen: everything people see after signing in (HTML, CSS and JavaScript) ----
APP_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>SecureManager — Cơm Nhà</title>
<link rel="manifest" href="/static/manifest.json">
<meta name="theme-color" content="#16231C">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="SecureManager">
<link rel="apple-touch-icon" href="/static/icons/apple-touch-icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,600;9..144,700&family=Work+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-deep: #16231C;
    --bg-panel: #1C2B22;
    --bg-panel-2: #223326;
    --paper: #F4ECD8;
    --paper-dim: #E9DEC2;
    --paper-line: #D8C9A3;
    --brass: #C99A3E;
    --brass-dim: #A87F2E;
    --chili: #B23A2E;
    --herb: #5C8F6E;
    --ink: #2B2018;
    --ink-soft: #6B5D48;
    --cream: #EFE6D2;
    --cream-dim: #B9AF97;
  }

  :root:not([data-theme="light"]) {
    color-scheme: dark;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) { color-scheme: dark; }
  }

  * { box-sizing: border-box; }

  html {
    scroll-padding-top: env(safe-area-inset-top, 0px);
  }

  body {
    margin: 0;
    background: var(--bg-deep);
    color: var(--cream);
    font-family: "Work Sans", -apple-system, BlinkMacSystemFont, sans-serif;
    padding-top: env(safe-area-inset-top, 0px);
    padding-bottom: env(safe-area-inset-bottom, 0px);
    min-height: 100%;
  }

  h1, h2, h3, .display {
    font-family: "Fraunces", Georgia, "Times New Roman", serif;
    font-weight: 600;
    letter-spacing: -0.01em;
  }

  button, input, select, textarea {
    font-family: inherit;
  }

  /* ---------- App shell ---------- */

  .app {
    display: grid;
    grid-template-columns: 220px 1fr;
    min-height: 100vh;
  }

  .rail {
    background: var(--bg-panel);
    border-right: 1px solid rgba(201, 154, 62, 0.18);
    padding: 28px 0 24px;
    display: flex;
    flex-direction: column;
  }

  .rail-brand {
    padding: 0 22px 22px;
    border-bottom: 1px dashed rgba(201, 154, 62, 0.3);
    margin-bottom: 14px;
  }

  .rail-brand .mark {
    font-family: "Fraunces", serif;
    font-size: 19px;
    font-weight: 700;
    color: var(--brass);
    line-height: 1.2;
  }

  .rail-brand .sub {
    font-size: 12px;
    color: var(--cream-dim);
    margin-top: 4px;
    letter-spacing: 0.02em;
  }

  .rail-nav {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 0 12px;
  }

  .rail-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 11px 12px;
    border-radius: 3px;
    background: transparent;
    border: none;
    border-left: 3px solid transparent;
    color: var(--cream-dim);
    font-size: 14px;
    font-weight: 500;
    text-align: left;
    cursor: pointer;
    position: relative;
  }

  .rail-item:not(:last-child)::after {
    content: "";
    position: absolute;
    left: 12px;
    right: 12px;
    bottom: -1px;
    border-bottom: 1px dotted rgba(239, 230, 210, 0.08);
  }

  .rail-item .ico { font-size: 16px; width: 18px; text-align: center; }

  .rail-item:hover { color: var(--cream); background: rgba(201, 154, 62, 0.08); }

  .rail-item.active {
    color: var(--paper);
    background: var(--bg-panel-2);
    border-left-color: var(--brass);
    font-weight: 600;
  }

  .rail-foot {
    margin-top: auto;
    padding: 16px 22px 0;
    font-size: 11px;
    color: var(--cream-dim);
    border-top: 1px dashed rgba(201, 154, 62, 0.25);
  }

  /* Mobile rail becomes a top scroll strip */
  .rail-toggle { display: none; }

  main {
    padding: 34px 40px 60px;
    max-width: 980px;
  }

  .topbar {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 26px;
    flex-wrap: wrap;
    gap: 8px;
  }

  .topbar h1 { font-size: 26px; margin: 0; color: var(--paper); }
  .topbar .date { font-size: 13px; color: var(--cream-dim); }

  section.view { display: none; }
  section.view.active { display: block; }

  .lede {
    color: var(--cream-dim);
    font-size: 14px;
    max-width: 62ch;
    line-height: 1.6;
    margin: -8px 0 26px;
  }

  /* ---------- Ticket / paper card system ---------- */

  .ticket {
    background: var(--paper);
    color: var(--ink);
    border-radius: 3px;
    box-shadow: 0 1px 0 rgba(0,0,0,0.25), 0 6px 18px rgba(0,0,0,0.22);
    position: relative;
  }

  .ticket::before {
    content: "";
    position: absolute;
    top: 0; bottom: 0; left: 0;
    width: 5px;
    background: var(--brass);
    border-radius: 3px 0 0 3px;
  }

  .ticket-pad { padding: 18px 20px 18px 24px; }

  .grid-3 {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
  }
  .grid-2 {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 16px;
  }

  .stat-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--ink-soft);
    margin: 0 0 6px;
  }
  .stat-value {
    font-family: "Fraunces", serif;
    font-size: 30px;
    font-weight: 600;
    color: var(--ink);
  }
  .stat-note { font-size: 12px; color: var(--ink-soft); margin-top: 4px; }

  /* ---------- Priorities ---------- */

  .priority-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 0;
    border-bottom: 1px dashed var(--paper-line);
  }
  .priority-row:last-child { border-bottom: none; }

  .priority-row input[type="checkbox"] {
    width: 18px; height: 18px; accent-color: var(--herb); cursor: pointer; flex-shrink: 0;
  }

  .priority-row.done .p-text { text-decoration: line-through; color: var(--ink-soft); }

  .p-text { flex: 1; font-size: 14px; }

  .tag {
    font-size: 10.5px;
    padding: 2px 8px;
    border-radius: 20px;
    font-weight: 600;
    letter-spacing: 0.02em;
    white-space: nowrap;
  }
  .tag.high { background: rgba(178,58,46,0.12); color: var(--chili); }
  .tag.med { background: rgba(201,154,62,0.15); color: var(--brass-dim); }
  .tag.low { background: rgba(92,143,110,0.15); color: var(--herb); }

  .add-row { display: flex; gap: 8px; margin-top: 14px; }
  .add-row input[type="text"] {
    flex: 1;
    padding: 9px 12px;
    border: 1px solid var(--paper-line);
    border-radius: 3px;
    background: #fff;
    font-size: 13.5px;
    color: var(--ink);
  }

  .btn {
    padding: 9px 16px;
    border-radius: 3px;
    border: none;
    background: var(--ink);
    color: var(--paper);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
  }
  .btn:hover { background: #453424; }
  .btn.brass { background: var(--brass); color: #241a08; }
  .btn.brass:hover { background: #b98931; }
  .btn.ghost {
    background: transparent;
    border: 1px solid var(--paper-line);
    color: var(--ink);
  }
  .btn.ghost:hover { background: rgba(0,0,0,0.04); }
  .btn.small { padding: 6px 11px; font-size: 12px; }

  h2.section-title {
    font-size: 19px;
    color: var(--paper);
    margin: 34px 0 14px;
  }
  h2.section-title:first-child { margin-top: 0; }

  .shortcut-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
  }
  .shortcut {
    background: var(--bg-panel-2);
    border: 1px solid rgba(201,154,62,0.2);
    border-radius: 3px;
    padding: 14px 16px;
    cursor: pointer;
    text-align: left;
    color: var(--cream);
  }
  .shortcut:hover { border-color: var(--brass); background: #26392b; }
  .shortcut .sc-title { font-weight: 600; font-size: 14px; margin-bottom: 3px; }
  .shortcut .sc-desc { font-size: 12px; color: var(--cream-dim); }

  /* ---------- SOP library ---------- */

  .sop-toolbar {
    display: flex;
    gap: 10px;
    margin-bottom: 18px;
    flex-wrap: wrap;
  }
  .sop-toolbar input[type="search"] {
    padding: 10px 14px;
    border-radius: 3px;
    border: 1px solid rgba(201,154,62,0.3);
    background: var(--bg-panel-2);
    color: var(--cream);
    font-size: 13.5px;
    min-width: 220px;
  }
  .sop-toolbar select {
    padding: 10px 12px;
    border-radius: 3px;
    border: 1px solid rgba(201,154,62,0.3);
    background: var(--bg-panel-2);
    color: var(--cream);
    font-size: 13.5px;
  }

  .sop-card { margin-bottom: 12px; }
  .sop-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    gap: 12px;
  }
  .sop-head .name { font-weight: 700; font-size: 15px; }
  .sop-head .meta { font-size: 12px; color: var(--ink-soft); margin-top: 3px; }
  .sop-chevron { font-size: 13px; color: var(--ink-soft); transition: transform 0.15s ease; }
  .sop-card.open .sop-chevron { transform: rotate(90deg); }

  .sop-body {
    display: none;
    margin-top: 14px;
    padding-top: 14px;
    border-top: 1px dashed var(--paper-line);
  }
  .sop-card.open .sop-body { display: block; }

  .sop-meta-row {
    display: flex;
    gap: 22px;
    font-size: 12.5px;
    color: var(--ink-soft);
    margin-bottom: 12px;
    flex-wrap: wrap;
  }
  .sop-meta-row b { color: var(--ink); }

  .sop-steps { list-style: none; margin: 0; padding: 0; }
  .sop-steps li {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 6px 0;
    font-size: 13.5px;
  }
  .sop-steps input[type="checkbox"] { margin-top: 2px; accent-color: var(--herb); cursor: pointer; }
  .sop-steps li.checked span { text-decoration: line-through; color: var(--ink-soft); }

  .sop-progress {
    font-size: 11.5px;
    color: var(--brass-dim);
    font-weight: 600;
    margin-left: 8px;
  }

  /* ---------- Finance ---------- */

  .calc-card h3 { font-size: 15px; margin: 0 0 4px; }
  .calc-card .calc-formula { font-size: 11.5px; color: var(--ink-soft); margin-bottom: 14px; font-style: italic; }

  .field { margin-bottom: 12px; }
  .field label { display: block; font-size: 12px; color: var(--ink-soft); margin-bottom: 5px; font-weight: 600; }
  .field input[type="number"] {
    width: 100%;
    padding: 9px 11px;
    border: 1px solid var(--paper-line);
    border-radius: 3px;
    background: #fff;
    font-size: 14px;
    color: var(--ink);
  }

  .calc-result {
    margin-top: 14px;
    padding: 12px 14px;
    background: var(--paper-dim);
    border-radius: 3px;
    border-left: 3px solid var(--brass);
  }
  .calc-result .cr-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--ink-soft); }
  .calc-result .cr-value { font-family: "Fraunces", serif; font-size: 22px; font-weight: 600; margin-top: 2px; }
  .calc-result .cr-value.warn { color: var(--chili); }
  .calc-result .cr-value.good { color: var(--herb); }

  /* ---------- Staff pipeline ---------- */

  .pipeline {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
  }
  .pipe-col-head {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--cream-dim);
    margin-bottom: 10px;
    padding-left: 4px;
  }
  .staff-card { margin-bottom: 10px; }
  .staff-card .ticket-pad { padding: 13px 14px 13px 18px; }
  .staff-name { font-weight: 700; font-size: 14px; }
  .staff-role { font-size: 12px; color: var(--ink-soft); margin-top: 2px; }
  .staff-flag { font-size: 11px; color: var(--chili); margin-top: 6px; font-weight: 600; }
  .staff-actions { margin-top: 10px; display: flex; gap: 6px; flex-wrap: wrap; }

  /* ---------- Marketing ---------- */

  .campaign-card .ticket-pad { padding: 16px 18px 16px 22px; }
  .campaign-head { display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }
  .campaign-title { font-weight: 700; font-size: 15px; }
  .campaign-meta { font-size: 12.5px; color: var(--ink-soft); margin-top: 6px; line-height: 1.6; }
  .status-pill {
    font-size: 11px;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: 20px;
    white-space: nowrap;
  }
  .status-pill.planning { background: rgba(201,154,62,0.18); color: var(--brass-dim); }
  .status-pill.scheduled { background: rgba(92,143,110,0.16); color: var(--herb); }
  .status-pill.live { background: rgba(178,58,46,0.14); color: var(--chili); }
  .status-pill.done { background: rgba(0,0,0,0.08); color: var(--ink-soft); }

  .new-campaign { margin-top: 18px; }
  .new-campaign .grid-2 { margin-bottom: 10px; }
  .new-campaign input[type="text"], .new-campaign select {
    width: 100%;
    padding: 9px 11px;
    border: 1px solid var(--paper-line);
    border-radius: 3px;
    background: #fff;
    font-size: 13.5px;
    color: var(--ink);
  }

  .idea-list { list-style: none; padding: 0; margin: 0; }
  .idea-list li {
    padding: 8px 0;
    border-bottom: 1px dashed var(--paper-line);
    font-size: 13.5px;
  }
  .idea-list li:last-child { border-bottom: none; }

  /* ---------- Security ---------- */

  .sec-check-row {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 11px 0;
    border-bottom: 1px dashed var(--paper-line);
  }
  .sec-check-row:last-child { border-bottom: none; }
  .sec-check-row input[type="checkbox"] { width: 18px; height: 18px; accent-color: var(--herb); margin-top: 2px; cursor: pointer; }
  .sec-check-row .sc-body { flex: 1; }
  .sec-check-row .sc-title2 { font-weight: 600; font-size: 13.5px; }
  .sec-check-row .sc-note { font-size: 12px; color: var(--ink-soft); margin-top: 2px; }
  .sec-check-row.checked .sc-title2 { text-decoration: line-through; color: var(--ink-soft); }

  .incident-log-item {
    padding: 10px 0;
    border-bottom: 1px dashed var(--paper-line);
    font-size: 13px;
  }
  .incident-log-item .il-date { font-weight: 700; margin-right: 8px; }
  .incident-log-item:last-child { border-bottom: none; }

  .incident-form { display: flex; gap: 8px; margin-top: 14px; flex-wrap: wrap; }
  .incident-form input[type="date"] {
    padding: 9px 10px; border: 1px solid var(--paper-line); border-radius: 3px; background: #fff; color: var(--ink); font-size: 13px;
  }
  .incident-form input[type="text"] {
    flex: 1; min-width: 180px; padding: 9px 12px; border: 1px solid var(--paper-line); border-radius: 3px; background: #fff; font-size: 13.5px; color: var(--ink);
  }

  .empty-note { font-size: 13px; color: var(--ink-soft); font-style: italic; padding: 6px 0; }

  /* ---------- Footer credit ---------- */
  .footer-note {
    margin-top: 40px;
    padding-top: 16px;
    border-top: 1px dashed rgba(239,230,210,0.15);
    font-size: 11.5px;
    color: var(--cream-dim);
  }

  /* ---------- Responsive ---------- */

  @media (max-width: 860px) {
    .grid-3 { grid-template-columns: 1fr; }
    .grid-2 { grid-template-columns: 1fr; }
    .shortcut-grid { grid-template-columns: 1fr; }
    .pipeline { grid-template-columns: 1fr 1fr; }
  }

  @media (max-width: 760px) {
    .app { grid-template-columns: 1fr; }
    .rail {
      flex-direction: row;
      overflow-x: auto;
      padding: env(safe-area-inset-top, 14px) 10px 10px;
      border-right: none;
      border-bottom: 1px solid rgba(201,154,62,0.18);
      position: sticky;
      top: 0;
      z-index: 5;
    }
    .rail-brand { display: none; }
    .rail-nav { flex-direction: row; padding: 0; gap: 4px; }
    .rail-item { border-left: none; border-bottom: 3px solid transparent; flex-shrink: 0; }
    .rail-item:not(:last-child)::after { display: none; }
    .rail-item.active { border-left: none; border-bottom-color: var(--brass); background: transparent; }
    .rail-foot { display: none; }
    main { padding: 22px 18px 50px; }
    .pipeline { grid-template-columns: 1fr 1fr; }
  }

  @media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation: none !important; }
  }

  /* ---------- Feedback + update banner ---------- */
  .rail-feedback {
    margin: 10px 12px 0; padding: 10px 12px; border-radius: 3px; cursor: pointer;
    background: transparent; border: 1px dashed rgba(201,154,62,0.45);
    color: var(--brass); font-size: 13px; font-weight: 600; text-align: left; flex-shrink: 0;
  }
  .rail-feedback:hover { background: rgba(201,154,62,0.1); }
  .fb-backdrop {
    position: fixed; inset: 0; background: rgba(0,0,0,0.55); display: none;
    align-items: center; justify-content: center; z-index: 50; padding: 18px;
  }
  .fb-backdrop.open { display: flex; }
  .fb-modal { width: 100%; max-width: 440px; }
  .fb-modal h3 { margin: 0 0 4px; font-size: 18px; }
  .fb-modal p.hint { font-size: 12.5px; color: var(--ink-soft); margin: 0 0 14px; }
  .fb-modal textarea {
    width: 100%; min-height: 110px; padding: 10px; border: 1px solid var(--paper-line);
    border-radius: 3px; background: #fff; color: var(--ink); font-size: 14px; resize: vertical;
  }
  .fb-rating { display: flex; gap: 6px; margin: 4px 0 12px; }
  .fb-rating button {
    width: 36px; height: 36px; border-radius: 3px; border: 1px solid var(--paper-line);
    background: #fff; color: var(--ink); font-weight: 700; cursor: pointer;
  }
  .fb-rating button.sel { background: var(--brass); border-color: var(--brass); color: #241a08; }
  .fb-actions { display: flex; gap: 8px; margin-top: 12px; align-items: center; }
  .fb-status { font-size: 12.5px; color: var(--ink-soft); margin-top: 10px; min-height: 16px; }
  .update-banner {
    position: fixed; left: 50%; transform: translateX(-50%); bottom: calc(18px + env(safe-area-inset-bottom, 0px));
    background: var(--brass); color: #241a08; padding: 10px 14px; border-radius: 4px; z-index: 60;
    display: none; align-items: center; gap: 12px; font-size: 13.5px; font-weight: 600;
    box-shadow: 0 6px 20px rgba(0,0,0,0.35);
  }
  .update-banner.show { display: flex; }
  .update-banner button {
    background: #241a08; color: var(--paper); border: none; border-radius: 3px;
    padding: 6px 12px; font-weight: 700; cursor: pointer;
  }

  /* ---------- Shared data: status, sign-in ---------- */
  .rail-sync { padding: 14px 22px 0; display: flex; flex-direction: column; gap: 6px; align-items: flex-start; }
  .sync-status { font-size: 12px; color: var(--cream-dim); }
  .sync-status.ok { color: #8fc3a1; }
  .sync-status.warn { color: #e0b05a; }
  .rail-signout {
    background: none; border: none; padding: 0; cursor: pointer; font-size: 12px;
    color: var(--brass); text-decoration: underline;
  }
  .rail-signout[hidden] { display: none; }
  .login-form label { display: block; font-size: 12px; font-weight: 600; color: var(--ink-soft); margin: 10px 0 4px; }
  .login-form input {
    width: 100%; padding: 10px; border: 1px solid var(--paper-line); border-radius: 3px;
    background: #fff; color: var(--ink); font-size: 15px;
  }
  @media (max-width: 760px) {
    .rail-sync { flex-direction: row; align-items: center; padding: 0 8px; gap: 10px; flex-shrink: 0; white-space: nowrap; }
  }

  /* ---------- v2.1: language, dashboard actions, menu, reviews, dialogs ---------- */
  [hidden] { display: none !important; }
  .btn.outline-light {
    background: transparent; border: 1px solid rgba(201,154,62,0.55); color: var(--cream);
  }
  .btn.outline-light:hover { background: rgba(201,154,62,0.14); }
  .btn.danger { color: var(--chili); border-color: rgba(178,58,46,0.5); margin-left: auto; }

  .lang-switch { display: flex; gap: 6px; padding: 14px 22px 0; flex-shrink: 0; }
  .lang-switch button {
    flex: 1; padding: 6px 4px; border-radius: 3px; cursor: pointer; font-size: 12px; font-weight: 600;
    background: transparent; border: 1px solid rgba(201,154,62,0.35); color: var(--cream-dim);
  }
  .lang-switch button.active { background: var(--brass); border-color: var(--brass); color: #241a08; }

  .topbar .btn { margin-left: auto; }
  .dash-actions { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 0 0 18px; }
  .dash-actions .spacer { flex: 1; }
  .user-chip { font-size: 12.5px; color: var(--cream-dim); }

  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 28px; }

  .menu-summary { font-size: 13px; color: var(--cream-dim); margin: -6px 0 14px; }
  .menu-cat-title { font-family: "Fraunces", Georgia, serif; font-size: 17px; font-weight: 600; margin: 4px 0 2px; }
  .menu-card { margin-bottom: 16px; }
  .menu-row { display: flex; align-items: center; gap: 12px; padding: 12px 0; border-bottom: 1px dashed var(--paper-line); }
  .menu-row:last-child { border-bottom: none; }
  .menu-info { flex: 1; min-width: 0; }
  .menu-name { font-weight: 700; font-size: 14.5px; }
  .menu-desc { font-size: 12.5px; color: var(--ink-soft); margin-top: 2px; }
  .menu-price { font-family: "Fraunces", Georgia, serif; font-weight: 600; font-size: 16px; white-space: nowrap; }
  .menu-row.soldout .menu-name, .menu-row.soldout .menu-price { color: var(--ink-soft); text-decoration: line-through; }
  .avail-btn {
    border: none; border-radius: 20px; padding: 5px 11px; font-size: 11.5px; font-weight: 700; cursor: pointer; white-space: nowrap;
  }
  .avail-btn.on { background: rgba(92,143,110,0.18); color: #3f7355; }
  .avail-btn.off { background: rgba(178,58,46,0.14); color: var(--chili); }
  .icon-btn {
    background: none; border: 1px solid var(--paper-line); border-radius: 3px; padding: 5px 9px; cursor: pointer;
    color: var(--ink); font-size: 12px; font-weight: 600;
  }
  .icon-btn:hover { background: rgba(0,0,0,0.05); }

  .review-summary { font-size: 14px; font-weight: 600; margin-bottom: 6px; }
  .review-note { font-size: 12px; color: var(--ink-soft); margin: 14px 0 0; }
  .review-row { padding: 14px 0; border-bottom: 1px dashed var(--paper-line); }
  .review-row:last-of-type { border-bottom: none; }
  .review-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .stars { color: var(--brass); letter-spacing: 2px; font-size: 16px; }
  .source-badge { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 20px; background: rgba(0,0,0,0.07); color: var(--ink-soft); }
  .review-meta { font-size: 12px; color: var(--ink-soft); }
  .review-text { font-size: 13.5px; margin: 8px 0 10px; line-height: 1.55; white-space: pre-wrap; }
  .review-actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .tag.reply { background: rgba(178,58,46,0.12); color: var(--chili); }
  .tag.done { background: rgba(92,143,110,0.16); color: #3f7355; }

  .modal-form label { display: block; font-size: 12px; font-weight: 700; color: var(--ink-soft); margin: 12px 0 5px; }
  .modal-form label.check { display: flex; align-items: center; gap: 8px; font-size: 13.5px; color: var(--ink); margin-top: 14px; }
  .modal-form input[type="text"], .modal-form input[type="number"], .modal-form input[type="date"],
  .modal-form input[type="url"], .modal-form select, .modal-form textarea {
    width: 100%; padding: 10px; border: 1px solid var(--paper-line); border-radius: 3px;
    background: #fff; color: var(--ink); font-size: 15px; font-family: inherit;
  }
  .modal-form textarea { min-height: 80px; resize: vertical; }
  .modal-form .fb-rating { margin: 2px 0 0; }
  .form-error { color: var(--chili); font-weight: 600; }
  .fb-modal { max-height: calc(100vh - 36px); overflow-y: auto; }

  @media (max-width: 1100px) { .grid-4 { grid-template-columns: repeat(2, 1fr); } }
  @media (max-width: 860px) {
    .menu-row { flex-wrap: wrap; }
    .menu-info { flex-basis: 100%; }
  }
  @media (max-width: 760px) {
    .lang-switch { padding: 0 8px; gap: 4px; align-items: center; }
    .lang-switch button { white-space: nowrap; padding: 6px 10px; }
    .dash-actions .spacer { display: none; }
  }
  @media (max-width: 460px) { .grid-4 { grid-template-columns: 1fr; } }
</style>
</head>
<body>

<div class="app">
  <nav class="rail" data-i18n-aria="nav.label" aria-label="Sections">
    <div class="rail-brand">
      <div class="mark">SecureManager</div>
    </div>
    <div class="rail-nav" id="railNav">
      <button class="rail-item active" data-view="dashboard"><span class="ico">☰</span> <span data-i18n="nav.dashboard">Dashboard</span></button>
      <button class="rail-item" data-view="menu"><span class="ico">🍜</span> <span data-i18n="nav.menu">Menu</span></button>
      <button class="rail-item" data-view="sop"><span class="ico">📋</span> <span data-i18n="nav.sop">SOP Library</span></button>
      <button class="rail-item" data-view="finance"><span class="ico">💰</span> <span data-i18n="nav.finance">Finance</span></button>
      <button class="rail-item" data-view="staff"><span class="ico">👥</span> <span data-i18n="nav.staff">Staff</span></button>
      <button class="rail-item" data-view="marketing"><span class="ico">📣</span> <span data-i18n="nav.marketing">Marketing</span></button>
      <button class="rail-item" data-view="reviews"><span class="ico">⭐</span> <span data-i18n="nav.reviews">Reviews</span></button>
      <button class="rail-item" data-view="security"><span class="ico">🔐</span> <span data-i18n="nav.security">Security</span></button>
    </div>
    <div class="lang-switch" role="group" data-i18n-aria="lang.label" aria-label="Language">
      <button type="button" data-lang="en">English</button>
      <button type="button" data-lang="vi">Tiếng Việt</button>
    </div>
    <div class="rail-sync">
      <span class="sync-status" id="syncStatus"></span>
      <button class="rail-signout" type="button" data-signout hidden data-i18n="common.signOut">Sign out</button>
    </div>
    <button class="rail-feedback" id="feedbackBtn" type="button" data-i18n="common.feedback">💬 Send feedback</button>
    <div class="rail-foot"><span data-i18n="common.internal">Internal tool — Cơm Nhà staff only</span> · <span id="appVersion"></span></div>
  </nav>

  <main>

    <!-- DASHBOARD -->
    <section class="view active" id="view-dashboard">
      <div class="topbar">
        <h1 data-i18n="nav.dashboard">Dashboard</h1>
        <div class="date" id="todayDate"></div>
      </div>

      <div class="dash-actions">
        <button class="btn brass" id="visitWebsiteBtn" type="button" data-i18n="dash.visitWebsite">🌐 Visit website</button>
        <button class="btn outline-light" type="button" data-view="reviews" data-i18n="dash.checkReviews">⭐ Check recent reviews</button>
        <button class="btn outline-light js-edit-links" type="button" data-i18n="dash.editLinks">✎ Edit links</button>
        <span class="spacer"></span>
        <span class="user-chip" id="dashUser"></span>
        <button class="btn outline-light" id="dashSignOut" type="button" data-signout hidden data-i18n="common.signOut">Sign out</button>
      </div>

      <p class="lede" data-i18n="dash.lede"></p>

      <div class="grid-4">
        <div class="ticket"><div class="ticket-pad">
          <p class="stat-label" data-i18n="stat.openPriorities">Open priorities</p>
          <p class="stat-value" id="statOpenPriorities">–</p>
          <p class="stat-note" data-i18n="stat.thisWeek">This week</p>
        </div></div>
        <div class="ticket"><div class="ticket-pad">
          <p class="stat-label" data-i18n="stat.menu">Dishes available</p>
          <p class="stat-value" id="statMenu">–</p>
          <p class="stat-note" id="statMenuNote"></p>
        </div></div>
        <div class="ticket"><div class="ticket-pad">
          <p class="stat-label" data-i18n="stat.reviews">Average rating</p>
          <p class="stat-value" id="statReviews">–</p>
          <p class="stat-note" id="statReviewsNote"></p>
        </div></div>
        <div class="ticket"><div class="ticket-pad">
          <p class="stat-label" data-i18n="stat.onboarding">Staff in onboarding</p>
          <p class="stat-value" id="statOnboarding">–</p>
          <p class="stat-note" data-i18n="stat.seeStaff">See Staff board</p>
        </div></div>
      </div>

      <h2 class="section-title" data-i18n="priorities.title">This week's priorities</h2>
      <div class="ticket"><div class="ticket-pad">
        <div id="priorityList"></div>
        <div class="add-row">
          <input type="text" id="newPriorityInput" data-i18n-ph="priorities.placeholder" maxlength="200">
          <button class="btn brass" id="addPriorityBtn" type="button" data-i18n="common.add">Add</button>
        </div>
      </div></div>

      <h2 class="section-title" data-i18n="dfin.title">Quick finance check</h2>
      <div class="ticket"><div class="ticket-pad">
        <p style="font-size:13px;color:var(--ink-soft);margin:0 0 14px;" data-i18n="dfin.intro"></p>
        <div class="grid-3">
          <div class="field"><label data-i18n="dfin.sales">Sales ($)</label><input type="number" id="dashSales" data-i18n-ph="dfin.salesPh"></div>
          <div class="field"><label data-i18n="dfin.foodCost">Food cost ($)</label><input type="number" id="dashFoodCost" data-i18n-ph="dfin.foodCostPh"></div>
          <div class="calc-result">
            <div class="cr-label" data-i18n="dfin.foodCostPct">Food cost %</div>
            <div class="cr-value" id="dashFoodCostResult">—</div>
          </div>
        </div>
        <div style="border-top:1px dashed var(--paper-line);margin:16px 0 14px;"></div>
        <p class="stat-label" style="margin-bottom:10px;" data-i18n="dfin.goalTitle">Sales goal</p>
        <div class="grid-2">
          <div class="field"><label data-i18n="dfin.goal">Goal ($)</label><input type="number" id="dashGoal" data-i18n-ph="dfin.goalPh"></div>
          <div class="calc-result">
            <div class="cr-label" id="dashGoalLabel"></div>
            <div class="cr-value" id="dashGoalResult">—</div>
          </div>
        </div>
        <div style="background:var(--paper-line);height:10px;border-radius:5px;margin-top:10px;overflow:hidden;">
          <div id="dashGoalBar" style="background:var(--brass);height:100%;width:0%;transition:width .2s ease;"></div>
        </div>
        <p id="dashGoalNote" style="font-size:12px;color:var(--ink-soft);margin:8px 0 0;"></p>
        <button class="btn ghost" style="margin-top:14px;" type="button" data-view="finance" data-i18n="dfin.open">Open Finance module →</button>
      </div></div>

      <h2 class="section-title" data-i18n="dash.jump">Jump to a module</h2>
      <div class="shortcut-grid">
        <button class="shortcut" type="button" data-view="menu">
          <div class="sc-title" data-i18n="nav.menu">Menu</div>
          <div class="sc-desc" data-i18n="sc.menu"></div>
        </button>
        <button class="shortcut" type="button" data-view="sop">
          <div class="sc-title" data-i18n="nav.sop">SOP Library</div>
          <div class="sc-desc" data-i18n="sc.sop"></div>
        </button>
        <button class="shortcut" type="button" data-view="finance">
          <div class="sc-title" data-i18n="nav.finance">Finance</div>
          <div class="sc-desc" data-i18n="sc.finance"></div>
        </button>
        <button class="shortcut" type="button" data-view="staff">
          <div class="sc-title" data-i18n="nav.staff">Staff</div>
          <div class="sc-desc" data-i18n="sc.staff"></div>
        </button>
        <button class="shortcut" type="button" data-view="marketing">
          <div class="sc-title" data-i18n="nav.marketing">Marketing</div>
          <div class="sc-desc" data-i18n="sc.marketing"></div>
        </button>
        <button class="shortcut" type="button" data-view="reviews">
          <div class="sc-title" data-i18n="nav.reviews">Reviews</div>
          <div class="sc-desc" data-i18n="sc.reviews"></div>
        </button>
        <button class="shortcut" type="button" data-view="security">
          <div class="sc-title" data-i18n="nav.security">Security</div>
          <div class="sc-desc" data-i18n="sc.security"></div>
        </button>
      </div>
    </section>

    <!-- MENU -->
    <section class="view" id="view-menu">
      <div class="topbar">
        <h1 data-i18n="nav.menu">Menu</h1>
        <button class="btn brass" id="addDishBtn" type="button" data-i18n="menu.addDish">+ Add dish</button>
      </div>
      <p class="lede" data-i18n="menu.lede"></p>
      <div class="sop-toolbar">
        <input type="search" id="menuSearch" data-i18n-ph="menu.search">
        <select id="menuFilter" data-i18n-aria="menu.filterLabel"></select>
      </div>
      <p class="menu-summary" id="menuSummary"></p>
      <div id="menuList"></div>
    </section>

    <!-- SOP LIBRARY -->
    <section class="view" id="view-sop">
      <div class="topbar"><h1 data-i18n="nav.sop">SOP Library</h1></div>
      <p class="lede" data-i18n="sop.lede"></p>
      <div class="sop-toolbar">
        <input type="search" id="sopSearch" data-i18n-ph="sop.search">
        <select id="sopFilter" data-i18n-aria="menu.filterLabel"></select>
      </div>
      <div id="sopListContainer"></div>
    </section>

    <!-- FINANCE -->
    <section class="view" id="view-finance">
      <div class="topbar"><h1 data-i18n="nav.finance">Finance</h1></div>
      <p class="lede" data-i18n="finance.lede"></p>

      <div class="grid-2">
        <div class="ticket calc-card"><div class="ticket-pad">
          <h3 data-i18n="calc.fc.title">Food cost %</h3>
          <p class="calc-formula" data-i18n="calc.fc.formula"></p>
          <div class="field"><label data-i18n="calc.fc.cost">Food cost ($)</label><input type="number" id="fc_cost" data-i18n-ph="calc.fc.costPh"></div>
          <div class="field"><label data-i18n="calc.fc.price">Menu sales price ($)</label><input type="number" id="fc_price" data-i18n-ph="calc.fc.pricePh"></div>
          <div class="calc-result">
            <div class="cr-label" data-i18n="calc.fc.title">Food cost %</div>
            <div class="cr-value" id="fc_result">—</div>
          </div>
        </div></div>

        <div class="ticket calc-card"><div class="ticket-pad">
          <h3 data-i18n="calc.pm.title">Profit margin</h3>
          <p class="calc-formula" data-i18n="calc.pm.formula"></p>
          <div class="field"><label data-i18n="calc.pm.rev">Revenue ($)</label><input type="number" id="pm_rev" data-i18n-ph="calc.pm.revPh"></div>
          <div class="field"><label data-i18n="calc.pm.cost">Total cost ($)</label><input type="number" id="pm_cost" data-i18n-ph="calc.pm.costPh"></div>
          <div class="calc-result">
            <div class="cr-label" data-i18n="calc.pm.title">Profit margin</div>
            <div class="cr-value" id="pm_result">—</div>
          </div>
        </div></div>

        <div class="ticket calc-card"><div class="ticket-pad">
          <h3 data-i18n="calc.mp.title">Menu price suggestion</h3>
          <p class="calc-formula" data-i18n="calc.mp.formula"></p>
          <div class="field"><label data-i18n="calc.mp.cost">Ingredient cost per dish ($)</label><input type="number" id="mp_cost" data-i18n-ph="calc.mp.costPh"></div>
          <div class="field"><label data-i18n="calc.mp.target">Target food cost %</label><input type="number" id="mp_target" value="30"></div>
          <div class="calc-result">
            <div class="cr-label" data-i18n="calc.mp.result">Suggested price</div>
            <div class="cr-value" id="mp_result">—</div>
          </div>
        </div></div>

        <div class="ticket calc-card"><div class="ticket-pad">
          <h3 data-i18n="calc.lc.title">Labour cost %</h3>
          <p class="calc-formula" data-i18n="calc.lc.formula"></p>
          <div class="field"><label data-i18n="calc.lc.labour">Labour cost this period ($)</label><input type="number" id="lc_labour" data-i18n-ph="calc.lc.labourPh"></div>
          <div class="field"><label data-i18n="calc.lc.sales">Sales this period ($)</label><input type="number" id="lc_sales" data-i18n-ph="calc.lc.salesPh"></div>
          <div class="calc-result">
            <div class="cr-label" data-i18n="calc.lc.title">Labour cost %</div>
            <div class="cr-value" id="lc_result">—</div>
          </div>
        </div></div>
      </div>
    </section>

    <!-- STAFF -->
    <section class="view" id="view-staff">
      <div class="topbar"><h1 data-i18n="nav.staff">Staff</h1></div>
      <p class="lede" data-i18n="staff.lede"></p>
      <div class="pipeline" id="staffPipeline"></div>
    </section>

    <!-- MARKETING -->
    <section class="view" id="view-marketing">
      <div class="topbar"><h1 data-i18n="nav.marketing">Marketing</h1></div>
      <p class="lede" data-i18n="marketing.lede"></p>

      <h2 class="section-title" style="margin-top:0;" data-i18n="marketing.campaigns">Campaigns</h2>
      <div id="campaignList" class="grid-2"></div>

      <div class="ticket new-campaign"><div class="ticket-pad">
        <h3 style="margin-top:0;" data-i18n="marketing.addCampaign">Add a campaign</h3>
        <div class="grid-2">
          <input type="text" id="camp_title" data-i18n-ph="marketing.name" maxlength="80">
          <input type="text" id="camp_channel" data-i18n-ph="marketing.channelPh" maxlength="80">
        </div>
        <div class="grid-2">
          <input type="text" id="camp_offer" data-i18n-ph="marketing.offerPh" maxlength="160">
          <select id="camp_status">
            <option value="Planning" data-i18n="status.Planning">Planning</option>
            <option value="Scheduled" data-i18n="status.Scheduled">Scheduled</option>
            <option value="Live" data-i18n="status.Live">Live</option>
            <option value="Done" data-i18n="status.Done">Done</option>
          </select>
        </div>
        <button class="btn brass" id="addCampaignBtn" type="button" data-i18n="marketing.addBtn">Add campaign</button>
      </div></div>

      <h2 class="section-title" data-i18n="marketing.ideas">Content ideas</h2>
      <div class="ticket"><div class="ticket-pad">
        <ul class="idea-list" id="ideaList"></ul>
        <div class="add-row">
          <input type="text" id="newIdeaInput" data-i18n-ph="marketing.ideaPh" maxlength="200">
          <button class="btn ghost" id="addIdeaBtn" type="button" data-i18n="common.add">Add</button>
        </div>
      </div></div>
    </section>

    <!-- REVIEWS -->
    <section class="view" id="view-reviews">
      <div class="topbar">
        <h1 data-i18n="nav.reviews">Reviews</h1>
        <button class="btn brass" id="addReviewBtn" type="button" data-i18n="reviews.add">+ Log a review</button>
      </div>
      <p class="lede" data-i18n="reviews.lede"></p>
      <div class="dash-actions">
        <button class="btn outline-light" id="openReviewsOnlineBtn" type="button" data-i18n="reviews.openOnline">⭐ Open reviews online</button>
        <button class="btn outline-light js-edit-links" type="button" data-i18n="dash.editLinks">✎ Edit links</button>
      </div>
      <div class="ticket"><div class="ticket-pad">
        <div class="review-summary" id="reviewSummary"></div>
        <div id="reviewList"></div>
        <p class="review-note" data-i18n="reviews.note"></p>
      </div></div>
    </section>

    <!-- SECURITY -->
    <section class="view" id="view-security">
      <div class="topbar"><h1 data-i18n="security.title">Security &amp; Privacy</h1></div>
      <p class="lede" data-i18n="security.lede"></p>

      <h2 class="section-title" style="margin-top:0;" data-i18n="security.checklist">Access &amp; privacy checklist</h2>
      <div class="ticket"><div class="ticket-pad" id="secChecklist"></div></div>

      <h2 class="section-title" data-i18n="security.incidents">Incident log</h2>
      <div class="ticket"><div class="ticket-pad">
        <div id="incidentLog"></div>
        <div class="incident-form">
          <input type="date" id="inc_date">
          <input type="text" id="inc_desc" data-i18n-ph="security.whatHappened" maxlength="400">
          <button class="btn ghost" id="addIncidentBtn" type="button" data-i18n="security.logIt">Log it</button>
        </div>
      </div></div>
    </section>

    <p class="footer-note" data-i18n="common.sampleNote"></p>
  </main>
</div>

<!-- Feedback -->
<div class="fb-backdrop" id="fbBackdrop" role="dialog" aria-modal="true" aria-labelledby="fbTitle">
  <div class="ticket fb-modal"><div class="ticket-pad">
    <h3 id="fbTitle" data-i18n="fb.title">How is SecureManager working for you?</h3>
    <p class="hint" data-i18n="fb.hint"></p>
    <div class="stat-label" data-i18n="fb.rating">Overall rating</div>
    <div class="fb-rating" id="fbRating">
      <button type="button" data-r="1">1</button><button type="button" data-r="2">2</button>
      <button type="button" data-r="3">3</button><button type="button" data-r="4">4</button>
      <button type="button" data-r="5">5</button>
    </div>
    <textarea id="fbText" data-i18n-ph="fb.placeholder"></textarea>
    <div class="fb-actions">
      <button class="btn brass" id="fbSend" type="button" data-i18n="common.send">Send</button>
      <button class="btn ghost" id="fbCancel" type="button" data-close data-i18n="common.cancel">Cancel</button>
    </div>
    <div class="fb-status" id="fbStatus"></div>
  </div></div>
</div>

<!-- Add / edit a dish -->
<div class="fb-backdrop" id="dishModal" role="dialog" aria-modal="true" aria-labelledby="dishTitle">
  <div class="ticket fb-modal"><div class="ticket-pad">
    <h3 id="dishTitle"></h3>
    <form id="dishForm" class="modal-form" novalidate>
      <label for="dishName" data-i18n="menu.field.name">Dish name</label>
      <input id="dishName" type="text" maxlength="80" autocomplete="off">
      <label for="dishCategory" data-i18n="menu.field.category">Category</label>
      <input id="dishCategory" type="text" list="dishCategories" maxlength="40" autocomplete="off">
      <datalist id="dishCategories"></datalist>
      <label for="dishPrice" data-i18n="menu.field.price">Price ($)</label>
      <input id="dishPrice" type="number" step="0.01" min="0" inputmode="decimal">
      <label for="dishDesc" data-i18n="menu.field.description">Description (optional)</label>
      <textarea id="dishDesc" maxlength="200"></textarea>
      <label class="check"><input id="dishAvail" type="checkbox"> <span data-i18n="menu.field.available">Available today</span></label>
      <div class="fb-actions">
        <button class="btn brass" type="submit" data-i18n="common.save">Save</button>
        <button class="btn ghost" type="button" data-close data-i18n="common.cancel">Cancel</button>
        <button class="btn ghost danger" type="button" id="dishDelete" data-i18n="common.delete">Delete</button>
      </div>
      <div class="fb-status form-error" id="dishError" role="alert"></div>
    </form>
  </div></div>
</div>

<!-- Log / edit a review -->
<div class="fb-backdrop" id="reviewModal" role="dialog" aria-modal="true" aria-labelledby="reviewTitle">
  <div class="ticket fb-modal"><div class="ticket-pad">
    <h3 id="reviewTitle"></h3>
    <form id="reviewForm" class="modal-form" novalidate>
      <label for="reviewSource" data-i18n="reviews.field.source">Where was it posted?</label>
      <select id="reviewSource">
        <option value="Google" data-i18n="source.Google">Google</option>
        <option value="Facebook" data-i18n="source.Facebook">Facebook</option>
        <option value="TripAdvisor" data-i18n="source.TripAdvisor">TripAdvisor</option>
        <option value="Other" data-i18n="source.Other">Other</option>
      </select>
      <label data-i18n="reviews.field.rating">Rating</label>
      <div class="fb-rating" id="reviewRating">
        <button type="button" data-r="1">1</button><button type="button" data-r="2">2</button>
        <button type="button" data-r="3">3</button><button type="button" data-r="4">4</button>
        <button type="button" data-r="5">5</button>
      </div>
      <label for="reviewDate" data-i18n="reviews.field.date">Date</label>
      <input id="reviewDate" type="date">
      <label for="reviewName" data-i18n="reviews.field.name">Reviewer name (optional)</label>
      <input id="reviewName" type="text" maxlength="60" autocomplete="off">
      <label for="reviewText" data-i18n="reviews.field.text">What they said</label>
      <textarea id="reviewText" maxlength="1500"></textarea>
      <label class="check"><input id="reviewReplied" type="checkbox"> <span data-i18n="reviews.field.replied">We have replied</span></label>
      <div class="fb-actions">
        <button class="btn brass" type="submit" data-i18n="common.save">Save</button>
        <button class="btn ghost" type="button" data-close data-i18n="common.cancel">Cancel</button>
        <button class="btn ghost danger" type="button" id="reviewDelete" data-i18n="common.delete">Delete</button>
      </div>
      <div class="fb-status form-error" id="reviewError" role="alert"></div>
    </form>
  </div></div>
</div>

<!-- Website and review links -->
<div class="fb-backdrop" id="linksModal" role="dialog" aria-modal="true" aria-labelledby="linksTitle">
  <div class="ticket fb-modal"><div class="ticket-pad">
    <h3 id="linksTitle" data-i18n="links.title">Website and review links</h3>
    <p class="hint" id="linksHint" data-i18n="links.hint"></p>
    <form id="linksForm" class="modal-form" novalidate>
      <label for="linkWebsite" data-i18n="links.website">Restaurant website</label>
      <input id="linkWebsite" type="text" inputmode="url" autocomplete="off" placeholder="https://">
      <label for="linkReviews" data-i18n="links.reviews">Reviews page (for example, your Google reviews link)</label>
      <input id="linkReviews" type="text" inputmode="url" autocomplete="off" placeholder="https://">
      <div class="fb-actions">
        <button class="btn brass" type="submit" data-i18n="common.save">Save</button>
        <button class="btn ghost" type="button" data-close data-i18n="common.cancel">Cancel</button>
      </div>
      <div class="fb-status form-error" id="linksError" role="alert"></div>
    </form>
  </div></div>
</div>

<div class="update-banner" id="updateBanner">
  <span data-i18n="common.updateReady">A new version of SecureManager is ready.</span>
  <button type="button" id="updateReload" data-i18n="common.refresh">Refresh</button>
</div>

<script>
(function () {
  "use strict";
  // ======================================================================
  // Text in both languages. Every key must exist in BOTH "en" and "vi".
  // ======================================================================
  const I18N = {
    en: {
      "nav.label": "Sections",
      "nav.dashboard": "Dashboard", "nav.menu": "Menu", "nav.sop": "SOP Library", "nav.finance": "Finance",
      "nav.staff": "Staff", "nav.marketing": "Marketing", "nav.reviews": "Reviews", "nav.security": "Security",
      "lang.label": "Language",

      "common.signOut": "Sign out",
      "common.signedInAs": "Signed in as {email}",
      "common.feedback": "💬 Send feedback",
      "common.internal": "Internal tool — Cơm Nhà staff only",
      "common.add": "Add", "common.save": "Save", "common.cancel": "Cancel", "common.delete": "Delete",
      "common.send": "Send", "common.edit": "Edit", "common.refresh": "Refresh",
      "common.updateReady": "A new version of SecureManager is ready.",
      "common.sampleNote": "Sample data is shown for demonstration — replace the sample menu, staff and campaigns with your own as you go.",

      "sync.connecting": "Connecting…", "sync.synced": "● Synced", "sync.offline": "● Offline — changes will sync",

      "dash.visitWebsite": "🌐 Visit website",
      "dash.checkReviews": "⭐ Check recent reviews",
      "dash.editLinks": "✎ Edit links",
      "dash.lede": "One place for the procedures, numbers, people and plans that keep Cơm Nhà running — so nothing important lives only in your head.",
      "dash.jump": "Jump to a module",

      "stat.openPriorities": "Open priorities", "stat.thisWeek": "This week",
      "stat.menu": "Dishes available", "stat.menuNote": "{total} on the menu",
      "stat.reviews": "Average rating", "stat.reviewsNote": "{n} waiting for a reply", "stat.noReviews": "No reviews logged yet",
      "stat.onboarding": "Staff in onboarding", "stat.seeStaff": "See Staff board",

      "priorities.title": "This week's priorities",
      "priorities.placeholder": "Add a priority for this week…",
      "priorities.empty": "No priorities yet — add one below.",
      "tag.high": "High", "tag.med": "Medium", "tag.low": "Low",

      "dfin.title": "Quick finance check",
      "dfin.intro": "Enter today's sales and food cost for a quick read — the full Finance module has margin, pricing and labour tools too.",
      "dfin.sales": "Sales ($)", "dfin.salesPh": "e.g. 1200",
      "dfin.foodCost": "Food cost ($)", "dfin.foodCostPh": "e.g. 360",
      "dfin.foodCostPct": "Food cost %",
      "dfin.goalTitle": "Sales goal", "dfin.goal": "Goal ($)", "dfin.goalPh": "e.g. 2000",
      "dfin.stillNeeded": "Still needed", "dfin.goalReached": "Goal reached",
      "dfin.goalNoteEmpty": "Set a sales goal above to track progress toward it.",
      "dfin.goalNoteMet": "🎉 {sales} of {goal} — goal met.",
      "dfin.goalNoteProgress": "{sales} of {goal} so far ({pct}%).",
      "dfin.open": "Open Finance module →",

      "sc.menu": "Dishes, prices & availability", "sc.sop": "Opening, closing, cleaning & more",
      "sc.finance": "Food cost, margin & pricing", "sc.staff": "Onboarding & training status",
      "sc.marketing": "Campaigns & content ideas", "sc.reviews": "Log and reply to reviews",
      "sc.security": "Access & privacy checklist",

      "menu.lede": "Keep the current menu up to date — change prices, mark dishes sold out, add new dishes. Everyone sees the change straight away.",
      "menu.search": "Search dishes…", "menu.filterLabel": "Category",
      "menu.allCategories": "All categories", "menu.uncategorised": "Other",
      "menu.addDish": "+ Add dish",
      "menu.summary": "{total} on the menu · {avail} available · {sold} sold out",
      "menu.empty": "No dishes yet — add your first one.",
      "menu.noMatch": "No dishes match that search.",
      "menu.available": "Available", "menu.soldOut": "Sold out",
      "menu.addTitle": "Add a dish", "menu.editTitle": "Edit dish",
      "menu.field.name": "Dish name", "menu.field.category": "Category", "menu.field.price": "Price ($)",
      "menu.field.description": "Description (optional)", "menu.field.available": "Available today",
      "menu.confirmDelete": "Delete \"{name}\" from the menu?",
      "menu.needName": "Please enter a dish name.",
      "menu.needPrice": "Enter a price of 0 or more (numbers only).",

      "sop.lede": "Ready-to-use procedures your team can follow without you writing them out again. Tap a procedure to open its checklist.",
      "sop.search": "Search procedures…", "sop.allCategories": "All categories",
      "sop.noMatch": "No procedures match that search.",

      "finance.lede": "Quick calculators for the numbers you check most — not a replacement for your accountant, just fast answers while you're deciding.",
      "calc.fc.title": "Food cost %", "calc.fc.formula": "Food cost ÷ sales × 100",
      "calc.fc.cost": "Food cost ($)", "calc.fc.costPh": "e.g. 4.50",
      "calc.fc.price": "Menu sales price ($)", "calc.fc.pricePh": "e.g. 15.00",
      "calc.pm.title": "Profit margin", "calc.pm.formula": "(Revenue − cost) ÷ revenue × 100",
      "calc.pm.rev": "Revenue ($)", "calc.pm.revPh": "e.g. 1200", "calc.pm.cost": "Total cost ($)", "calc.pm.costPh": "e.g. 780",
      "calc.mp.title": "Menu price suggestion", "calc.mp.formula": "Ingredient cost ÷ target food cost %",
      "calc.mp.cost": "Ingredient cost per dish ($)", "calc.mp.costPh": "e.g. 5.20",
      "calc.mp.target": "Target food cost %", "calc.mp.result": "Suggested price",
      "calc.lc.title": "Labour cost %", "calc.lc.formula": "Labour cost ÷ sales × 100",
      "calc.lc.labour": "Labour cost this period ($)", "calc.lc.labourPh": "e.g. 3200",
      "calc.lc.sales": "Sales this period ($)", "calc.lc.salesPh": "e.g. 11000",

      "staff.lede": "Track where each team member sits, from first day to fully active, and flag anyone who still needs to confirm an SOP.",
      "staff.empty": "Empty", "staff.flag": "SOP sign-off pending",
      "staff.moveTo": "Move to {stage}", "staff.confirmSop": "Confirm SOP",
      "stage.New": "New", "stage.Onboarding": "Onboarding", "stage.Training": "Training", "stage.Active": "Active",

      "marketing.lede": "One place to plan what's coming, instead of ideas scattered across your phone.",
      "marketing.campaigns": "Campaigns", "marketing.addCampaign": "Add a campaign",
      "marketing.name": "Campaign name", "marketing.channelPh": "Channel (e.g. Instagram)", "marketing.offerPh": "Offer / idea",
      "marketing.addBtn": "Add campaign", "marketing.channel": "Channel:", "marketing.offer": "Offer:",
      "marketing.noCampaigns": "No campaigns yet.",
      "marketing.ideas": "Content ideas", "marketing.ideaPh": "Jot down a content idea…", "marketing.noIdeas": "No ideas yet.",
      "status.Planning": "Planning", "status.Scheduled": "Scheduled", "status.Live": "Live", "status.Done": "Done",

      "reviews.lede": "See what customers are saying. Open your review page online to read the latest, then record the ones that matter here so the whole team can see and reply.",
      "reviews.add": "+ Log a review", "reviews.openOnline": "⭐ Open reviews online",
      "reviews.note": "Reviews aren't pulled in automatically — they're added by hand here.",
      "reviews.empty": "No reviews logged yet.",
      "reviews.summary": "Average {avg} ★ · {count} · {need} waiting for a reply",
      "reviews.count.one": "{n} review", "reviews.count.other": "{n} reviews",
      "reviews.needsReply": "Needs reply", "reviews.replied": "Replied",
      "reviews.markReplied": "Mark replied", "reviews.markNotReplied": "Mark not replied",
      "reviews.addTitle": "Log a review", "reviews.editTitle": "Edit review",
      "reviews.field.source": "Where was it posted?", "reviews.field.rating": "Rating", "reviews.field.date": "Date",
      "reviews.field.name": "Reviewer name (optional)", "reviews.field.text": "What they said",
      "reviews.field.replied": "We have replied",
      "reviews.confirmDelete": "Delete this review?",
      "reviews.needRating": "Choose a star rating (1–5).",
      "reviews.needDate": "Choose the date of the review.",
      "reviews.starsLabel": "{n} out of 5 stars",
      "source.Google": "Google", "source.Facebook": "Facebook", "source.TripAdvisor": "TripAdvisor", "source.Other": "Other",

      "links.title": "Website and review links",
      "links.hint": "Paste the full web address. Only http and https links are accepted.",
      "links.website": "Restaurant website",
      "links.reviews": "Reviews page (for example, your Google reviews link)",
      "links.notSetWebsite": "No website address is set yet. Add it here and the button will open it.",
      "links.notSetReviews": "No reviews link is set yet. Add it here and the button will open it.",
      "links.invalid": "That doesn't look like a valid web address.",

      "security.title": "Security & Privacy",
      "security.lede": "Not a technical security system — simple habits for keeping staff and customer information appropriately protected.",
      "security.checklist": "Access & privacy checklist", "security.incidents": "Incident log",
      "security.whatHappened": "What happened?", "security.logIt": "Log it", "security.noIncidents": "No incidents logged.",

      "fb.title": "How is SecureManager working for you?",
      "fb.hint": "Tell us what's confusing, missing, or great. Please don't include passwords or customer details.",
      "fb.rating": "Overall rating", "fb.placeholder": "What would make this more useful?",
      "fb.needInput": "Add a rating or a few words first.",
      "fb.sent": "Thanks — your feedback was sent.",
      "fb.failed": "Couldn't send right now. Please try again later."
    },

    vi: {
      "nav.label": "Các mục",
      "nav.dashboard": "Tổng quan", "nav.menu": "Thực đơn", "nav.sop": "Quy trình (SOP)", "nav.finance": "Tài chính",
      "nav.staff": "Nhân viên", "nav.marketing": "Marketing", "nav.reviews": "Đánh giá", "nav.security": "Bảo mật",
      "lang.label": "Ngôn ngữ",

      "common.signOut": "Đăng xuất",
      "common.signedInAs": "Đang đăng nhập: {email}",
      "common.feedback": "💬 Gửi góp ý",
      "common.internal": "Công cụ nội bộ — chỉ dành cho nhân viên Cơm Nhà",
      "common.add": "Thêm", "common.save": "Lưu", "common.cancel": "Hủy", "common.delete": "Xóa",
      "common.send": "Gửi", "common.edit": "Sửa", "common.refresh": "Tải lại",
      "common.updateReady": "Đã có phiên bản mới của SecureManager.",
      "common.sampleNote": "Dữ liệu mẫu chỉ để minh họa — hãy thay thực đơn, nhân viên và chiến dịch mẫu bằng thông tin thật của quán.",

      "sync.connecting": "Đang kết nối…", "sync.synced": "● Đã đồng bộ", "sync.offline": "● Ngoại tuyến — thay đổi sẽ được đồng bộ sau",

      "dash.visitWebsite": "🌐 Mở website",
      "dash.checkReviews": "⭐ Xem đánh giá gần đây",
      "dash.editLinks": "✎ Sửa liên kết",
      "dash.lede": "Một nơi cho quy trình, số liệu, nhân sự và kế hoạch giúp Cơm Nhà vận hành — để không điều quan trọng nào chỉ nằm trong đầu bạn.",
      "dash.jump": "Đi nhanh đến mục",

      "stat.openPriorities": "Việc ưu tiên chưa xong", "stat.thisWeek": "Tuần này",
      "stat.menu": "Món đang bán", "stat.menuNote": "{total} món trong thực đơn",
      "stat.reviews": "Điểm đánh giá trung bình", "stat.reviewsNote": "{n} đang chờ phản hồi", "stat.noReviews": "Chưa có đánh giá nào",
      "stat.onboarding": "Nhân viên đang làm quen", "stat.seeStaff": "Xem bảng nhân viên",

      "priorities.title": "Việc ưu tiên trong tuần",
      "priorities.placeholder": "Thêm việc ưu tiên cho tuần này…",
      "priorities.empty": "Chưa có việc ưu tiên — hãy thêm bên dưới.",
      "tag.high": "Cao", "tag.med": "Vừa", "tag.low": "Thấp",

      "dfin.title": "Kiểm tra tài chính nhanh",
      "dfin.intro": "Nhập doanh thu và chi phí nguyên liệu hôm nay để xem nhanh — mục Tài chính còn có công cụ tính lợi nhuận, giá bán và chi phí nhân công.",
      "dfin.sales": "Doanh thu ($)", "dfin.salesPh": "ví dụ: 1200",
      "dfin.foodCost": "Chi phí nguyên liệu ($)", "dfin.foodCostPh": "ví dụ: 360",
      "dfin.foodCostPct": "Tỷ lệ chi phí nguyên liệu",
      "dfin.goalTitle": "Mục tiêu doanh thu", "dfin.goal": "Mục tiêu ($)", "dfin.goalPh": "ví dụ: 2000",
      "dfin.stillNeeded": "Còn thiếu", "dfin.goalReached": "Đã đạt mục tiêu",
      "dfin.goalNoteEmpty": "Đặt mục tiêu doanh thu ở trên để theo dõi tiến độ.",
      "dfin.goalNoteMet": "🎉 {sales} trên {goal} — đã đạt mục tiêu.",
      "dfin.goalNoteProgress": "Hiện có {sales} trên {goal} ({pct}%).",
      "dfin.open": "Mở mục Tài chính →",

      "sc.menu": "Món ăn, giá và tình trạng", "sc.sop": "Mở cửa, đóng cửa, vệ sinh và hơn thế",
      "sc.finance": "Chi phí nguyên liệu, lợi nhuận và giá bán", "sc.staff": "Làm quen và đào tạo",
      "sc.marketing": "Chiến dịch và ý tưởng nội dung", "sc.reviews": "Ghi nhận và phản hồi đánh giá",
      "sc.security": "Danh sách kiểm tra truy cập và riêng tư",

      "menu.lede": "Giữ thực đơn luôn cập nhật — đổi giá, đánh dấu hết món, thêm món mới. Mọi người sẽ thấy thay đổi ngay.",
      "menu.search": "Tìm món…", "menu.filterLabel": "Danh mục",
      "menu.allCategories": "Tất cả danh mục", "menu.uncategorised": "Khác",
      "menu.addDish": "+ Thêm món",
      "menu.summary": "{total} món · {avail} đang bán · {sold} hết hàng",
      "menu.empty": "Chưa có món nào — hãy thêm món đầu tiên.",
      "menu.noMatch": "Không có món nào khớp.",
      "menu.available": "Đang bán", "menu.soldOut": "Hết hàng",
      "menu.addTitle": "Thêm món", "menu.editTitle": "Sửa món",
      "menu.field.name": "Tên món", "menu.field.category": "Danh mục", "menu.field.price": "Giá ($)",
      "menu.field.description": "Mô tả (không bắt buộc)", "menu.field.available": "Đang bán hôm nay",
      "menu.confirmDelete": "Xóa \"{name}\" khỏi thực đơn?",
      "menu.needName": "Vui lòng nhập tên món.",
      "menu.needPrice": "Nhập giá từ 0 trở lên (chỉ nhập số).",

      "sop.lede": "Các quy trình có sẵn để nhóm của bạn làm theo mà không cần viết lại. Chạm vào một quy trình để mở danh sách kiểm tra.",
      "sop.search": "Tìm quy trình…", "sop.allCategories": "Tất cả danh mục",
      "sop.noMatch": "Không có quy trình nào khớp.",

      "finance.lede": "Máy tính nhanh cho những con số bạn xem nhiều nhất — không thay thế kế toán, chỉ giúp có câu trả lời nhanh khi bạn cần quyết định.",
      "calc.fc.title": "Tỷ lệ chi phí nguyên liệu", "calc.fc.formula": "Chi phí nguyên liệu ÷ doanh thu × 100",
      "calc.fc.cost": "Chi phí nguyên liệu ($)", "calc.fc.costPh": "ví dụ: 4.50",
      "calc.fc.price": "Giá bán trên thực đơn ($)", "calc.fc.pricePh": "ví dụ: 15.00",
      "calc.pm.title": "Biên lợi nhuận", "calc.pm.formula": "(Doanh thu − chi phí) ÷ doanh thu × 100",
      "calc.pm.rev": "Doanh thu ($)", "calc.pm.revPh": "ví dụ: 1200", "calc.pm.cost": "Tổng chi phí ($)", "calc.pm.costPh": "ví dụ: 780",
      "calc.mp.title": "Gợi ý giá bán", "calc.mp.formula": "Chi phí nguyên liệu ÷ tỷ lệ chi phí mục tiêu",
      "calc.mp.cost": "Chi phí nguyên liệu mỗi món ($)", "calc.mp.costPh": "ví dụ: 5.20",
      "calc.mp.target": "Tỷ lệ chi phí nguyên liệu mục tiêu (%)", "calc.mp.result": "Giá gợi ý",
      "calc.lc.title": "Tỷ lệ chi phí nhân công", "calc.lc.formula": "Chi phí nhân công ÷ doanh thu × 100",
      "calc.lc.labour": "Chi phí nhân công trong kỳ ($)", "calc.lc.labourPh": "ví dụ: 3200",
      "calc.lc.sales": "Doanh thu trong kỳ ($)", "calc.lc.salesPh": "ví dụ: 11000",

      "staff.lede": "Theo dõi từng thành viên từ ngày đầu đến khi làm việc đầy đủ, và đánh dấu ai còn cần xác nhận quy trình (SOP).",
      "staff.empty": "Trống", "staff.flag": "Chờ xác nhận SOP",
      "staff.moveTo": "Chuyển sang {stage}", "staff.confirmSop": "Xác nhận SOP",
      "stage.New": "Mới", "stage.Onboarding": "Làm quen", "stage.Training": "Đào tạo", "stage.Active": "Chính thức",

      "marketing.lede": "Một nơi để lên kế hoạch cho những gì sắp tới, thay vì ý tưởng rải rác trong điện thoại.",
      "marketing.campaigns": "Chiến dịch", "marketing.addCampaign": "Thêm chiến dịch",
      "marketing.name": "Tên chiến dịch", "marketing.channelPh": "Kênh (ví dụ: Instagram)", "marketing.offerPh": "Ưu đãi / ý tưởng",
      "marketing.addBtn": "Thêm chiến dịch", "marketing.channel": "Kênh:", "marketing.offer": "Ưu đãi:",
      "marketing.noCampaigns": "Chưa có chiến dịch nào.",
      "marketing.ideas": "Ý tưởng nội dung", "marketing.ideaPh": "Ghi nhanh một ý tưởng nội dung…", "marketing.noIdeas": "Chưa có ý tưởng nào.",
      "status.Planning": "Đang lên kế hoạch", "status.Scheduled": "Đã lên lịch", "status.Live": "Đang chạy", "status.Done": "Hoàn thành",

      "reviews.lede": "Xem khách hàng nói gì về quán. Mở trang đánh giá trực tuyến để đọc những đánh giá mới nhất, rồi ghi lại những đánh giá quan trọng tại đây để cả nhóm cùng xem và phản hồi.",
      "reviews.add": "+ Ghi nhận đánh giá", "reviews.openOnline": "⭐ Mở đánh giá trực tuyến",
      "reviews.note": "Đánh giá không được lấy về tự động — bạn thêm thủ công tại đây.",
      "reviews.empty": "Chưa có đánh giá nào được ghi nhận.",
      "reviews.summary": "Trung bình {avg} ★ · {count} · {need} đang chờ phản hồi",
      "reviews.count.one": "{n} đánh giá", "reviews.count.other": "{n} đánh giá",
      "reviews.needsReply": "Cần phản hồi", "reviews.replied": "Đã phản hồi",
      "reviews.markReplied": "Đánh dấu đã phản hồi", "reviews.markNotReplied": "Bỏ đánh dấu đã phản hồi",
      "reviews.addTitle": "Ghi nhận đánh giá", "reviews.editTitle": "Sửa đánh giá",
      "reviews.field.source": "Đăng ở đâu?", "reviews.field.rating": "Số sao", "reviews.field.date": "Ngày",
      "reviews.field.name": "Tên người đánh giá (không bắt buộc)", "reviews.field.text": "Nội dung đánh giá",
      "reviews.field.replied": "Chúng ta đã phản hồi",
      "reviews.confirmDelete": "Xóa đánh giá này?",
      "reviews.needRating": "Hãy chọn số sao (1–5).",
      "reviews.needDate": "Hãy chọn ngày của đánh giá.",
      "reviews.starsLabel": "{n} trên 5 sao",
      "source.Google": "Google", "source.Facebook": "Facebook", "source.TripAdvisor": "TripAdvisor", "source.Other": "Khác",

      "links.title": "Liên kết website và đánh giá",
      "links.hint": "Dán địa chỉ web đầy đủ. Chỉ chấp nhận liên kết http và https.",
      "links.website": "Website của quán",
      "links.reviews": "Trang đánh giá (ví dụ: liên kết đánh giá Google)",
      "links.notSetWebsite": "Chưa có địa chỉ website. Hãy nhập tại đây, nút này sẽ mở website đó.",
      "links.notSetReviews": "Chưa có liên kết đánh giá. Hãy nhập tại đây, nút này sẽ mở trang đó.",
      "links.invalid": "Địa chỉ web này không hợp lệ.",

      "security.title": "Bảo mật & Riêng tư",
      "security.lede": "Đây không phải hệ thống bảo mật kỹ thuật — chỉ là những thói quen đơn giản để bảo vệ thông tin nhân viên và khách hàng đúng cách.",
      "security.checklist": "Danh sách kiểm tra truy cập & riêng tư", "security.incidents": "Nhật ký sự cố",
      "security.whatHappened": "Chuyện gì đã xảy ra?", "security.logIt": "Ghi lại", "security.noIncidents": "Chưa có sự cố nào được ghi.",

      "fb.title": "SecureManager dùng có ổn với bạn không?",
      "fb.hint": "Hãy cho chúng tôi biết điều gì khó hiểu, còn thiếu hoặc rất tốt. Vui lòng không ghi mật khẩu hoặc thông tin khách hàng.",
      "fb.rating": "Đánh giá chung", "fb.placeholder": "Điều gì sẽ giúp ứng dụng hữu ích hơn?",
      "fb.needInput": "Hãy chọn số sao hoặc viết vài từ trước.",
      "fb.sent": "Cảm ơn — góp ý của bạn đã được gửi.",
      "fb.failed": "Không gửi được lúc này. Vui lòng thử lại sau."
    }
  };

  // ======================================================================
  // Starter content, in both languages. The first device to open the app
  // publishes its language's version; after that it is the team's own data.
  // ======================================================================
  const SAMPLES = {
    en: {
      priorities: [
        { text: "Confirm supplier delivery for Saturday", tag: "high", done: false },
        { text: "Review till reconciliation from last weekend", tag: "med", done: false },
        { text: "Finalise Lunar New Year set menu pricing", tag: "high", done: false },
        { text: "Check in with new kitchen hire", tag: "low", done: true }
      ],
      staff: [
        { name: "Mai", role: "Kitchen Hand", stage: "New", sopFlag: true },
        { name: "Tuấn", role: "Front of House", stage: "Onboarding", sopFlag: true },
        { name: "Linh", role: "Line Cook", stage: "Training", sopFlag: false },
        { name: "Huy", role: "Front of House", stage: "Training", sopFlag: true },
        { name: "Anh", role: "Line Cook", stage: "Active", sopFlag: false },
        { name: "Phương", role: "Floor Supervisor", stage: "Active", sopFlag: false }
      ],
      campaigns: [
        { title: "Lunar New Year Set Menu", channel: "Instagram / Facebook", offer: "Set-menu promotion, 4 courses", status: "Planning" },
        { title: "Weekend Family Combo", channel: "In-store signage", offer: "Combo pricing for tables of 4+", status: "Scheduled" },
        { title: "Behind the Kitchen Reels", channel: "Instagram", offer: "Short clips of prep & cooking", status: "Live" }
      ],
      ideas: [
        "Customer shout-out of the week on Instagram Stories",
        "Short video on how the broth is made",
        "Loyalty stamp card for regulars"
      ],
      security: [
        { title: "Review staff system access", note: "Check who can access POS, bookings and accounts", done: false },
        { title: "Remove access for departed staff", note: "Disable logins the same day someone leaves", done: false },
        { title: "No shared logins", note: "Every staff member uses their own account", done: true },
        { title: "Limit customer data collected", note: "Only keep what you actually use (name, phone, notes)", done: true },
        { title: "Check new apps before connecting accounts", note: "Confirm a new tool is trustworthy before linking email or payments", done: false },
        { title: "Report suspicious emails immediately", note: "Don't click links in unexpected messages", done: false }
      ],
      incidents: [
        { date: "2026-08-14", desc: "Staff member reported a suspicious email asking for banking details — reported, not actioned." }
      ],
      menu: [
        { id: "m1", name: "Cơm tấm sườn bì chả", category: "Mains", price: 17.5, description: "Broken rice with grilled pork chop, shredded pork skin and steamed egg meatloaf", available: true },
        { id: "m2", name: "Cơm gà xối mỡ", category: "Mains", price: 16, description: "Crispy fried chicken on rice with pickles and fish sauce", available: true },
        { id: "m3", name: "Phở bò", category: "Noodles", price: 16.5, description: "Beef noodle soup with herbs and lime", available: true },
        { id: "m4", name: "Bún chả", category: "Noodles", price: 17, description: "Vermicelli with grilled pork patties and dipping sauce", available: true },
        { id: "m5", name: "Gỏi cuốn (2 rolls)", category: "Starters", price: 9.5, description: "Fresh rice-paper rolls with prawn, pork and herbs", available: true },
        { id: "m6", name: "Cà phê sữa đá", category: "Drinks", price: 5.5, description: "Vietnamese iced coffee with condensed milk", available: true },
        { id: "m7", name: "Chè ba màu", category: "Desserts", price: 7, description: "Three-colour dessert with beans, jelly and coconut milk", available: false }
      ]
    },
    vi: {
      priorities: [
        { text: "Xác nhận giao hàng của nhà cung cấp vào thứ Bảy", tag: "high", done: false },
        { text: "Xem lại đối chiếu tiền mặt của cuối tuần trước", tag: "med", done: false },
        { text: "Chốt giá thực đơn set Tết Nguyên Đán", tag: "high", done: false },
        { text: "Hỏi thăm nhân viên bếp mới", tag: "low", done: true }
      ],
      staff: [
        { name: "Mai", role: "Phụ bếp", stage: "New", sopFlag: true },
        { name: "Tuấn", role: "Phục vụ phòng ăn", stage: "Onboarding", sopFlag: true },
        { name: "Linh", role: "Đầu bếp", stage: "Training", sopFlag: false },
        { name: "Huy", role: "Phục vụ phòng ăn", stage: "Training", sopFlag: true },
        { name: "Anh", role: "Đầu bếp", stage: "Active", sopFlag: false },
        { name: "Phương", role: "Giám sát phòng ăn", stage: "Active", sopFlag: false }
      ],
      campaigns: [
        { title: "Thực đơn set Tết Nguyên Đán", channel: "Instagram / Facebook", offer: "Khuyến mãi thực đơn set, 4 món", status: "Planning" },
        { title: "Combo gia đình cuối tuần", channel: "Biển hiệu tại quán", offer: "Giá combo cho bàn từ 4 người", status: "Scheduled" },
        { title: "Video hậu trường nhà bếp", channel: "Instagram", offer: "Video ngắn về sơ chế và nấu ăn", status: "Live" }
      ],
      ideas: [
        "Giới thiệu khách hàng của tuần trên Instagram Stories",
        "Video ngắn cách nấu nước dùng",
        "Thẻ tích điểm cho khách quen"
      ],
      security: [
        { title: "Xem lại quyền truy cập hệ thống của nhân viên", note: "Kiểm tra ai có thể truy cập POS, đặt bàn và tài khoản", done: false },
        { title: "Thu hồi quyền truy cập của nhân viên đã nghỉ", note: "Vô hiệu hóa tài khoản ngay trong ngày nhân viên nghỉ", done: false },
        { title: "Không dùng chung tài khoản", note: "Mỗi nhân viên dùng tài khoản riêng của mình", done: true },
        { title: "Hạn chế dữ liệu khách hàng thu thập", note: "Chỉ giữ những gì thực sự dùng (tên, số điện thoại, ghi chú)", done: true },
        { title: "Kiểm tra ứng dụng mới trước khi kết nối tài khoản", note: "Xác nhận công cụ mới đáng tin trước khi liên kết email hoặc thanh toán", done: false },
        { title: "Báo ngay các email đáng ngờ", note: "Không bấm vào liên kết trong tin nhắn bất ngờ", done: false }
      ],
      incidents: [
        { date: "2026-08-14", desc: "Một nhân viên báo có email đáng ngờ yêu cầu thông tin ngân hàng — đã báo cáo, không làm theo." }
      ],
      menu: [
        { id: "m1", name: "Cơm tấm sườn bì chả", category: "Món chính", price: 17.5, description: "Cơm tấm với sườn nướng, bì và chả trứng hấp", available: true },
        { id: "m2", name: "Cơm gà xối mỡ", category: "Món chính", price: 16, description: "Gà chiên giòn ăn với cơm, đồ chua và nước mắm", available: true },
        { id: "m3", name: "Phở bò", category: "Phở & bún", price: 16.5, description: "Phở bò kèm rau thơm và chanh", available: true },
        { id: "m4", name: "Bún chả", category: "Phở & bún", price: 17, description: "Bún với chả nướng và nước chấm", available: true },
        { id: "m5", name: "Gỏi cuốn (2 cuốn)", category: "Khai vị", price: 9.5, description: "Gỏi cuốn tôm thịt với rau thơm", available: true },
        { id: "m6", name: "Cà phê sữa đá", category: "Đồ uống", price: 5.5, description: "Cà phê pha phin với sữa đặc, uống với đá", available: true },
        { id: "m7", name: "Chè ba màu", category: "Tráng miệng", price: 7, description: "Chè ba màu với đậu, thạch và nước cốt dừa", available: false }
      ]
    }
  };

  // The SOP library is built into the app (same order in both languages, so ticked steps line up).
  const SOPS = {
    en: [
      { name: "Opening Checklist — Kitchen & Floor", category: "Opening & Closing", responsible: "Shift Supervisor", review: "Reviewed monthly",
        steps: ["Unlock and disarm premises; check for overnight issues", "Turn on kitchen equipment and allow warm-up time", "Check fridge and freezer temperatures, log results", "Set up prep stations with the day's mise en place", "Restock front-of-house condiments, napkins and menus", "Brief staff on today's specials and any 86'd items"] },
      { name: "Closing Checklist — Kitchen & Floor", category: "Opening & Closing", responsible: "Shift Supervisor", review: "Reviewed monthly",
        steps: ["Store or discard perishable prep according to date labels", "Clean and sanitise all food-contact surfaces", "Empty and clean grease traps if scheduled", "Cash up and reconcile till against POS report", "Set alarm and lock all doors and windows", "Note any equipment issues for the next shift"] },
      { name: "Daily Cleaning & Sanitation", category: "Cleaning", responsible: "All Staff", review: "Reviewed quarterly",
        steps: ["Sanitise chopping boards and utensils between raw and cooked use", "Wipe down and sanitise all prep surfaces after each use", "Sweep and mop kitchen floor at end of shift", "Clean bathroom and restock supplies", "Empty bins and replace liners", "Sign off on the cleaning log"] },
      { name: "Food Preparation & Storage", category: "Food Safety", responsible: "Kitchen Staff", review: "Reviewed quarterly",
        steps: ["Wash hands and change gloves between tasks", "Label and date all prepped items before storage", "Store raw meat below ready-to-eat items in the fridge", "Follow FIFO (first in, first out) when using stock", "Discard any item past its use-by date", "Record fridge/freezer temperature checks twice daily"] },
      { name: "Customer Complaint Handling", category: "Customer Service", responsible: "Floor Manager", review: "Reviewed every 6 months",
        steps: ["Listen fully before responding — don't interrupt", "Apologise for the experience, regardless of fault", "Offer a practical resolution (remake, discount, or refund)", "Log the complaint and resolution in the incident log", "Follow up with the customer if a remake was promised", "Flag repeated issues to the manager for review"] },
      { name: "New Staff Onboarding", category: "Staff", responsible: "Manager", review: "Reviewed every 6 months",
        steps: ["Complete employment paperwork and system access setup", "Walk through opening/closing checklists together", "Assign a buddy for the first two shifts", "Review food safety and hygiene expectations", "Confirm understanding of relevant SOPs (sign-off)", "Schedule a 2-week check-in"] },
      { name: "Cash Handling & End-of-Day Reconciliation", category: "Finance", responsible: "Shift Supervisor", review: "Reviewed monthly",
        steps: ["Count float at start of shift and record amount", "Record all manual discounts or voids with a reason", "Reconcile till total against POS summary at close", "Report and investigate any discrepancy over $10", "Store cash securely and log the deposit", "Sign the reconciliation sheet"] },
      { name: "Emergency & Incident Reporting", category: "Emergency", responsible: "All Staff", review: "Reviewed every 6 months",
        steps: ["Ensure immediate safety of staff and customers first", "Call emergency services if required", "Notify the manager as soon as it is safe to do so", "Record what happened, when, and who was involved", "Note any follow-up action required", "Review the incident at the next team meeting"] }
    ],
    vi: [
      { name: "Checklist mở cửa — Bếp & Phòng ăn", category: "Mở cửa & Đóng cửa", responsible: "Giám sát ca", review: "Xem xét hằng tháng",
        steps: ["Mở khóa và tắt báo động; kiểm tra sự cố qua đêm", "Bật thiết bị bếp và chờ làm nóng", "Kiểm tra nhiệt độ tủ lạnh và tủ đông, ghi lại kết quả", "Chuẩn bị khu sơ chế với nguyên liệu sơ chế sẵn trong ngày", "Bổ sung gia vị, khăn giấy và thực đơn ở khu phục vụ", "Thông báo cho nhân viên các món đặc biệt hôm nay và các món đã hết"] },
      { name: "Checklist đóng cửa — Bếp & Phòng ăn", category: "Mở cửa & Đóng cửa", responsible: "Giám sát ca", review: "Xem xét hằng tháng",
        steps: ["Cất hoặc bỏ thực phẩm sơ chế theo nhãn ngày", "Vệ sinh và khử trùng mọi bề mặt tiếp xúc với thực phẩm", "Vệ sinh bẫy mỡ nếu đến lịch", "Kết sổ tiền mặt và đối chiếu với báo cáo POS", "Bật báo động và khóa tất cả cửa ra vào, cửa sổ", "Ghi chú các sự cố thiết bị cho ca sau"] },
      { name: "Vệ sinh và khử trùng hằng ngày", category: "Vệ sinh", responsible: "Toàn bộ nhân viên", review: "Xem xét hằng quý",
        steps: ["Khử trùng thớt và dụng cụ giữa lúc dùng cho đồ sống và đồ chín", "Lau và khử trùng mọi bề mặt sơ chế sau mỗi lần sử dụng", "Quét và lau sàn bếp vào cuối ca", "Vệ sinh nhà vệ sinh và bổ sung vật dụng", "Đổ rác và thay túi rác mới", "Ký xác nhận vào sổ vệ sinh"] },
      { name: "Sơ chế và bảo quản thực phẩm", category: "An toàn thực phẩm", responsible: "Nhân viên bếp", review: "Xem xét hằng quý",
        steps: ["Rửa tay và thay găng giữa các công việc", "Dán nhãn và ghi ngày lên mọi món sơ chế trước khi bảo quản", "Để thịt sống ở ngăn dưới, bên dưới đồ ăn liền trong tủ lạnh", "Áp dụng nguyên tắc nhập trước, xuất trước (FIFO) khi dùng nguyên liệu", "Bỏ mọi thực phẩm đã quá hạn sử dụng", "Ghi nhiệt độ tủ lạnh/tủ đông hai lần mỗi ngày"] },
      { name: "Xử lý khiếu nại của khách", category: "Chăm sóc khách hàng", responsible: "Quản lý phòng ăn", review: "Xem xét 6 tháng một lần",
        steps: ["Lắng nghe đầy đủ trước khi trả lời — không ngắt lời", "Xin lỗi vì trải nghiệm của khách, bất kể lỗi của ai", "Đề xuất cách giải quyết thực tế (làm lại món, giảm giá hoặc hoàn tiền)", "Ghi khiếu nại và cách giải quyết vào nhật ký sự cố", "Liên hệ lại với khách nếu đã hứa làm lại món", "Báo cho quản lý những vấn đề lặp lại để xem xét"] },
      { name: "Đào tạo nhân viên mới", category: "Nhân viên", responsible: "Quản lý", review: "Xem xét 6 tháng một lần",
        steps: ["Hoàn tất giấy tờ tuyển dụng và thiết lập quyền truy cập hệ thống", "Cùng đi qua các checklist mở cửa/đóng cửa", "Chỉ định một người kèm cặp trong hai ca đầu", "Xem lại yêu cầu về vệ sinh và an toàn thực phẩm", "Xác nhận đã hiểu các quy trình liên quan (ký xác nhận)", "Lên lịch gặp trao đổi sau 2 tuần"] },
      { name: "Quản lý tiền mặt và đối chiếu cuối ngày", category: "Tài chính", responsible: "Giám sát ca", review: "Xem xét hằng tháng",
        steps: ["Đếm tiền đầu ca và ghi lại số tiền", "Ghi mọi khoản giảm giá hoặc hủy món thủ công kèm lý do", "Đối chiếu tổng tiền trong két với báo cáo POS khi đóng cửa", "Báo cáo và điều tra mọi chênh lệch trên $10", "Cất tiền mặt an toàn và ghi lại khoản nộp", "Ký vào phiếu đối chiếu"] },
      { name: "Xử lý và báo cáo sự cố khẩn cấp", category: "Khẩn cấp", responsible: "Toàn bộ nhân viên", review: "Xem xét 6 tháng một lần",
        steps: ["Trước tiên, đảm bảo an toàn cho nhân viên và khách hàng", "Gọi dịch vụ khẩn cấp nếu cần", "Báo cho quản lý ngay khi an toàn", "Ghi lại điều gì đã xảy ra, khi nào và ai liên quan", "Ghi chú các việc cần xử lý tiếp theo", "Xem xét sự cố trong cuộc họp nhóm tiếp theo"] }
    ]
  };

  // ======================================================================
  // Basics: storage, language, small helpers
  // ======================================================================
  const SM = window.SM = window.SM || { push: null, applyingRemote: false, keys: [] };
  SM.langListeners = [];
  SM.pending = SM.pending || new Set();     // changes made before the sync script started

  function safeGet(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (e) { return fallback; }
  }
  function safeSet(key, value) {
    const raw = JSON.stringify(value);
    try { localStorage.setItem(key, raw); } catch (e) {}
    if (SM.applyingRemote) return;
    if (SM.push) SM.push(key, raw); else SM.pending.add(key);
  }

  const LANGS = ["en", "vi"];
  function readCookie(name) {
    const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[1]) : "";
  }
  function initialLang() {
    let l = readCookie("sm_lang");
    if (!LANGS.includes(l)) { try { l = localStorage.getItem("sm_lang") || ""; } catch (e) { l = ""; } }
    return LANGS.includes(l) ? l : "en";
  }
  let lang = initialLang();

  function t(key, vars) {
    const own = I18N[lang] && I18N[lang][key];
    let s = own !== undefined ? own : (I18N.en[key] !== undefined ? I18N.en[key] : key);
    if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? vars[k] : m));
    return s;
  }
  const plural = (base, n) => t(base + (n === 1 ? ".one" : ".other"), { n });
  SM.t = t;
  SM.onLang = (fn) => SM.langListeners.push(fn);

  const $ = (id) => document.getElementById(id);
  function escapeHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  const newId = () => Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-3);
  const money = (n) => "$" + (Number(n) || 0).toFixed(2);
  function todayISO() {
    const d = new Date(), p = (n) => String(n).padStart(2, "0");
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate());
  }
  const locale = () => (lang === "vi" ? "vi-VN" : undefined);
  function fmtDate(iso) {
    const d = new Date(String(iso) + "T00:00:00");
    return isNaN(d) ? String(iso || "") : d.toLocaleDateString(locale(), { year: "numeric", month: "short", day: "numeric" });
  }

  // ---- dialogs
  function openModal(id) {
    const m = $(id);
    m.classList.add("open");
    const first = m.querySelector("input:not([type=hidden]):not([type=checkbox]), textarea, select");
    if (first) setTimeout(() => first.focus(), 30);
  }
  function closeModals() { document.querySelectorAll(".fb-backdrop.open").forEach((m) => m.classList.remove("open")); }
  SM.openModal = openModal;
  SM.closeModals = closeModals;
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModals(); });
  document.querySelectorAll(".fb-backdrop").forEach((b) =>
    b.addEventListener("click", (e) => { if (e.target === b) b.classList.remove("open"); }));
  document.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", closeModals));

  // ---- navigation
  const views = document.querySelectorAll(".view");
  const railItems = document.querySelectorAll(".rail-item");
  function showView(name) {
    views.forEach((v) => v.classList.toggle("active", v.id === "view-" + name));
    railItems.forEach((b) => b.classList.toggle("active", b.dataset.view === name));
    window.scrollTo(0, 0);
  }
  document.querySelectorAll("[data-view]").forEach((el) => el.addEventListener("click", () => showView(el.dataset.view)));

  // ======================================================================
  // Data (shared with everyone through the server)
  // ======================================================================
  const sample = (name) => JSON.parse(JSON.stringify(SAMPLES[lang][name]));
  let priorities = safeGet("cn_priorities", sample("priorities"));
  let sopChecks = safeGet("cn_sop_checks", {});
  let dashFinance = safeGet("cn_dash_finance", { sales: "", foodCost: "", goal: "" });
  let staff = safeGet("cn_staff", sample("staff"));
  let campaigns = safeGet("cn_campaigns", sample("campaigns"));
  let ideas = safeGet("cn_ideas", sample("ideas"));
  let secItems = safeGet("cn_security", sample("security"));
  let incidents = safeGet("cn_incidents", sample("incidents"));
  let menu = safeGet("cn_menu", sample("menu"));
  let reviews = safeGet("cn_reviews", []);
  let settings = safeGet("cn_settings", { websiteUrl: "", reviewsUrl: "" });

  const STAGES = ["New", "Onboarding", "Training", "Active"];
  const TAGS = ["high", "med", "low"];
  const STATUS_CLASS = { Planning: "planning", Scheduled: "scheduled", Live: "live", Done: "done" };

  // ======================================================================
  // Text, date, user
  // ======================================================================
  function applyStaticText() {
    document.documentElement.lang = lang;
    document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
    document.querySelectorAll("[data-i18n-ph]").forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
    document.querySelectorAll("[data-i18n-aria]").forEach((el) => el.setAttribute("aria-label", t(el.dataset.i18nAria)));
    document.querySelectorAll(".lang-switch button").forEach((b) => b.classList.toggle("active", b.dataset.lang === lang));
  }
  function renderDate() {
    $("todayDate").textContent = new Date().toLocaleDateString(locale(),
      { weekday: "long", year: "numeric", month: "long", day: "numeric" });
  }
  function renderUser() {
    $("dashUser").textContent = SM.userEmail ? t("common.signedInAs", { email: SM.userEmail }) : "";
  }
  SM.setUser = (email) => { SM.userEmail = email; renderUser(); };

  // ======================================================================
  // Dashboard: stats, links, priorities, quick finance
  // ======================================================================
  function renderStats() {
    $("statOpenPriorities").textContent = priorities.filter((p) => !p.done).length;
    $("statMenu").textContent = menu.filter((m) => m.available).length;
    $("statMenuNote").textContent = t("stat.menuNote", { total: menu.length });
    if (reviews.length) {
      const avg = reviews.reduce((s, r) => s + (Number(r.rating) || 0), 0) / reviews.length;
      $("statReviews").textContent = avg.toFixed(1);
      $("statReviewsNote").textContent = t("stat.reviewsNote", { n: reviews.filter((r) => !r.replied).length });
    } else {
      $("statReviews").textContent = "–";
      $("statReviewsNote").textContent = t("stat.noReviews");
    }
    $("statOnboarding").textContent = staff.filter((m) => m.stage === "New" || m.stage === "Onboarding").length;
  }

  // Website / review links: only http(s) addresses are ever opened.
  // Returns "" for empty, null for invalid, otherwise the cleaned address.
  function cleanUrl(raw) {
    let s = String(raw || "").trim();
    if (!s) return "";
    if (!/^[a-z][a-z0-9+.-]*:/i.test(s)) s = "https://" + s;
    try {
      const u = new URL(s);
      return (u.protocol === "http:" || u.protocol === "https:") && u.hostname.includes(".") ? u.href : null;
    } catch (e) { return null; }
  }
  function openLinks(focus) {
    $("linkWebsite").value = settings.websiteUrl || "";
    $("linkReviews").value = settings.reviewsUrl || "";
    $("linksError").textContent = "";
    let hint = t("links.hint");
    if (focus === "website") hint = t("links.notSetWebsite");
    if (focus === "reviews") hint = t("links.notSetReviews");
    $("linksHint").textContent = hint;
    openModal("linksModal");
    const field = $(focus === "reviews" ? "linkReviews" : "linkWebsite");
    setTimeout(() => field.focus(), 40);
  }
  function openConfiguredLink(which) {
    const url = cleanUrl(which === "website" ? settings.websiteUrl : settings.reviewsUrl);
    if (url) window.open(url, "_blank", "noopener");
    else openLinks(which === "website" ? "website" : "reviews");
  }
  $("visitWebsiteBtn").addEventListener("click", () => openConfiguredLink("website"));
  $("openReviewsOnlineBtn").addEventListener("click", () => openConfiguredLink("reviews"));
  document.querySelectorAll(".js-edit-links").forEach((b) => b.addEventListener("click", () => openLinks()));
  $("linksForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const website = cleanUrl($("linkWebsite").value);
    const reviewsUrl = cleanUrl($("linkReviews").value);
    if (website === null || reviewsUrl === null) { $("linksError").textContent = t("links.invalid"); return; }
    settings = { websiteUrl: website, reviewsUrl: reviewsUrl };
    safeSet("cn_settings", settings);
    closeModals();
  });

  // ---- priorities
  function renderPriorities() {
    const list = $("priorityList");
    list.innerHTML = "";
    if (!priorities.length) list.innerHTML = `<p class="empty-note">${escapeHtml(t("priorities.empty"))}</p>`;
    priorities.forEach((p, i) => {
      const tag = TAGS.includes(p.tag) ? p.tag : "med";
      const row = document.createElement("div");
      row.className = "priority-row" + (p.done ? " done" : "");
      row.innerHTML = `
        <input type="checkbox" ${p.done ? "checked" : ""}>
        <span class="p-text">${escapeHtml(p.text)}</span>
        <span class="tag ${tag}">${escapeHtml(t("tag." + tag))}</span>`;
      row.querySelector("input").addEventListener("change", (e) => {
        priorities[i].done = e.target.checked;
        safeSet("cn_priorities", priorities);
        renderPriorities();
      });
      list.appendChild(row);
    });
    renderStats();
  }
  $("addPriorityBtn").addEventListener("click", () => {
    const input = $("newPriorityInput");
    const val = input.value.trim();
    if (!val) return;
    priorities.push({ text: val, tag: "med", done: false });
    safeSet("cn_priorities", priorities);
    input.value = "";
    renderPriorities();
  });
  $("newPriorityInput").addEventListener("keydown", (e) => { if (e.key === "Enter") $("addPriorityBtn").click(); });

  // ---- quick finance check + sales goal
  function refreshDashFinance() {
    const sales = parseFloat(dashFinance.sales), cost = parseFloat(dashFinance.foodCost), goal = parseFloat(dashFinance.goal);
    const fcOut = $("dashFoodCostResult");
    if (sales && dashFinance.foodCost !== "" && isFinite(cost)) {
      const pct = (cost / sales) * 100;
      fcOut.textContent = pct.toFixed(1) + "%";
      fcOut.className = "cr-value " + (pct > 35 ? "warn" : "good");
    } else { fcOut.textContent = "—"; fcOut.className = "cr-value"; }

    const bar = $("dashGoalBar"), res = $("dashGoalResult"), label = $("dashGoalLabel"), note = $("dashGoalNote");
    if (goal && goal > 0) {
      const have = isFinite(sales) ? sales : 0;
      const remaining = goal - have;
      const ratio = Math.max(0, Math.min(have / goal, 1));
      bar.style.width = (ratio * 100).toFixed(0) + "%";
      if (remaining <= 0) {
        bar.style.background = "var(--herb)";
        label.textContent = t("dfin.goalReached");
        res.textContent = "+" + money(Math.abs(remaining));
        res.className = "cr-value good";
        note.textContent = t("dfin.goalNoteMet", { sales: money(have), goal: money(goal) });
      } else {
        bar.style.background = "var(--brass)";
        label.textContent = t("dfin.stillNeeded");
        res.textContent = money(remaining);
        res.className = "cr-value " + (ratio < 0.5 ? "warn" : "");
        note.textContent = t("dfin.goalNoteProgress", { sales: money(have), goal: money(goal), pct: (ratio * 100).toFixed(0) });
      }
    } else {
      bar.style.width = "0%";
      label.textContent = t("dfin.stillNeeded");
      res.textContent = "—"; res.className = "cr-value";
      note.textContent = t("dfin.goalNoteEmpty");
    }
  }
  function restoreDashFinanceInputs() {
    $("dashSales").value = dashFinance.sales || "";
    $("dashFoodCost").value = dashFinance.foodCost || "";
    $("dashGoal").value = dashFinance.goal || "";
  }
  ["dashSales", "dashFoodCost", "dashGoal"].forEach((id) => $(id).addEventListener("input", () => {
    dashFinance = { sales: $("dashSales").value, foodCost: $("dashFoodCost").value, goal: $("dashGoal").value };
    safeSet("cn_dash_finance", dashFinance);
    refreshDashFinance();
  }));

  // ======================================================================
  // Menu
  // ======================================================================
  const catKey = (c) => c || "__none__";
  function menuRowHtml(m) {
    const id = escapeHtml(m.id);
    return `
      <div class="menu-row ${m.available ? "" : "soldout"}">
        <div class="menu-info">
          <div class="menu-name">${escapeHtml(m.name)}</div>
          ${m.description ? `<div class="menu-desc">${escapeHtml(m.description)}</div>` : ""}
        </div>
        <div class="menu-price">${money(m.price)}</div>
        <button class="avail-btn ${m.available ? "on" : "off"}" type="button" data-act="toggle" data-id="${id}">${escapeHtml(t(m.available ? "menu.available" : "menu.soldOut"))}</button>
        <button class="icon-btn" type="button" data-act="edit" data-id="${id}">✎ ${escapeHtml(t("common.edit"))}</button>
      </div>`;
  }
  function renderMenu() {
    const sel = $("menuFilter");
    const prev = sel.value || "all";
    const cats = [];
    menu.forEach((m) => { const k = catKey(m.category); if (!cats.includes(k)) cats.push(k); });
    sel.innerHTML = `<option value="all">${escapeHtml(t("menu.allCategories"))}</option>` +
      cats.map((k) => `<option value="${escapeHtml(k)}">${escapeHtml(k === "__none__" ? t("menu.uncategorised") : k)}</option>`).join("");
    sel.value = (prev === "all" || cats.includes(prev)) ? prev : "all";

    const q = $("menuSearch").value.trim().toLowerCase();
    const shown = menu.filter((m) =>
      (sel.value === "all" || catKey(m.category) === sel.value) &&
      (!q || (m.name + " " + (m.description || "")).toLowerCase().includes(q)));
    const sold = menu.filter((m) => !m.available).length;
    $("menuSummary").textContent = menu.length ? t("menu.summary", { total: menu.length, avail: menu.length - sold, sold }) : "";

    const list = $("menuList");
    list.innerHTML = "";
    if (!menu.length) list.innerHTML = `<p class="empty-note" style="color:var(--cream-dim)">${escapeHtml(t("menu.empty"))}</p>`;
    else if (!shown.length) list.innerHTML = `<p class="empty-note" style="color:var(--cream-dim)">${escapeHtml(t("menu.noMatch"))}</p>`;
    else {
      const order = [];
      shown.forEach((m) => { const k = catKey(m.category); if (!order.includes(k)) order.push(k); });
      order.forEach((k) => {
        const card = document.createElement("div");
        card.className = "ticket menu-card";
        card.innerHTML = `<div class="ticket-pad"><div class="menu-cat-title">${escapeHtml(k === "__none__" ? t("menu.uncategorised") : k)}</div>` +
          shown.filter((m) => catKey(m.category) === k).map(menuRowHtml).join("") + `</div>`;
        list.appendChild(card);
      });
    }
    renderStats();
  }
  $("menuSearch").addEventListener("input", renderMenu);
  $("menuFilter").addEventListener("change", renderMenu);
  $("menuList").addEventListener("click", (e) => {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const item = menu.find((m) => m.id === b.dataset.id);
    if (!item) return;
    if (b.dataset.act === "toggle") {
      item.available = !item.available;
      safeSet("cn_menu", menu);
      renderMenu();
    } else openDish(item.id);
  });

  let editingDishId = null;
  function openDish(id) {
    editingDishId = id || null;
    const m = id ? menu.find((x) => x.id === id) : null;
    $("dishTitle").textContent = t(m ? "menu.editTitle" : "menu.addTitle");
    $("dishName").value = m ? m.name : "";
    $("dishCategory").value = m ? (m.category || "") : "";
    $("dishPrice").value = m ? m.price : "";
    $("dishDesc").value = m ? (m.description || "") : "";
    $("dishAvail").checked = m ? !!m.available : true;
    $("dishDelete").hidden = !m;
    $("dishError").textContent = "";
    const cats = [...new Set(menu.map((x) => x.category).filter(Boolean))];
    $("dishCategories").innerHTML = cats.map((c) => `<option value="${escapeHtml(c)}"></option>`).join("");
    openModal("dishModal");
  }
  $("addDishBtn").addEventListener("click", () => openDish());
  $("dishForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const name = $("dishName").value.trim();
    const price = parseFloat($("dishPrice").value);
    if (!name) { $("dishError").textContent = t("menu.needName"); return; }
    if (!isFinite(price) || price < 0) { $("dishError").textContent = t("menu.needPrice"); return; }
    const item = {
      id: editingDishId || newId(), name,
      category: $("dishCategory").value.trim(), price: Math.round(price * 100) / 100,
      description: $("dishDesc").value.trim(), available: $("dishAvail").checked,
    };
    const idx = menu.findIndex((m) => m.id === item.id);
    if (idx >= 0) menu[idx] = item; else menu.push(item);
    safeSet("cn_menu", menu);
    closeModals();
    renderMenu();
  });
  $("dishDelete").addEventListener("click", () => {
    const m = menu.find((x) => x.id === editingDishId);
    if (!m || !window.confirm(t("menu.confirmDelete", { name: m.name }))) return;
    menu = menu.filter((x) => x.id !== editingDishId);
    safeSet("cn_menu", menu);
    closeModals();
    renderMenu();
  });

  // ======================================================================
  // SOP library (built in)
  // ======================================================================
  let sopOpen = {};
  function renderSops() {
    const sops = SOPS[lang];
    const sel = $("sopFilter");
    const prev = sel.value || "all";
    const cats = [...new Set(sops.map((s) => s.category))];
    sel.innerHTML = `<option value="all">${escapeHtml(t("sop.allCategories"))}</option>` +
      cats.map((c) => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("");
    sel.value = (prev === "all" || cats.includes(prev)) ? prev : "all";

    const query = $("sopSearch").value.trim().toLowerCase();
    const container = $("sopListContainer");
    container.innerHTML = "";
    const filtered = sops.map((s, i) => ({ s, i }))
      .filter(({ s }) => sel.value === "all" || s.category === sel.value)
      .filter(({ s }) => !query || s.name.toLowerCase().includes(query));
    if (!filtered.length) { container.innerHTML = `<p class="empty-note" style="color:var(--cream-dim)">${escapeHtml(t("sop.noMatch"))}</p>`; return; }

    filtered.forEach(({ s, i }) => {
      const doneCount = s.steps.filter((_, si) => sopChecks[i + ":" + si]).length;
      const card = document.createElement("div");
      card.className = "ticket sop-card" + (sopOpen[i] ? " open" : "");
      card.innerHTML = `
        <div class="ticket-pad">
          <div class="sop-head">
            <div>
              <div class="name">${escapeHtml(s.name)}<span class="sop-progress">${doneCount}/${s.steps.length}</span></div>
              <div class="meta">${escapeHtml(s.category)} · ${escapeHtml(s.responsible)} · ${escapeHtml(s.review)}</div>
            </div>
            <div class="sop-chevron">▶</div>
          </div>
          <div class="sop-body">
            <ul class="sop-steps">
              ${s.steps.map((step, si) => `
                <li class="${sopChecks[i + ":" + si] ? "checked" : ""}">
                  <input type="checkbox" data-i="${i}" data-si="${si}" ${sopChecks[i + ":" + si] ? "checked" : ""}>
                  <span>${escapeHtml(step)}</span>
                </li>`).join("")}
            </ul>
          </div>
        </div>`;
      card.querySelector(".sop-head").addEventListener("click", () => { sopOpen[i] = !sopOpen[i]; renderSops(); });
      card.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
        cb.addEventListener("click", (e) => e.stopPropagation());
        cb.addEventListener("change", (e) => {
          sopChecks[e.target.dataset.i + ":" + e.target.dataset.si] = e.target.checked;
          safeSet("cn_sop_checks", sopChecks);
          renderSops();
        });
      });
      container.appendChild(card);
    });
  }
  $("sopSearch").addEventListener("input", renderSops);
  $("sopFilter").addEventListener("change", renderSops);

  // ======================================================================
  // Finance calculators
  // ======================================================================
  function setResult(id, text, cls) { const el = $(id); el.textContent = text; el.className = "cr-value" + (cls ? " " + cls : ""); }
  function calcFoodCost() {
    const cost = parseFloat($("fc_cost").value), price = parseFloat($("fc_price").value);
    if (!cost || !price) return setResult("fc_result", "—");
    const pct = (cost / price) * 100;
    setResult("fc_result", pct.toFixed(1) + "%", pct > 35 ? "warn" : "good");
  }
  function calcMargin() {
    const rev = parseFloat($("pm_rev").value), cost = parseFloat($("pm_cost").value);
    if (!rev) return setResult("pm_result", "—");
    const pct = ((rev - (cost || 0)) / rev) * 100;
    setResult("pm_result", pct.toFixed(1) + "%", pct < 10 ? "warn" : "good");
  }
  function calcMenuPrice() {
    const cost = parseFloat($("mp_cost").value), target = parseFloat($("mp_target").value);
    if (!cost || !target) return setResult("mp_result", "—");
    setResult("mp_result", money(cost / (target / 100)), "good");
  }
  function calcLabour() {
    const labour = parseFloat($("lc_labour").value), sales = parseFloat($("lc_sales").value);
    if (!labour || !sales) return setResult("lc_result", "—");
    const pct = (labour / sales) * 100;
    setResult("lc_result", pct.toFixed(1) + "%", pct > 30 ? "warn" : "good");
  }
  ["fc_cost", "fc_price"].forEach((id) => $(id).addEventListener("input", calcFoodCost));
  ["pm_rev", "pm_cost"].forEach((id) => $(id).addEventListener("input", calcMargin));
  ["mp_cost", "mp_target"].forEach((id) => $(id).addEventListener("input", calcMenuPrice));
  ["lc_labour", "lc_sales"].forEach((id) => $(id).addEventListener("input", calcLabour));

  // ======================================================================
  // Staff pipeline
  // ======================================================================
  function renderStaff() {
    const el = $("staffPipeline");
    el.innerHTML = "";
    STAGES.forEach((stage) => {
      const col = document.createElement("div");
      col.innerHTML = `<div class="pipe-col-head">${escapeHtml(t("stage." + stage))}</div>`;
      const members = staff.map((m, i) => ({ m, i })).filter(({ m }) => m.stage === stage);
      if (!members.length) col.innerHTML += `<p class="empty-note" style="color:var(--cream-dim)">${escapeHtml(t("staff.empty"))}</p>`;
      members.forEach(({ m, i }) => {
        const nextStage = STAGES[STAGES.indexOf(stage) + 1];
        const card = document.createElement("div");
        card.className = "ticket staff-card";
        card.innerHTML = `
          <div class="ticket-pad">
            <div class="staff-name">${escapeHtml(m.name)}</div>
            <div class="staff-role">${escapeHtml(m.role)}</div>
            ${m.sopFlag ? `<div class="staff-flag">${escapeHtml(t("staff.flag"))}</div>` : ""}
            <div class="staff-actions">
              ${nextStage ? `<button class="btn small ghost" type="button" data-next="${nextStage}">${escapeHtml(t("staff.moveTo", { stage: t("stage." + nextStage) }))}</button>` : ""}
              ${m.sopFlag ? `<button class="btn small brass" type="button" data-clearflag="1">${escapeHtml(t("staff.confirmSop"))}</button>` : ""}
            </div>
          </div>`;
        card.querySelectorAll("button").forEach((btn) => btn.addEventListener("click", () => {
          if (btn.dataset.next) staff[i].stage = btn.dataset.next;
          if (btn.dataset.clearflag) staff[i].sopFlag = false;
          safeSet("cn_staff", staff);
          renderStaff();
        }));
        col.appendChild(card);
      });
      el.appendChild(col);
    });
    renderStats();
  }

  // ======================================================================
  // Marketing
  // ======================================================================
  function renderCampaigns() {
    const el = $("campaignList");
    el.innerHTML = "";
    if (!campaigns.length) el.innerHTML = `<p class="empty-note" style="color:var(--cream-dim)">${escapeHtml(t("marketing.noCampaigns"))}</p>`;
    campaigns.forEach((c) => {
      const status = STATUS_CLASS[c.status] ? c.status : "Planning";
      const card = document.createElement("div");
      card.className = "ticket campaign-card";
      card.innerHTML = `
        <div class="ticket-pad">
          <div class="campaign-head">
            <div class="campaign-title">${escapeHtml(c.title)}</div>
            <span class="status-pill ${STATUS_CLASS[status]}">${escapeHtml(t("status." + status))}</span>
          </div>
          <div class="campaign-meta">
            <b>${escapeHtml(t("marketing.channel"))}</b> ${escapeHtml(c.channel || "—")}<br>
            <b>${escapeHtml(t("marketing.offer"))}</b> ${escapeHtml(c.offer || "—")}
          </div>
        </div>`;
      el.appendChild(card);
    });
  }
  function renderIdeas() {
    const el = $("ideaList");
    el.innerHTML = "";
    if (!ideas.length) el.innerHTML = `<li class="empty-note">${escapeHtml(t("marketing.noIdeas"))}</li>`;
    ideas.forEach((idea) => { const li = document.createElement("li"); li.textContent = idea; el.appendChild(li); });
  }
  $("addCampaignBtn").addEventListener("click", () => {
    const title = $("camp_title").value.trim();
    if (!title) return;
    campaigns.unshift({ title, channel: $("camp_channel").value.trim(), offer: $("camp_offer").value.trim(), status: $("camp_status").value });
    safeSet("cn_campaigns", campaigns);
    ["camp_title", "camp_channel", "camp_offer"].forEach((id) => { $(id).value = ""; });
    renderCampaigns();
  });
  $("addIdeaBtn").addEventListener("click", () => {
    const input = $("newIdeaInput");
    const val = input.value.trim();
    if (!val) return;
    ideas.unshift(val);
    safeSet("cn_ideas", ideas);
    input.value = "";
    renderIdeas();
  });
  $("newIdeaInput").addEventListener("keydown", (e) => { if (e.key === "Enter") $("addIdeaBtn").click(); });

  // ======================================================================
  // Reviews
  // ======================================================================
  let editingReviewId = null;
  let reviewRating = 0;
  const starsText = (n) => { n = Math.max(0, Math.min(5, Math.round(Number(n) || 0))); return "★".repeat(n) + "☆".repeat(5 - n); };
  const sourceLabel = (s) => (I18N.en["source." + s] !== undefined ? t("source." + s) : String(s || ""));

  function renderReviews() {
    const need = reviews.filter((r) => !r.replied).length;
    $("reviewSummary").textContent = reviews.length
      ? t("reviews.summary", {
          avg: (reviews.reduce((s, r) => s + (Number(r.rating) || 0), 0) / reviews.length).toFixed(1),
          count: plural("reviews.count", reviews.length), need })
      : t("reviews.empty");
    const list = $("reviewList");
    list.innerHTML = "";
    reviews.slice().sort((a, b) => String(b.date).localeCompare(String(a.date))).forEach((r) => {
      const row = document.createElement("div");
      row.className = "review-row";
      const id = escapeHtml(r.id);
      row.innerHTML = `
        <div class="review-head">
          <span class="stars" role="img" aria-label="${escapeHtml(t("reviews.starsLabel", { n: r.rating }))}">${starsText(r.rating)}</span>
          <span class="source-badge">${escapeHtml(sourceLabel(r.source))}</span>
          <span class="review-meta">${escapeHtml(r.name || "")}${r.name ? " · " : ""}${escapeHtml(fmtDate(r.date))}</span>
          <span class="tag ${r.replied ? "done" : "reply"}">${escapeHtml(t(r.replied ? "reviews.replied" : "reviews.needsReply"))}</span>
        </div>
        ${r.text ? `<div class="review-text">${escapeHtml(r.text)}</div>` : ""}
        <div class="review-actions">
          <button class="icon-btn" type="button" data-act="replied" data-id="${id}">${escapeHtml(t(r.replied ? "reviews.markNotReplied" : "reviews.markReplied"))}</button>
          <button class="icon-btn" type="button" data-act="edit" data-id="${id}">✎ ${escapeHtml(t("common.edit"))}</button>
        </div>`;
      list.appendChild(row);
    });
    renderStats();
  }
  $("reviewList").addEventListener("click", (e) => {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const r = reviews.find((x) => x.id === b.dataset.id);
    if (!r) return;
    if (b.dataset.act === "replied") { r.replied = !r.replied; safeSet("cn_reviews", reviews); renderReviews(); }
    else openReview(r.id);
  });
  function setReviewRating(n) {
    reviewRating = n;
    document.querySelectorAll("#reviewRating button").forEach((b) => b.classList.toggle("sel", Number(b.dataset.r) === n));
  }
  document.querySelectorAll("#reviewRating button").forEach((b) => b.addEventListener("click", () => setReviewRating(Number(b.dataset.r))));
  function openReview(id) {
    editingReviewId = id || null;
    const r = id ? reviews.find((x) => x.id === id) : null;
    $("reviewTitle").textContent = t(r ? "reviews.editTitle" : "reviews.addTitle");
    $("reviewSource").value = r ? r.source : "Google";
    setReviewRating(r ? Number(r.rating) : 0);
    $("reviewDate").value = r ? r.date : todayISO();
    $("reviewName").value = r ? (r.name || "") : "";
    $("reviewText").value = r ? (r.text || "") : "";
    $("reviewReplied").checked = r ? !!r.replied : false;
    $("reviewDelete").hidden = !r;
    $("reviewError").textContent = "";
    openModal("reviewModal");
  }
  $("addReviewBtn").addEventListener("click", () => openReview());
  $("reviewForm").addEventListener("submit", (e) => {
    e.preventDefault();
    if (reviewRating < 1) { $("reviewError").textContent = t("reviews.needRating"); return; }
    if (!$("reviewDate").value) { $("reviewError").textContent = t("reviews.needDate"); return; }
    const item = {
      id: editingReviewId || newId(), source: $("reviewSource").value, rating: reviewRating,
      date: $("reviewDate").value, name: $("reviewName").value.trim(),
      text: $("reviewText").value.trim(), replied: $("reviewReplied").checked,
    };
    const idx = reviews.findIndex((x) => x.id === item.id);
    if (idx >= 0) reviews[idx] = item; else reviews.push(item);
    safeSet("cn_reviews", reviews);
    closeModals();
    renderReviews();
  });
  $("reviewDelete").addEventListener("click", () => {
    if (!window.confirm(t("reviews.confirmDelete"))) return;
    reviews = reviews.filter((x) => x.id !== editingReviewId);
    safeSet("cn_reviews", reviews);
    closeModals();
    renderReviews();
  });

  // ======================================================================
  // Security
  // ======================================================================
  function renderSecurity() {
    const el = $("secChecklist");
    el.innerHTML = "";
    secItems.forEach((item, i) => {
      const row = document.createElement("div");
      row.className = "sec-check-row" + (item.done ? " checked" : "");
      row.innerHTML = `
        <input type="checkbox" ${item.done ? "checked" : ""}>
        <div class="sc-body">
          <div class="sc-title2">${escapeHtml(item.title)}</div>
          <div class="sc-note">${escapeHtml(item.note)}</div>
        </div>`;
      row.querySelector("input").addEventListener("change", (e) => {
        secItems[i].done = e.target.checked;
        safeSet("cn_security", secItems);
        renderSecurity();
      });
      el.appendChild(row);
    });
  }
  function renderIncidents() {
    const el = $("incidentLog");
    el.innerHTML = "";
    if (!incidents.length) { el.innerHTML = `<p class="empty-note">${escapeHtml(t("security.noIncidents"))}</p>`; return; }
    incidents.slice().reverse().forEach((inc) => {
      const div = document.createElement("div");
      div.className = "incident-log-item";
      div.innerHTML = `<span class="il-date">${escapeHtml(inc.date)}</span>${escapeHtml(inc.desc)}`;
      el.appendChild(div);
    });
  }
  $("addIncidentBtn").addEventListener("click", () => {
    const date = $("inc_date").value, desc = $("inc_desc").value.trim();
    if (!date || !desc) return;
    incidents.push({ date, desc });
    safeSet("cn_incidents", incidents);
    $("inc_desc").value = "";
    renderIncidents();
  });

  // ======================================================================
  // Language switch + first draw
  // ======================================================================
  function renderAll() {
    renderDate(); renderUser();
    renderPriorities(); renderMenu(); renderSops(); renderStaff();
    renderCampaigns(); renderIdeas(); renderReviews();
    renderSecurity(); renderIncidents(); refreshDashFinance();
    calcFoodCost(); calcMargin(); calcMenuPrice(); calcLabour();
  }
  function setLang(next) {
    if (!LANGS.includes(next) || next === lang) return;
    lang = next;
    try { localStorage.setItem("sm_lang", next); } catch (e) {}
    document.cookie = "sm_lang=" + next + "; path=/; max-age=31536000; SameSite=Lax" + (location.protocol === "https:" ? "; Secure" : "");
    applyStaticText();
    renderAll();
    SM.langListeners.forEach((fn) => fn());
  }
  document.querySelectorAll(".lang-switch button").forEach((b) => b.addEventListener("click", () => setLang(b.dataset.lang)));

  $("inc_date").value = todayISO();
  restoreDashFinanceInputs();
  applyStaticText();
  renderAll();

  // ======================================================================
  // Shared-data bindings: how changes from other devices reach the screen
  // ======================================================================
  const syncBindings = {
    cn_priorities:   { get: () => priorities,  set: (v) => { priorities = v; renderPriorities(); } },
    cn_sop_checks:   { get: () => sopChecks,   set: (v) => { sopChecks = v; renderSops(); } },
    cn_staff:        { get: () => staff,       set: (v) => { staff = v; renderStaff(); } },
    cn_campaigns:    { get: () => campaigns,   set: (v) => { campaigns = v; renderCampaigns(); } },
    cn_ideas:        { get: () => ideas,       set: (v) => { ideas = v; renderIdeas(); } },
    cn_security:     { get: () => secItems,    set: (v) => { secItems = v; renderSecurity(); } },
    cn_incidents:    { get: () => incidents,   set: (v) => { incidents = v; renderIncidents(); } },
    cn_dash_finance: { get: () => dashFinance, set: (v) => { dashFinance = v; restoreDashFinanceInputs(); refreshDashFinance(); } },
    cn_menu:         { get: () => menu,        set: (v) => { menu = v; renderMenu(); } },
    cn_reviews:      { get: () => reviews,     set: (v) => { reviews = v; renderReviews(); } },
    cn_settings:     { get: () => settings,    set: (v) => { settings = v; } },
  };
  SM.keys = Object.keys(syncBindings);
  SM.current = (key) => JSON.stringify(syncBindings[key].get());
  SM.apply = (key, raw) => {
    let value;
    try { value = JSON.parse(raw); } catch (e) { return; }
    const binding = syncBindings[key];
    if (!binding || Array.isArray(value) !== Array.isArray(binding.get())) return;   // ignore malformed data
    SM.applyingRemote = true;
    try {
      localStorage.setItem(key, raw);
      binding.set(value);
    } catch (e) {
      console.warn("Could not apply shared data for", key, e);
    } finally {
      SM.applyingRemote = false;
    }
  };

})();
</script>

<script>
// ---------- Version, feedback and updates ----------
(function () {
  "use strict";
  const SM = window.SM;
  const t = SM.t;
  const APP_VERSION = "2.1.0";
  document.getElementById("appVersion").textContent = "v" + APP_VERSION;

  const statusEl = document.getElementById("fbStatus");
  const textEl = document.getElementById("fbText");
  let rating = 0;

  document.getElementById("feedbackBtn").addEventListener("click", () => {
    statusEl.textContent = "";
    SM.openModal("fbBackdrop");
  });
  document.querySelectorAll("#fbRating button").forEach((b) => {
    b.addEventListener("click", () => {
      rating = Number(b.dataset.r);
      document.querySelectorAll("#fbRating button").forEach((x) => x.classList.toggle("sel", x === b));
    });
  });

  document.getElementById("fbSend").addEventListener("click", async () => {
    const message = textEl.value.trim();
    if (!message && !rating) { statusEl.textContent = t("fb.needInput"); return; }
    const activeView = (document.querySelector(".view.active") || {}).id || "";
    try {
      const res = await fetch("/api/feedback", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-SM": "1" },
        body: JSON.stringify({ message, rating, page: activeView.replace("view-", ""), version: APP_VERSION }),
      });
      if (res.status === 401) { window.location.href = "/login"; return; }
      if (!res.ok) throw new Error("bad response");
      statusEl.textContent = t("fb.sent");
      textEl.value = ""; rating = 0;
      document.querySelectorAll("#fbRating button").forEach((x) => x.classList.remove("sel"));
      setTimeout(SM.closeModals, 1400);
    } catch (err) {
      statusEl.textContent = t("fb.failed");
    }
  });
})();

// Register the service worker (installable app + opens offline) and prompt when a new version is ready.
if ("serviceWorker" in navigator) {
  const hadController = !!navigator.serviceWorker.controller;
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (hadController) document.getElementById("updateBanner").classList.add("show");
  });
  document.getElementById("updateReload").addEventListener("click", () => window.location.reload());
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch((err) => {
      console.warn("Service worker registration failed:", err);
    });
  });
}
</script>

<script>
// ---------- Shared data: talks to the Python server ----------
(function () {
  "use strict";
  const SM = window.SM;
  const POLL_MS = 5000;                       // how often to check for other people's changes
  const statusEl = document.getElementById("syncStatus");
  const signOutButtons = document.querySelectorAll("[data-signout]");

  let rev = 0;                                // newest server revision we've seen
  let seeded = false;
  let inFlight = false;
  let signedOut = false;
  let current = { key: "sync.connecting", cls: "" };
  const timers = {};                          // key -> pending debounce timer
  const dirty = new Set();                    // keys with changes the server hasn't confirmed yet
  try { JSON.parse(localStorage.getItem("sm_dirty") || "[]").forEach((k) => dirty.add(k)); } catch (e) {}
  (SM.pending || []).forEach((k) => dirty.add(k));
  const saveDirty = () => { try { localStorage.setItem("sm_dirty", JSON.stringify([...dirty])); } catch (e) {} };

  function setStatus(key, cls) {
    current = { key, cls: cls || "" };
    statusEl.textContent = SM.t(key);
    statusEl.className = "sync-status " + current.cls;
  }
  SM.onLang(() => setStatus(current.key, current.cls));

  async function api(path, method, body) {
    const res = await fetch(path, {
      method: method || "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "X-SM": "1" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status === 401) { window.location.href = "/login"; throw new Error("signed out"); }
    if (!res.ok) throw new Error("http " + res.status);
    return res.json();
  }

  async function flush(key) {
    try {
      await api("/api/data/" + key, "PUT", { value: SM.current(key) });   // always send the newest local copy
      dirty.delete(key);
      saveDirty();
      return true;
    } catch (e) {
      return false;
    }
  }

  // Called by the app after every change on this device.
  SM.push = (key) => {
    dirty.add(key);
    saveDirty();
    clearTimeout(timers[key]);
    timers[key] = setTimeout(async () => {
      delete timers[key];
      const ok = await flush(key);
      if (ok && !dirty.size) setStatus("sync.synced", "ok");
      else setStatus("sync.offline", "warn");
    }, 800);
  };

  async function pull() {
    if (inFlight || signedOut) return;
    inFlight = true;
    try {
      const data = await api("/api/changes?since=" + rev);
      const onServer = new Set();
      data.items.forEach((item) => {
        onServer.add(item.key);
        if (!SM.keys.includes(item.key)) return;
        if (dirty.has(item.key) || timers[item.key]) return;           // our unsent edit wins
        if (item.value !== SM.current(item.key)) SM.apply(item.key, item.value);
      });
      if (!seeded) {
        seeded = true;
        // First device ever: publish what's on screen so everyone starts from the same data.
        SM.keys.forEach((key) => { if (!onServer.has(key)) dirty.add(key); });
        saveDirty();
      }
      rev = data.rev;
      for (const key of [...dirty]) { if (!timers[key]) await flush(key); }   // send anything still waiting
      if (dirty.size) setStatus("sync.offline", "warn");
      else setStatus("sync.synced", "ok");
    } catch (e) {
      if (!signedOut) setStatus("sync.offline", "warn");
    } finally {
      inFlight = false;
    }
  }

  setInterval(() => { if (!document.hidden) pull(); }, POLL_MS);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) pull(); });
  window.addEventListener("online", pull);
  window.addEventListener("offline", () => setStatus("sync.offline", "warn"));

  signOutButtons.forEach((btn) => {
    btn.hidden = false;
    btn.addEventListener("click", async () => {
      signedOut = true;
      try { await api("/api/logout", "POST", {}); } catch (e) {}
      window.location.href = "/login";
    });
  });
  api("/api/me").then((me) => { SM.setUser(me.email); }).catch(() => {});

  setStatus("sync.connecting");
  pull();
})();
</script>
</body>
</html>
'''

# ---- The sign-in page (a template; the words come from LOGIN_TEXT above) ----
LOGIN_HTML = r'''<!DOCTYPE html>
<html lang="{{ lang }}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#16231C">
<title>{{ tx.page_title }}</title>
<link rel="icon" href="/static/icons/icon-512.png">
<link rel="manifest" href="/static/manifest.json">
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    padding: 24px; background: #16231C; color: #EFE6D2;
    font-family: "Work Sans", "Segoe UI", system-ui, -apple-system, sans-serif;
  }
  .card {
    width: 100%; max-width: 380px; background: #F4ECD8; color: #2B2018; border-radius: 3px;
    border-left: 5px solid #C99A3E; padding: 26px 24px 24px;
    box-shadow: 0 6px 18px rgba(0,0,0,0.35);
  }
  h1 { font-family: Georgia, "Times New Roman", serif; font-size: 24px; margin: 0 0 4px; color: #1C2B22; }
  p.sub { margin: 0 0 18px; font-size: 13.5px; color: #6B5D48; }
  label { display: block; font-size: 12px; font-weight: 700; color: #6B5D48; margin: 12px 0 5px; }
  input[type=email], input[type=password] {
    width: 100%; padding: 11px 12px; border: 1px solid #D8C9A3; border-radius: 3px;
    background: #fff; color: #2B2018; font-size: 16px;
  }
  button {
    margin-top: 18px; width: 100%; padding: 12px; border: none; border-radius: 3px; cursor: pointer;
    background: #C99A3E; color: #241a08; font-size: 15px; font-weight: 700;
  }
  button:hover { background: #b98931; }
  .error { margin-top: 14px; font-size: 13.5px; color: #B23A2E; font-weight: 600; }
  .note { margin-top: 16px; font-size: 12px; color: #6B5D48; }
  .langs { margin-top: 14px; padding-top: 12px; border-top: 1px dashed #D8C9A3; display: flex; gap: 14px; font-size: 13px; }
  .langs a { color: #6B5D48; text-decoration: none; }
  .langs a.on { color: #2B2018; font-weight: 700; text-decoration: underline; }
</style>
</head>
<body>
  <form class="card" method="post" action="/login" autocomplete="on">
    <h1>SecureManager</h1>
    <p class="sub">{{ tx.intro }}</p>
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <input type="hidden" name="next" value="{{ next_url }}">
    <label for="email">{{ tx.email }}</label>
    <input id="email" name="email" type="email" autocomplete="username" required autofocus>
    <label for="password">{{ tx.password }}</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">{{ tx.button }}</button>
    {% if error %}<div class="error" role="alert">{{ error }}</div>{% endif %}
    <div class="note">{{ tx.forgot }}</div>
    <div class="langs" aria-label="{{ tx.language }}">
      <a href="/login?lang=en{% if next_url != '/' %}&next={{ next_url|urlencode }}{% endif %}" {% if lang == 'en' %}class="on"{% endif %}>English</a>
      <a href="/login?lang=vi{% if next_url != '/' %}&next={{ next_url|urlencode }}{% endif %}" {% if lang == 'vi' %}class="on"{% endif %}>Tiếng Việt</a>
    </div>
  </form>
</body>
</html>
'''

# ---- Lets the app install on a phone and open offline. Change CACHE_NAME when you release an update. ----
SERVICE_WORKER_JS = r'''// SecureManager service worker: installable app + the app screen still opens offline.
//
// - The app page ("/") is fetched from the server first, so people always get the newest
//   version and the sign-in redirect works. The last good copy is used only when offline.
// - Icons and the manifest are cached.
// - Data and sign-in traffic (/api/..., /login) are never touched, so shared data is always live.
//
// When you release a new version, change CACHE_NAME below. Open copies of the app will then
// show a "new version ready - Refresh" banner.

const CACHE_NAME = "securemanager-v2";
const PRECACHE = [
  "/static/manifest.json",
  "/static/icons/icon-512.png",
  "/static/icons/icon-512-maskable.png",
  "/static/icons/apple-touch-icon.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;           // fonts etc.: let the browser handle them
  if (url.pathname.startsWith("/api/") || url.pathname === "/login" || url.pathname === "/sw.js") return;

  // The app page: network first, last good copy when offline.
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then((response) => {
          // Keep a copy only of the real app page (not the sign-in page or a redirect).
          if (response.ok && !response.redirected && url.pathname === "/") {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put("/", copy));
          }
          return response;
        })
        .catch(() =>
          caches.match("/").then((cached) =>
            cached || new Response("You're offline, and the app hasn't been opened on this device yet.",
                                   { status: 503, headers: { "Content-Type": "text/plain" } })
          )
        )
    );
    return;
  }

  // Everything else on our own site (icons, manifest): cached copy first.
  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;
      return fetch(request).then((response) => {
        if (response.ok) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
        }
        return response;
      });
    })
  );
});
'''

# ---- Tells phones and browsers how to install the app ----
MANIFEST = {
    "name": "SecureManager — Cơm Nhà",
    "short_name": "SecureManager",
    "description": "Management toolkit for Cơm Nhà: SOPs, finance, staff, marketing and security.",
    "id": "/",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "orientation": "any",
    "background_color": "#16231C",
    "theme_color": "#16231C",
    "icons": [
        {
            "src": "/static/icons/icon-512.png",
            "sizes": "512x512",
            "type": "image/png",
            "purpose": "any"
        },
        {
            "src": "/static/icons/icon-512-maskable.png",
            "sizes": "512x512",
            "type": "image/png",
            "purpose": "maskable"
        }
    ]
}

# ---- App icons (stored as text, turned back into pictures when needed) ----
_ICONS_BASE64 = {
    "icon-512.png": """
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
""",
    "icon-512-maskable.png": """
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
""",
    "apple-touch-icon.png": """
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
/7I3n++MwensrtRYMhhjRsfGL3/3hWeeefrY6PghMwYHtu2486+uvLq3pyeTSc9yTVNErLWrV6248eZbrvrEP/QMDtjmN4zT
t5+++qqM73eGGegMOYioVg9OWHPchW9/c32i5HkGgIhmc9lHHn70ir+/LpvxmWmuon0QhiuWDX3tm9+66d/+s9jfZ60FwMzl
cuWM9aduet2fjo1PxM+QdDpBDmN4oly+ePOmlWtW1epBI9ITiPkj13xm956Hs9ns3P42q6rneR++5oY9ex72s5k4lU9ENgje
f+H5PYV81BHXByReDiKq1eonrDnuovPeXC+VjWEA1tqe3p5v3/aD//ru1mXDg3OeIRPRXNbft//AJ27Y4vu+qqAZPNavP/VN
r3vV2ERp8np8Qkm8HMxcrtZefs7GlatW1Jthw7CpVWtbvnqT76fjsD/nhKHtK/be9oMdd/38nkKhEEcmJRLVv3jVKwzz3N7i
uSgkXg4RyfjpSza/xUY2LgSNRPI9he9sveNnv7inkM/PX/kWM1eqtS1fvQnN3JzHXC2VX33uyzac/oJSucqzvoJvcUm2HEQU
hOGqFctPXLsmCgImUqghqgfBF278hjFmXvPp1tpiT+E727bfe9/OfC4br51YazPZ7Bnr/iCe6M7fT18Aki0HE9XqwQue/7yV
y4eDMIxv885mM7/e/dB9O3flstn5TnYYY8rlyvd33Gl8P144V0CZX/Ki9SLi5FhMiEisPfelL1bmRtsoTCp1387d4wsyJBTA
sPnVAzuDQ8Mdjqq1s154+vDQYBhFifYj2XIAEJF8Lkfc+I8IFMbc9av7FibFoSKZjH//zl0T42Npr5HXVdV8LhfvbFiIh5g3
EiwHEUXWDg0OvOiMU8NqLc6keMZUSqVHn/h9yvMWpm2MMWMT5ceeeNKkvPgSgiAMh5cNvfC0dbVanTnB73CCH11EwjDyPDM4
0K8iBERRRMDBAwcf3PWQ76cXQI54NWz/wZEHdz3EhsMwivcuZLLZYm9PPQgSXeGR4H0rmYwPRTaTiVcyFCgWe5HJeJ7x/bRO
LFxIJ+bBgT6T7R9grlWqgVi11vNMIZ/P5bKVSjWh/Usis7LMXKlWb/zn61+68YWlSmWwv4+JUp732S99be+jT7ChW2/fXqsv
UEgnonoQnHvOi088fk2tVrvyfZeuXrU8DKOJUrkeBMy86ZLLHnr4kWzGT9yGuaRGDlUd7CsOLR/OT5RERFU9j//n+z/46U9/
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
""",
}
ICON_FILES = {name: base64.b64decode("".join(text.split())) for name, text in _ICONS_BASE64.items()}



# ====================================================================
# 7. The launcher
# ====================================================================

def main():
    parser = argparse.ArgumentParser(description="SecureManager", epilog="With no command, the app starts.")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("run", help="start the app")
    p.add_argument("--host"); p.add_argument("--port", type=int); p.add_argument("--no-browser", action="store_true")
    p.set_defaults(fn=cmd_run)
    p = sub.add_parser("add-user", help="add a person");           p.add_argument("email"); p.add_argument("--password"); p.set_defaults(fn=cmd_add_user)
    p = sub.add_parser("set-password", help="change a password");  p.add_argument("email"); p.add_argument("--password"); p.set_defaults(fn=cmd_set_password)
    p = sub.add_parser("remove-user", help="remove a person");     p.add_argument("email"); p.set_defaults(fn=cmd_remove_user)
    p = sub.add_parser("list-users", help="list people");          p.set_defaults(fn=cmd_list_users)
    p = sub.add_parser("feedback", help="read feedback");          p.add_argument("--limit", type=int, default=50); p.set_defaults(fn=cmd_feedback)
    p = sub.add_parser("export", help="save the data as JSON");    p.add_argument("file"); p.set_defaults(fn=cmd_export)
    p = sub.add_parser("backup", help="copy the database");        p.add_argument("file"); p.set_defaults(fn=cmd_backup)
    p = sub.add_parser("selftest", help="check that everything works"); p.set_defaults(fn=cmd_selftest)
    p = sub.add_parser("_selftest"); p.set_defaults(fn=lambda _a: _run_selftest())

    args = parser.parse_args()
    if args.cmd is None:
        args = parser.parse_args(["run"])
    args.fn(args)


if __name__ == "__main__":
    main()