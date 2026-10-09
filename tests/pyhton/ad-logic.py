import hmac
import os
import random
import tempfile
import time

import jwt
from flask import Flask, abort, request, session
from flask_login import current_user, login_required

app = Flask(__name__)
# ruleid: py-hardcoded-flask-secret-key
app.secret_key = "super_secret_dev_key"
# ruleid: py-hardcoded-flask-secret-key
app.config["SECRET_KEY"] = "changeme"
# ok: py-hardcoded-flask-secret-key
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

# ruleid: py-django-debug-or-wildcard-hosts
DEBUG = True


def issue_token(user):
    # ruleid: py-jwt-hardcoded-key
    return jwt.encode({"sub": user.id}, "jwt-secret", algorithm="HS256")


def check_token(tok):
    # ok: py-jwt-hardcoded-key
    return jwt.decode(tok, os.environ["JWT_KEY"], algorithms=["HS256"])


def new_reset_code():
    # ruleid: py-weak-random-token
    return "".join(random.choice("0123456789") for _ in range(6))


# ruleid: py-random-seed-predictable
random.seed(int(time.time()))
# ruleid: py-random-seed-predictable
random.seed(1337)
# ok: py-random-seed-predictable
random.seed(os.urandom(16))


def verify(req_token, stored_token):
    # ruleid: py-timing-unsafe-secret-compare
    if req_token == stored_token:
        return True
    # ok: py-timing-unsafe-secret-compare
    return hmac.compare_digest(req_token, stored_token)


@app.post("/register")
def register():
    # ruleid: py-mass-assignment
    user = User(**request.json)
    db.session.add(user)
    return "ok"


# ruleid: py-sensitive-route-without-auth
@app.post("/profile")
def profile():
    user = load_user()
    # ruleid: py-mass-assignment
    for key, value in request.form.items():
        setattr(user, key, value)
    return "ok"


@app.route("/admin/delete/<int:uid>")
def admin_delete(uid):
    # ruleid: py-assert-used-for-auth
    assert session.get("is_admin"), "forbidden"
    return "deleted"


# ruleid: py-sensitive-route-without-auth
@app.route("/admin/flags")
def all_flags():
    return str(Flag.query.all())


# ok: py-sensitive-route-without-auth
@app.route("/admin/users")
@login_required
def all_users():
    return str(User.query.all())


# ok: py-sensitive-route-without-auth
@app.route("/export")
def export():
    if not current_user.is_admin:
        abort(403)
    return "data"


def tmp():
    # ruleid: py-tempfile-mktemp
    name = tempfile.mktemp()
    return name


def list_notes(cur, sort):
    # ruleid: py-sql-order-by-limit-format
    cur.execute(f"SELECT * FROM notes ORDER BY {sort}")
    # ok: py-sql-order-by-limit-format
    cur.execute("SELECT * FROM notes ORDER BY created_at LIMIT ?", (10,))


def dev_server():
    from werkzeug.serving import run_simple
    # ruleid: py-werkzeug-debugger-or-pin-disabled
    run_simple("0.0.0.0", 5000, app, use_debugger=True)


# FastAPI: /backdoor hands out any profile, no auth dependency
# ruleid: py-sensitive-route-without-auth
@api.get("/backdoor", response_model=UserProfile)
def get_backdoor(username: str):
    return users.find_one({"username": username})


# ok: py-sensitive-route-without-auth
@api.get("/profile", response_model=UserProfile)
def get_profile(current_user_id: str = Depends(get_current_user_id)):
    return users.find_one({"_id": current_user_id})


# aiohttp: /profile/{username} shows the private key to ANY logged-in user
async def handle_profile(request):
    session = await get_session(request)
    try:
        username = request.match_info["username"]
    except KeyError:
        username = session["username"]
    privkey = load_key(username)
    data = [("name", username)]
    # ruleid: py-idor-session-presence-only
    if "username" in session:
        data += privkey.dict().items()
    return render(data)


async def handle_profile_fixed(request):
    session = await get_session(request)
    username = request.match_info["username"]
    privkey = load_key(username)
    data = [("name", username)]
    # ok: py-idor-session-presence-only
    if "username" in session:
        if username == session["username"]:
            data += privkey.dict().items()
    return render(data)


def gen_navbar():
    # ok: py-weak-random-token
    if random.randint(0, 5) == 0:
        return "inspire"
    # ok: py-weak-random-token
    return random.choice(quotes)
