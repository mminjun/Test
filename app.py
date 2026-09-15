import os
import sqlite3
from functools import wraps

from flask import Flask, g, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "memo.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")


# ---------- DB ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


# ---------- Auth helper ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


@app.before_request
def load_current_user():
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = get_db().execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if g.user is None:
            session.clear()


# ---------- Templates ----------
LAYOUT = """
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>{{ title }}</title>
</head>
<body>
  <h1>메모 서비스</h1>
  <p>
    {% if g.user %}
      <b>{{ g.user.username }}</b>님 로그인 중 |
      <a href="{{ url_for('index') }}">홈</a> |
      <a href="{{ url_for('logout') }}">로그아웃</a>
    {% else %}
      <a href="{{ url_for('login') }}">로그인</a> |
      <a href="{{ url_for('register') }}">회원가입</a>
    {% endif %}
  </p>
  <hr>
  {% if error %}<p><b>오류:</b> {{ error }}</p>{% endif %}
  {% if message %}<p>{{ message }}</p>{% endif %}
  {{ body|safe }}
</body>
</html>
"""

INDEX_BODY = """
<h2>홈</h2>
{% if g.user %}
  <p>환영합니다, {{ g.user.username }}님. 메모 기능은 아직 준비 중입니다.</p>
{% else %}
  <p>로그인하거나 회원가입을 해주세요.</p>
{% endif %}
"""

REGISTER_BODY = """
<h2>회원가입</h2>
<form method="post">
  <p><label>아이디 <input type="text" name="username" value="{{ username }}" required></label></p>
  <p><label>비밀번호 <input type="password" name="password" required></label></p>
  <p><label>비밀번호 확인 <input type="password" name="password2" required></label></p>
  <p><button type="submit">가입</button></p>
</form>
<p>이미 계정이 있나요? <a href="{{ url_for('login') }}">로그인</a></p>
"""

LOGIN_BODY = """
<h2>로그인</h2>
<form method="post">
  <input type="hidden" name="next" value="{{ next }}">
  <p><label>아이디 <input type="text" name="username" value="{{ username }}" required></label></p>
  <p><label>비밀번호 <input type="password" name="password" required></label></p>
  <p><button type="submit">로그인</button></p>
</form>
<p>계정이 없나요? <a href="{{ url_for('register') }}">회원가입</a></p>
"""


def render(title, body_template, **ctx):
    body = render_template_string(body_template, **ctx)
    return render_template_string(LAYOUT, title=title, body=body, **ctx)


# ---------- Routes ----------
@app.route("/")
def index():
    return render("홈", INDEX_BODY, message=request.args.get("message"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))

    error = None
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if not username or not password:
            error = "아이디와 비밀번호를 모두 입력해주세요."
        elif len(username) < 3 or len(username) > 20:
            error = "아이디는 3~20자여야 합니다."
        elif len(password) < 4:
            error = "비밀번호는 4자 이상이어야 합니다."
        elif password != password2:
            error = "비밀번호 확인이 일치하지 않습니다."
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "이미 사용 중인 아이디입니다."
            else:
                return redirect(url_for("login", message="회원가입이 완료되었습니다. 로그인해주세요."))

    return render("회원가입", REGISTER_BODY, error=error, username=username)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))

    error = None
    username = ""
    next_url = request.values.get("next", "")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            error = "아이디 또는 비밀번호가 올바르지 않습니다."
        else:
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            # 외부 URL로 리다이렉트되지 않도록 내부 경로만 허용
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("index"))

    return render(
        "로그인",
        LOGIN_BODY,
        error=error,
        username=username,
        next=next_url,
        message=request.args.get("message"),
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index", message="로그아웃되었습니다."))


init_db()

if __name__ == "__main__":
    app.run(debug=True)
