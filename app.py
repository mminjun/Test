import os
import sqlite3
from functools import wraps

from flask import Flask, abort, g, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "memo.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

# 초기 관리자 계정 및 관리자 메모 (환경변수로 덮어쓸 수 있음)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin1234!")
ADMIN_MEMO_TITLE = "관리자 전용 메모"
ADMIN_MEMO_CONTENT = os.environ.get("ADMIN_MEMO_CONTENT", "SBOB{mminjun_admin_only_memo_2026}")


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
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # 이전 버전 DB에 is_admin 컬럼이 없으면 추가
        columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
        if "is_admin" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS memos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )
        seed_admin(db)


def seed_admin(db):
    """admin 계정과 admin 전용 메모를 초기 데이터로 생성 (없을 때만)."""
    admin = db.execute(
        "SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)
    ).fetchone()
    if admin is None:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
            (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD)),
        )
        admin_id = cur.lastrowid
    else:
        admin_id = admin[0]
        db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (admin_id,))

    has_memo = db.execute(
        "SELECT 1 FROM memos WHERE user_id = ? AND title = ?", (admin_id, ADMIN_MEMO_TITLE)
    ).fetchone()
    if has_memo is None:
        db.execute(
            "INSERT INTO memos (user_id, title, content) VALUES (?, ?, ?)",
            (admin_id, ADMIN_MEMO_TITLE, ADMIN_MEMO_CONTENT),
        )


# ---------- Auth helper ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        if not g.user or not g.user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


@app.before_request
def load_current_user():
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = get_db().execute(
            "SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)
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
      <a href="{{ url_for('memo_list') }}">메모</a> |
      {% if g.user.is_admin %}<a href="{{ url_for('admin_users') }}">관리자</a> |{% endif %}
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
  <p>환영합니다, {{ g.user.username }}님. <a href="{{ url_for('memo_list') }}">내 메모 보기</a></p>
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


MEMO_LIST_BODY = """
<h2>내 메모</h2>
<p><a href="{{ url_for('memo_new') }}">새 메모 작성</a></p>
{% if memos %}
  <ul>
  {% for m in memos %}
    <li>
      <a href="{{ url_for('memo_detail', memo_id=m.id) }}">{{ m.title }}</a>
      <small>({{ m.updated_at }})</small>
    </li>
  {% endfor %}
  </ul>
{% else %}
  <p>작성한 메모가 없습니다.</p>
{% endif %}
"""

MEMO_FORM_BODY = """
<h2>{{ heading }}</h2>
<form method="post">
  <p><label>제목<br><input type="text" name="title" value="{{ title_value }}" required></label></p>
  <p><label>내용<br><textarea name="content" rows="10" cols="60">{{ content_value }}</textarea></label></p>
  <p>
    <button type="submit">저장</button>
    <a href="{{ cancel_url }}">취소</a>
  </p>
</form>
"""

MEMO_DETAIL_BODY = """
<h2>{{ memo.title }}</h2>
<p><small>작성: {{ memo.created_at }} / 수정: {{ memo.updated_at }}</small></p>
<pre>{{ memo.content }}</pre>
<p>
  <a href="{{ url_for('memo_edit', memo_id=memo.id) }}">수정</a> |
  <a href="{{ url_for('memo_delete', memo_id=memo.id) }}">삭제</a> |
  <a href="{{ url_for('memo_list') }}">목록</a>
</p>
"""

MEMO_DELETE_BODY = """
<h2>메모 삭제</h2>
<p>"<b>{{ memo.title }}</b>" 메모를 정말 삭제할까요?</p>
<form method="post">
  <button type="submit">삭제</button>
  <a href="{{ url_for('memo_detail', memo_id=memo.id) }}">취소</a>
</form>
"""


ADMIN_USERS_BODY = """
<h2>관리자: 전체 회원 목록</h2>
<p>총 {{ users|length }}명</p>
<table border="1" cellpadding="4">
  <tr>
    <th>ID</th><th>아이디</th><th>권한</th><th>메모 수</th><th>가입일</th>
  </tr>
  {% for u in users %}
  <tr>
    <td>{{ u.id }}</td>
    <td>{{ u.username }}</td>
    <td>{{ '관리자' if u.is_admin else '일반' }}</td>
    <td>{{ u.memo_count }}</td>
    <td>{{ u.created_at }}</td>
  </tr>
  {% endfor %}
</table>
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


# ---------- Memo ----------
def get_own_memo(memo_id):
    """현재 로그인한 사용자의 메모만 반환. 없거나 남의 메모면 404."""
    memo = get_db().execute(
        "SELECT * FROM memos WHERE id = ? AND user_id = ?", (memo_id, g.user["id"])
    ).fetchone()
    if memo is None:
        abort(404)
    return memo


def validate_memo_form():
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").replace("\r\n", "\n")
    error = None
    if not title:
        error = "제목을 입력해주세요."
    elif len(title) > 100:
        error = "제목은 100자 이하여야 합니다."
    return title, content, error


@app.route("/memos")
@login_required
def memo_list():
    memos = get_db().execute(
        "SELECT id, title, updated_at FROM memos WHERE user_id = ? ORDER BY updated_at DESC, id DESC",
        (g.user["id"],),
    ).fetchall()
    return render("내 메모", MEMO_LIST_BODY, memos=memos, message=request.args.get("message"))


@app.route("/memos/new", methods=["GET", "POST"])
@login_required
def memo_new():
    error = None
    title, content = "", ""
    if request.method == "POST":
        title, content, error = validate_memo_form()
        if error is None:
            db = get_db()
            cur = db.execute(
                "INSERT INTO memos (user_id, title, content) VALUES (?, ?, ?)",
                (g.user["id"], title, content),
            )
            db.commit()
            return redirect(url_for("memo_detail", memo_id=cur.lastrowid))
    return render(
        "새 메모",
        MEMO_FORM_BODY,
        heading="새 메모",
        error=error,
        title_value=title,
        content_value=content,
        cancel_url=url_for("memo_list"),
    )


@app.route("/memos/<int:memo_id>")
@login_required
def memo_detail(memo_id):
    memo = get_own_memo(memo_id)
    return render(memo["title"], MEMO_DETAIL_BODY, memo=memo)


@app.route("/memos/<int:memo_id>/edit", methods=["GET", "POST"])
@login_required
def memo_edit(memo_id):
    memo = get_own_memo(memo_id)
    error = None
    title, content = memo["title"], memo["content"]
    if request.method == "POST":
        title, content, error = validate_memo_form()
        if error is None:
            db = get_db()
            db.execute(
                "UPDATE memos SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE id = ? AND user_id = ?",
                (title, content, memo_id, g.user["id"]),
            )
            db.commit()
            return redirect(url_for("memo_detail", memo_id=memo_id))
    return render(
        "메모 수정",
        MEMO_FORM_BODY,
        heading="메모 수정",
        error=error,
        title_value=title,
        content_value=content,
        cancel_url=url_for("memo_detail", memo_id=memo_id),
    )


@app.route("/memos/<int:memo_id>/delete", methods=["GET", "POST"])
@login_required
def memo_delete(memo_id):
    memo = get_own_memo(memo_id)
    if request.method == "POST":
        db = get_db()
        db.execute("DELETE FROM memos WHERE id = ? AND user_id = ?", (memo_id, g.user["id"]))
        db.commit()
        return redirect(url_for("memo_list", message="메모가 삭제되었습니다."))
    return render("메모 삭제", MEMO_DELETE_BODY, memo=memo)


# ---------- Admin ----------
@app.route("/admin")
@admin_required
def admin_users():
    users = get_db().execute(
        """
        SELECT u.id, u.username, u.is_admin, u.created_at,
               (SELECT COUNT(*) FROM memos m WHERE m.user_id = u.id) AS memo_count
        FROM users u
        ORDER BY u.id
        """
    ).fetchall()
    return render("관리자", ADMIN_USERS_BODY, users=users)


init_db()

if __name__ == "__main__":
    app.run(debug=True)
