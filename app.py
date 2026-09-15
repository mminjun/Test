"""
메모 서비스 (교육용 공방 CTF 방어 서버)

실행 모드
  개발:   python app.py            -> 127.0.0.1:5000, 임시 SECRET_KEY, 임시 admin 비밀번호(콘솔 출력)
  초기화: python app.py init       -> 테이블 생성 + admin/플래그 메모 시드 (운영에서는 root로 1회 실행)
  운영:   gunicorn app:app         -> SECRET_KEY 환경변수 필수, 없으면 기동 거부

환경변수
  SECRET_KEY          세션 서명 키 (운영 필수, 앱 프로세스)
  ADMIN_PASSWORD      admin 비밀번호 (init 단계 필수, 앱 프로세스에는 불필요). init 마다 이 값으로 동기화됨
  ADMIN_USERNAME      기본 admin
  FLAG_FILE           플래그 파일 경로 (init 단계 필수). 이 파일 내용이 admin 메모 내용이 됨. 소스에는 플래그 없음
  ADMIN_MEMO_CONTENT  FLAG_FILE 대신 환경변수로 줄 때 (권장하지 않음). 둘 다 없으면 운영 모드 init 거부
  MEMO_DB_PATH        SQLite 파일 경로 (기본: app.py 옆 memo.db)
  TRUST_PROXY=1       nginx 뒤에서 실행 시 X-Forwarded-For/Proto 를 신뢰 (rate limit용 IP)
  MEMO_DEV=1          개발 모드 강제
  MEMO_CSRF_EXEMPT    CSRF 검사를 면제할 엔드포인트 이름 목록 (예: login,register). 체커 호환용
"""

import hmac
import os
import secrets
import sqlite3
import sys
import time
from datetime import timedelta
from functools import wraps
from urllib.parse import urlsplit

from flask import Flask, abort, g, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# `python app.py` (인자 없음) 또는 MEMO_DEV=1 이면 개발 모드. `python app.py init` 은 운영 모드로 동작.
DEV_MODE = os.environ.get("MEMO_DEV") == "1" or (__name__ == "__main__" and len(sys.argv) == 1)

DATABASE = os.environ.get("MEMO_DB_PATH", os.path.join(BASE_DIR, "memo.db"))


def _require_secret(name, dev_factory):
    """운영 모드에서는 환경변수 필수. 개발 모드에서만 임시값 생성."""
    value = os.environ.get(name)
    if value:
        return value
    if DEV_MODE:
        value = dev_factory()
        print(f"[memo] {name} 미설정 -> 개발용 임시값 사용", file=sys.stderr)
        return value
    sys.exit(f"[memo] 환경변수 {name} 가 필요합니다. 운영 모드에서는 기본값을 제공하지 않습니다.")


# [방어] 공개 저장소에 박힌 기본 SECRET_KEY 로 세션 쿠키를 위조해 admin 으로 로그인하는 공격 차단
SECRET_KEY = _require_secret("SECRET_KEY", lambda: secrets.token_hex(32))

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_MEMO_TITLE = "관리자 전용 메모"


def resolve_admin_password():
    """시드 단계에서만 호출. 앱(gunicorn) 프로세스 환경에는 ADMIN_PASSWORD 를 둘 필요가 없다."""
    # [방어] 기본 비밀번호(admin1234!)로 admin 에 바로 로그인하는 공격 차단
    password = _require_secret("ADMIN_PASSWORD", lambda: secrets.token_urlsafe(12))
    if DEV_MODE and not os.environ.get("ADMIN_PASSWORD"):
        print(f"[memo] 개발용 admin 비밀번호: {password}", file=sys.stderr)
    return password


def load_flag():
    """플래그 값 결정. FLAG_FILE > ADMIN_MEMO_CONTENT > (아래 기본값)."""
    path = os.environ.get("FLAG_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                value = f.read().strip()
        except OSError as e:
            sys.exit(f"[memo] FLAG_FILE 을 읽을 수 없습니다: {path} ({e})")
        if not value:
            sys.exit(f"[memo] FLAG_FILE 이 비어 있습니다: {path}")
        return value
    value = os.environ.get("ADMIN_MEMO_CONTENT")
    if value:
        return value
    # [방어] 소스에 플래그를 두지 않음. 운영 모드에서 파일도 환경변수도 없으면 시드를 거부한다.
    #        실제 플래그는 서버의 /etc/memo/flag (root 전용) 에만 존재한다.
    if DEV_MODE:
        print("[memo] FLAG_FILE 미설정 -> 개발용 더미 플래그 사용", file=sys.stderr)
        return "SBOB{dev_dummy_flag_not_real}"
    sys.exit("[memo] FLAG_FILE 환경변수가 필요합니다. 플래그는 소스코드에 포함되지 않습니다.")


# [방어] static_folder=None: /static/<경로> 라우트 자체를 제거해 어떤 파일도 직접 서빙되지 않게 함
app = Flask(__name__, static_folder=None)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    # [방어] 세션 쿠키 탈취/재사용 범위 축소: HTTPS 전용, JS 접근 불가, 크로스사이트 전송 차단(Strict), 2시간 만료
    SESSION_COOKIE_SECURE=not DEV_MODE,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_NAME="memo_session",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    # [방어] 대용량 요청으로 메모리/디스크를 채우는 DoS 차단
    MAX_CONTENT_LENGTH=32 * 1024,
)

# [방어] nginx 뒤에서만 X-Forwarded-* 를 신뢰. 직접 접근 시 헤더 위조로 rate limit 을 우회하는 것을 방지
if os.environ.get("TRUST_PROXY") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0, x_port=0, x_prefix=0)

CSRF_EXEMPT = {e.strip() for e in os.environ.get("MEMO_CSRF_EXEMPT", "").split(",") if e.strip()}

# 존재하지 않는 사용자 로그인 시에도 동일한 비용의 해시 검증을 수행하기 위한 더미 해시
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))

# 입력 제한
USERNAME_MIN, USERNAME_MAX = 3, 20
PASSWORD_MIN, PASSWORD_MAX = 8, 128
TITLE_MAX, CONTENT_MAX = 100, 10000

# rate limit: (버킷, 허용 횟수, 윈도우 초)
# [방어] 체커 없는 교육용 공방전이므로 강하게: 로그인 실패 IP 당 15분에 5회, 가입 IP 당 1시간에 5개
LOGIN_FAIL_LIMIT = ("login_fail", 5, 900)
REGISTER_LIMIT = ("register", 5, 3600)


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
    """테이블 생성/마이그레이션만 수행. 시드는 seed_admin() 에서 별도로 수행."""
    db_dir = os.path.dirname(DATABASE)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
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
        db.execute("CREATE INDEX IF NOT EXISTS idx_memos_user ON memos(user_id)")
        # rate limit 기록
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS rate_hits (
                bucket TEXT NOT NULL,
                key TEXT NOT NULL,
                at REAL NOT NULL
            )
            """
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_rate_hits ON rate_hits(bucket, key, at)")
    # [방어] DB 파일을 소유자만 읽고 쓸 수 있게 제한 (같은 호스트의 다른 계정이 DB 를 읽는 것 방지)
    try:
        os.chmod(DATABASE, 0o600)
    except OSError:
        pass


def seed_admin():
    """admin 계정과 admin 전용 메모를 생성/동기화. 비밀번호와 메모 내용은 항상 현재 설정값으로 맞춘다."""
    flag = load_flag()
    password_hash = generate_password_hash(resolve_admin_password())
    with sqlite3.connect(DATABASE) as db:
        admin = db.execute(
            "SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)
        ).fetchone()
        if admin is None:
            cur = db.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                (ADMIN_USERNAME, password_hash),
            )
            admin_id = cur.lastrowid
        else:
            admin_id = admin[0]
            # [방어] 환경변수만 바꾸고 재시작하면 admin 비밀번호가 교체되도록 (유출 시 즉시 회전 가능)
            db.execute(
                "UPDATE users SET password_hash = ?, is_admin = 1 WHERE id = ?",
                (password_hash, admin_id),
            )

        memo = db.execute(
            "SELECT id FROM memos WHERE user_id = ? AND title = ?", (admin_id, ADMIN_MEMO_TITLE)
        ).fetchone()
        if memo is None:
            db.execute(
                "INSERT INTO memos (user_id, title, content) VALUES (?, ?, ?)",
                (admin_id, ADMIN_MEMO_TITLE, flag),
            )
        else:
            db.execute(
                "UPDATE memos SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (flag, memo[0]),
            )


# ---------- Rate limit ----------
def client_ip():
    return request.remote_addr or "unknown"


def rate_limited(limit_spec, key):
    """윈도우 내 기록 수가 허용치 이상이면 True."""
    bucket, limit, window = limit_spec
    now = time.time()
    db = get_db()
    # 오래된 기록 정리 (가벼운 확률적 정리)
    if secrets.randbelow(20) == 0:
        db.execute("DELETE FROM rate_hits WHERE at < ?", (now - 24 * 3600,))
        db.commit()
    count = db.execute(
        "SELECT COUNT(*) FROM rate_hits WHERE bucket = ? AND key = ? AND at > ?",
        (bucket, key, now - window),
    ).fetchone()[0]
    return count >= limit


def record_hit(limit_spec, key):
    bucket = limit_spec[0]
    db = get_db()
    db.execute("INSERT INTO rate_hits (bucket, key, at) VALUES (?, ?, ?)", (bucket, key, time.time()))
    db.commit()


def clear_hits(limit_spec, key):
    bucket = limit_spec[0]
    db = get_db()
    db.execute("DELETE FROM rate_hits WHERE bucket = ? AND key = ?", (bucket, key))
    db.commit()


# ---------- Auth helper ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        # [방어] 비관리자에게는 관리자 페이지의 존재 자체를 알리지 않음 (403 대신 404)
        if not g.user["is_admin"]:
            abort(404)
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


# ---------- CSRF ----------
def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


def csp_nonce():
    """요청당 1회 생성되는 CSP nonce. 템플릿의 <style nonce> 와 응답 헤더에 같은 값이 들어간다."""
    nonce = g.get("csp_nonce")
    if not nonce:
        nonce = secrets.token_urlsafe(16)
        g.csp_nonce = nonce
    return nonce


app.jinja_env.globals["csp_nonce"] = csp_nonce


@app.before_request
def check_csrf():
    # [방어] 다른 사이트에서 로그인된 사용자의 브라우저를 이용해 메모 생성/수정/삭제/로그인을 강제하는 CSRF 차단
    if request.method != "POST":
        return None
    if request.endpoint in CSRF_EXEMPT:
        return None
    sent = request.form.get("_csrf", "")
    expected = session.get("_csrf", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, description="잘못된 요청입니다. 페이지를 새로 고친 뒤 다시 시도해주세요.")
    return None


# ---------- Security headers ----------
@app.after_request
def set_security_headers(resp):
    # [방어] 인라인 스크립트/외부 리소스 전면 차단(CSP), 클릭재킹(frame-ancestors), MIME 스니핑, 리퍼러 유출 방지
    #        스타일은 요청마다 새로 만든 nonce 가 붙은 <style> 하나만 허용. 공격자가 주입한 style 태그는 nonce 를 몰라 무시됨
    nonce = g.get("csp_nonce")
    style_src = f"'nonce-{nonce}'" if nonce else "'none'"
    resp.headers["Content-Security-Policy"] = (
        f"default-src 'none'; style-src {style_src}; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------- Templates ----------
# CSS 는 이 파일 안에 상수로 두고, 요청마다 발급되는 CSP nonce 가 붙은 <style> 하나로만 내려간다.
STYLE = """
:root {
  --bg: #f4f5f7; --card: #ffffff; --text: #1f2933; --muted: #6b7280;
  --line: #e5e7eb; --brand: #2563eb; --brand-dark: #1d4ed8;
  --danger: #dc2626; --danger-bg: #fef2f2; --ok: #166534; --ok-bg: #f0fdf4;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", "Apple SD Gothic Neo", "Noto Sans KR", sans-serif;
}
a { color: var(--brand); text-decoration: none; }
a:hover { text-decoration: underline; }
header {
  background: var(--card); border-bottom: 1px solid var(--line);
}
.bar {
  max-width: 760px; margin: 0 auto; padding: 14px 20px;
  display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap;
}
.brand { font-weight: 700; font-size: 18px; color: var(--text); }
.brand:hover { text-decoration: none; }
nav { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
nav .who { color: var(--muted); }
nav .who b { color: var(--text); }
nav .badge {
  font-size: 12px; padding: 1px 8px; border-radius: 999px;
  background: #eef2ff; color: var(--brand-dark); border: 1px solid #c7d2fe;
}
main { max-width: 760px; margin: 28px auto; padding: 0 20px; }
.card {
  background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 24px 28px; box-shadow: 0 1px 2px rgba(0,0,0,.04);
}
h2 { margin: 0 0 16px; font-size: 22px; }
.sub { color: var(--muted); font-size: 13px; margin: -8px 0 16px; }
.alert { padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; border: 1px solid; }
.alert.error { background: var(--danger-bg); border-color: #fecaca; color: var(--danger); }
.alert.info { background: var(--ok-bg); border-color: #bbf7d0; color: var(--ok); }
label { display: block; font-weight: 600; margin-bottom: 6px; font-size: 14px; }
.field { margin-bottom: 16px; }
input[type=text], input[type=password], textarea {
  width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 8px;
  font: inherit; background: #fff; color: var(--text);
}
input:focus, textarea:focus { outline: none; border-color: var(--brand); box-shadow: 0 0 0 3px rgba(37,99,235,.15); }
textarea { resize: vertical; min-height: 200px; }
.actions { display: flex; align-items: center; gap: 12px; margin-top: 8px; flex-wrap: wrap; }
.btn {
  display: inline-block; padding: 9px 16px; border-radius: 8px; border: 1px solid transparent;
  font: inherit; font-weight: 600; cursor: pointer; background: var(--brand); color: #fff;
}
.btn:hover { background: var(--brand-dark); text-decoration: none; }
.btn.secondary { background: #fff; color: var(--text); border-color: #d1d5db; }
.btn.secondary:hover { background: #f9fafb; }
.btn.danger { background: var(--danger); }
.btn.danger:hover { background: #b91c1c; }
.btn.small { padding: 5px 12px; font-size: 13px; }
.hint { color: var(--muted); font-size: 13px; }
.memo-list { list-style: none; margin: 0; padding: 0; }
.memo-list li {
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  padding: 12px 0; border-top: 1px solid var(--line);
}
.memo-list li:first-child { border-top: none; }
.memo-list a { font-weight: 600; }
.memo-list time { color: var(--muted); font-size: 13px; white-space: nowrap; }
.empty { color: var(--muted); text-align: center; padding: 28px 0; }
pre.memo {
  background: #f9fafb; border: 1px solid var(--line); border-radius: 8px;
  padding: 16px; white-space: pre-wrap; word-break: break-word; font: 14px/1.6 ui-monospace, Consolas, monospace;
}
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; font-size: 13px; background: #f9fafb; }
tr:last-child td { border-bottom: none; }
.tag { font-size: 12px; padding: 1px 8px; border-radius: 999px; background: #f3f4f6; color: var(--muted); }
.tag.admin { background: #eef2ff; color: var(--brand-dark); }
.hero { text-align: center; padding: 20px 0; }
.hero p { color: var(--muted); margin: 8px 0 20px; }
footer { text-align: center; color: var(--muted); font-size: 12px; padding: 24px; }
"""

LAYOUT = """
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} · 메모</title>
  <style nonce="{{ csp_nonce() }}">{{ style }}</style>
</head>
<body>
  <header>
    <div class="bar">
      <a class="brand" href="{{ url_for('index') }}">메모</a>
      <nav>
        {% if g.user %}
          <span class="who"><b>{{ g.user.username }}</b>{% if g.user.is_admin %} <span class="badge">관리자</span>{% endif %}</span>
          <a href="{{ url_for('memo_list') }}">내 메모</a>
          {% if g.user.is_admin %}<a href="{{ url_for('admin_users') }}">회원 관리</a>{% endif %}
          <a href="{{ url_for('logout') }}">로그아웃</a>
        {% else %}
          <a href="{{ url_for('login') }}">로그인</a>
          <a class="btn small" href="{{ url_for('register') }}">회원가입</a>
        {% endif %}
      </nav>
    </div>
  </header>
  <main>
    {% if error %}<div class="alert error">{{ error }}</div>{% endif %}
    {% if message %}<div class="alert info">{{ message }}</div>{% endif %}
    <div class="card">
      {{ body|safe }}
    </div>
  </main>
  <footer>메모 서비스</footer>
</body>
</html>
"""

INDEX_BODY = """
<div class="hero">
  {% if g.user %}
    <h2>안녕하세요, {{ g.user.username }}님</h2>
    <p>오늘의 생각을 기록해 보세요.</p>
    <a class="btn" href="{{ url_for('memo_list') }}">내 메모 보기</a>
    <a class="btn secondary" href="{{ url_for('memo_new') }}">새 메모 작성</a>
  {% else %}
    <h2>나만 볼 수 있는 메모</h2>
    <p>가입하고 로그인하면 메모를 작성하고 보관할 수 있습니다.</p>
    <a class="btn" href="{{ url_for('register') }}">시작하기</a>
    <a class="btn secondary" href="{{ url_for('login') }}">로그인</a>
  {% endif %}
</div>
"""

REGISTER_BODY = """
<h2>회원가입</h2>
<form method="post">
  <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
  <div class="field">
    <label for="username">아이디</label>
    <input id="username" type="text" name="username" value="{{ username }}" autocomplete="username" required>
  </div>
  <div class="field">
    <label for="password">비밀번호</label>
    <input id="password" type="password" name="password" autocomplete="new-password" required>
  </div>
  <div class="field">
    <label for="password2">비밀번호 확인</label>
    <input id="password2" type="password" name="password2" autocomplete="new-password" required>
  </div>
  <p class="hint">아이디는 영문/숫자/밑줄 3~20자, 비밀번호는 8자 이상입니다.</p>
  <div class="actions">
    <button class="btn" type="submit">가입하기</button>
    <span class="hint">이미 계정이 있나요? <a href="{{ url_for('login') }}">로그인</a></span>
  </div>
</form>
"""

LOGIN_BODY = """
<h2>로그인</h2>
<form method="post">
  <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
  <input type="hidden" name="next" value="{{ next }}">
  <div class="field">
    <label for="username">아이디</label>
    <input id="username" type="text" name="username" value="{{ username }}" autocomplete="username" required>
  </div>
  <div class="field">
    <label for="password">비밀번호</label>
    <input id="password" type="password" name="password" autocomplete="current-password" required>
  </div>
  <div class="actions">
    <button class="btn" type="submit">로그인</button>
    <span class="hint">계정이 없나요? <a href="{{ url_for('register') }}">회원가입</a></span>
  </div>
</form>
"""

LOGOUT_BODY = """
<h2>로그아웃</h2>
<p>정말 로그아웃 하시겠습니까?</p>
<form method="post">
  <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
  <div class="actions">
    <button class="btn" type="submit">로그아웃</button>
    <a class="btn secondary" href="{{ url_for('index') }}">취소</a>
  </div>
</form>
"""

MEMO_LIST_BODY = """
<h2>내 메모</h2>
<p class="sub">총 {{ memos|length }}개</p>
<div class="actions"><a class="btn" href="{{ url_for('memo_new') }}">새 메모 작성</a></div>
{% if memos %}
  <ul class="memo-list">
  {% for m in memos %}
    <li>
      <a href="{{ url_for('memo_detail', memo_id=m.id) }}">{{ m.title }}</a>
      <time>{{ m.updated_at }}</time>
    </li>
  {% endfor %}
  </ul>
{% else %}
  <p class="empty">아직 작성한 메모가 없습니다.</p>
{% endif %}
"""

MEMO_FORM_BODY = """
<h2>{{ heading }}</h2>
<form method="post">
  <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
  <div class="field">
    <label for="title">제목</label>
    <input id="title" type="text" name="title" value="{{ title_value }}" maxlength="100" required>
  </div>
  <div class="field">
    <label for="content">내용</label>
    <textarea id="content" name="content" rows="10" maxlength="10000">{{ content_value }}</textarea>
  </div>
  <div class="actions">
    <button class="btn" type="submit">저장</button>
    <a class="btn secondary" href="{{ cancel_url }}">취소</a>
  </div>
</form>
"""

MEMO_DETAIL_BODY = """
<h2>{{ memo.title }}</h2>
<p class="sub">작성 {{ memo.created_at }} · 수정 {{ memo.updated_at }}</p>
<pre class="memo">{{ memo.content }}</pre>
<div class="actions">
  <a class="btn" href="{{ url_for('memo_edit', memo_id=memo.id) }}">수정</a>
  <a class="btn danger" href="{{ url_for('memo_delete', memo_id=memo.id) }}">삭제</a>
  <a class="btn secondary" href="{{ url_for('memo_list') }}">목록</a>
</div>
"""

MEMO_DELETE_BODY = """
<h2>메모 삭제</h2>
<p>"<b>{{ memo.title }}</b>" 메모를 삭제합니다. 되돌릴 수 없습니다.</p>
<form method="post">
  <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
  <div class="actions">
    <button class="btn danger" type="submit">삭제</button>
    <a class="btn secondary" href="{{ url_for('memo_detail', memo_id=memo.id) }}">취소</a>
  </div>
</form>
"""

ADMIN_USERS_BODY = """
<h2>회원 관리</h2>
<p class="sub">총 {{ users|length }}명</p>
<table>
  <tr>
    <th>ID</th><th>아이디</th><th>권한</th><th>메모 수</th><th>가입일</th>
  </tr>
  {% for u in users %}
  <tr>
    <td>{{ u.id }}</td>
    <td>{{ u.username }}</td>
    <td>{% if u.is_admin %}<span class="tag admin">관리자</span>{% else %}<span class="tag">일반</span>{% endif %}</td>
    <td>{{ u.memo_count }}</td>
    <td>{{ u.created_at }}</td>
  </tr>
  {% endfor %}
</table>
"""

ERROR_BODY = """
<h2>{{ code }}</h2>
<p>{{ description }}</p>
<div class="actions"><a class="btn secondary" href="{{ url_for('index') }}">홈으로</a></div>
"""


def render(title, body_template, **ctx):
    body = render_template_string(body_template, **ctx)
    return render_template_string(LAYOUT, title=title, body=body, style=STYLE, **ctx)


# ---------- Error pages ----------
def _error_page(code, description):
    if "user" not in g:
        g.user = None
    return render(str(code), ERROR_BODY, code=code, description=description), code


@app.errorhandler(400)
def bad_request(e):
    return _error_page(400, e.description or "잘못된 요청입니다.")


@app.errorhandler(404)
def not_found(e):
    return _error_page(404, "페이지를 찾을 수 없습니다.")


@app.errorhandler(413)
def too_large(e):
    return _error_page(413, "요청이 너무 큽니다.")


@app.errorhandler(429)
def too_many(e):
    return _error_page(429, e.description or "요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")


# ---------- Validation ----------
def valid_username(username):
    if not (USERNAME_MIN <= len(username) <= USERNAME_MAX):
        return False
    # [방어] 영문/숫자/밑줄만 허용: 공백, 제어문자, 유니코드 유사문자로 admin 을 흉내내는 계정 생성 방지
    return all(c.isascii() and (c.isalnum() or c == "_") for c in username)


def safe_next_url(url):
    """내부 경로만 허용. 스킴/호스트가 있거나 // 또는 백슬래시로 시작하는 값은 거부."""
    if not url:
        return None
    # [방어] //evil.com, /\\evil.com, https://evil.com 형태의 오픈 리다이렉트 차단
    if not url.startswith("/") or url.startswith("//") or "\\" in url:
        return None
    parts = urlsplit(url)
    if parts.scheme or parts.netloc:
        return None
    return url


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
        ip = client_ip()
        # [방어] 한 IP 에서 계정을 대량 생성해 DB 를 채우거나 rate limit 을 우회하는 시도 차단
        if rate_limited(REGISTER_LIMIT, ip):
            abort(429, description="가입 요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if not username or not password:
            error = "아이디와 비밀번호를 모두 입력해주세요."
        elif not valid_username(username):
            error = "아이디는 영문/숫자/밑줄 3~20자여야 합니다."
        elif not (PASSWORD_MIN <= len(password) <= PASSWORD_MAX):
            error = f"비밀번호는 {PASSWORD_MIN}~{PASSWORD_MAX}자여야 합니다."
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
                record_hit(REGISTER_LIMIT, ip)
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
        ip = client_ip()
        # [방어] admin 비밀번호 무차별 대입(brute force) 차단: IP 당 10분에 10회 실패 시 잠금
        if rate_limited(LOGIN_FAIL_LIMIT, ip):
            abort(429, description="로그인 시도가 너무 많습니다. 10분 후 다시 시도해주세요.")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # [방어] 없는 아이디도 동일하게 해시 검증을 수행해 응답 시간 차이로 계정 존재를 추측하는 것을 어렵게 함
        stored_hash = user["password_hash"] if user is not None else _DUMMY_HASH
        ok = check_password_hash(stored_hash, password) and user is not None

        if not ok:
            record_hit(LOGIN_FAIL_LIMIT, ip)
            error = "아이디 또는 비밀번호가 올바르지 않습니다."
        else:
            clear_hits(LOGIN_FAIL_LIMIT, ip)
            # [방어] 세션 고정(session fixation) 방지: 로그인 시 기존 세션을 완전히 비우고 새로 발급
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            target = safe_next_url(next_url)
            return redirect(target or url_for("index"))

    return render(
        "로그인",
        LOGIN_BODY,
        error=error,
        username=username,
        next=next_url,
        message=request.args.get("message"),
    )


@app.route("/logout", methods=["GET", "POST"])
def logout():
    # [방어] GET 링크 하나로 강제 로그아웃시키는 것을 막기 위해 실제 로그아웃은 CSRF 토큰이 있는 POST 로만 처리
    if request.method == "POST":
        session.clear()
        return redirect(url_for("index", message="로그아웃되었습니다."))
    if g.user is None:
        return redirect(url_for("index"))
    return render("로그아웃", LOGOUT_BODY)


# ---------- Memo ----------
def get_own_memo(memo_id):
    """현재 로그인한 사용자의 메모만 반환. 없거나 남의 메모면 404."""
    # [방어] IDOR 차단: 메모 ID 와 소유자 ID 를 항상 함께 조건으로 조회. 남의 메모는 존재 여부도 노출하지 않음
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
    elif len(title) > TITLE_MAX:
        error = f"제목은 {TITLE_MAX}자 이하여야 합니다."
    elif len(content) > CONTENT_MAX:
        error = f"내용은 {CONTENT_MAX}자 이하여야 합니다."
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


# ---------- Startup ----------
# 테이블만 준비. 시드(admin/플래그)는 `python app.py init` 또는 개발 서버 기동 시에만 수행하여
# 운영에서는 플래그 파일을 읽는 단계(root)와 앱 실행 단계(전용 유저)를 분리한다.
init_db()


def main(argv):
    if len(argv) > 1 and argv[1] == "init":
        seed_admin()
        print(f"[memo] 초기화 완료: DB={DATABASE}, admin={ADMIN_USERNAME}")
        return 0
    if len(argv) > 1:
        print("사용법: python app.py [init]", file=sys.stderr)
        return 2

    seed_admin()
    print("[memo] 개발 모드로 실행합니다. 외부 노출 금지. 운영은 gunicorn + nginx 를 사용하세요.", file=sys.stderr)
    # [방어] debug=False: Werkzeug 디버거 콘솔(원격 코드 실행)과 스택트레이스 노출 차단. 127.0.0.1 에만 바인딩
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
