# 보안 분석 및 방어 내역

교육용 공방(attack-defense) CTF 배틀그라운드용 메모 서비스. 목표는 admin 메모에 들어 있는 flag 에 도달하는 모든 경로를 차단하는 것.

## 1. 프로젝트 개요

| 항목 | 내용 |
|---|---|
| 언어 / 프레임워크 | Python 3, Flask 3.1, Werkzeug 3.1, Jinja2 (Flask 내장) |
| DB | SQLite (`sqlite3` 표준 모듈, 파라미터 바인딩) |
| 구조 | `app.py` 단일 파일. 라우트, 템플릿 문자열, DB 초기화 모두 포함 |
| 운영 실행 | `gunicorn app:app` (systemd `memo.service`, 유저 `memoapp`, `127.0.0.1:8000`) |
| 초기화 | `python app.py init` (systemd `memo-seed.service`, root, 플래그 파일 읽어 시드) |
| 개발 실행 | `python app.py` (`127.0.0.1:5000`, 임시 SECRET_KEY, 임시 admin 비밀번호 출력) |
| 프론트 | nginx 443 (Cloudflare Origin CA) → gunicorn. 80 미개방 |

라우트: `/`, `/register`, `/login`, `/logout`, `/memos`, `/memos/new`, `/memos/<id>`, `/memos/<id>/edit`, `/memos/<id>/delete`, `/admin`

## 2. flag 저장 방식

### 수정 전

| 위치 | 상태 |
|---|---|
| `app.py` 소스 리터럴 | `ADMIN_MEMO_CONTENT` 기본값으로 하드코딩. **공개 GitHub 저장소(mminjun/Test)에 커밋됨** |
| 환경변수 `ADMIN_MEMO_CONTENT` | 선택. 앱 프로세스 환경에 노출 |
| SQLite `memos` 테이블 | admin(user_id=1) 소유 memo id=1 의 `content` 컬럼 |

### 수정 후 (현재 코드)

| 위치 | 상태 |
|---|---|
| `/etc/memo/flag` 파일 | root:root 0400. `FLAG_FILE` 환경변수로 지정. **앱 실행 유저 memoapp 은 읽을 수 없음**. systemd `InaccessiblePaths` 로 한 겹 더 |
| SQLite `memos` 테이블 | admin 소유 메모 `content`. 시드 유닛(root)이 파일을 읽어 기록. 앱은 이 DB 를 읽어 admin 에게만 보여줌 |
| `app.py` 소스 리터럴 | **제거됨**. 개발 모드에서만 `SBOB{dev_dummy_flag_not_real}` 더미값 사용. 운영 모드는 파일/환경변수 없으면 init 거부 |
| 환경변수 `ADMIN_MEMO_CONTENT` | FLAG_FILE 대신 쓸 수 있으나 프로세스 환경에 노출되므로 비권장 |

앱이 admin 에게 flag 를 보여줘야 하므로 DB 사본을 앱 유저가 읽는 것은 피할 수 없다. 따라서 방어의 핵심은 (1) 인증/인가 계층이 뚫리지 않는 것, (2) 앱 유저 권한으로 코드가 실행돼도 flag 파일 원본과 시드 비밀은 못 읽게 하는 것, 두 축이다.

## 3. 발견된 취약점 (수정 전 코드 기준)

flag 도달 경로가 되는 것부터 심각도 순.

| # | 심각도 | 취약점 | flag 도달 경로 | 상태 |
|---|---|---|---|---|
| 1 | **치명** | flag 값이 소스에 하드코딩되어 공개 저장소 이력에 존재 | GitHub 에서 `app.py` 열람 → 즉시 flag | 소스에서 제거 완료. 새 flag 는 서버 파일에만 둔다 (구 값은 소각) |
| 2 | **치명** | `SECRET_KEY` 기본값 `dev-secret-key-change-me` 가 소스/이력에 존재 | 키로 `{"user_id":1}` 세션 쿠키 서명 위조 → admin 세션 → `/memos/1` | 수정 완료 |
| 3 | **치명** | admin 기본 비밀번호 `admin1234!` 가 소스/이력에 존재 | `/login` 에 그대로 입력 → admin | 수정 완료 |
| 4 | **치명** | `app.run(debug=True)` | 예외 발생 시 Werkzeug 인터랙티브 콘솔 → 원격 코드 실행 → DB/파일 전부. 트레이스백으로 소스·경로 노출 | 수정 완료 |
| 5 | 높음 | 로그인 시도 제한 없음 | admin 비밀번호 무차별 대입 | 수정 완료 |
| 6 | 높음 | 세션 쿠키에 `Secure`/`SameSite` 미설정, 만료 31일 | 평문 구간 스니핑·장기 재사용으로 admin 세션 탈취 | 수정 완료 |
| 7 | 중간 | CSRF 방어 없음 (로그인, 메모 생성/수정/삭제, 로그아웃이 GET) | 직접적인 flag 유출은 아니지만 admin 브라우저를 통한 메모 변조·삭제 → 체커 실패(SLA 손실) | 수정 완료 |
| 8 | 중간 | Flask 기본 `/static/` 라우트 활성 | 현재 `static/` 폴더가 없어 실제 노출은 없음. 배포 중 실수로 폴더가 생기면 파일 서빙 | 수정 완료 (라우트 제거) |
| 9 | 중간 | DB 파일이 소스 디렉터리(`memo.db`)에 위치 | 리버스 프록시 루트를 저장소로 잡는 실수 시 `memo.db` 다운로드 → flag | 수정 완료 (경로 분리) |
| 10 | 중간 | `.git` 디렉터리가 배포 경로에 함께 존재할 위험 | 정적 서빙 실수 시 `.git` 복원 → 이력에서 flag/비밀번호 | 수정 완료 (배포 스크립트가 `.git` 미복사, nginx 가 점 경로 차단) |
| 11 | 낮음 | `next` 리다이렉트 검사에 `/\evil.com` 우회 가능 | 피싱용 오픈 리다이렉트. flag 직접 경로는 아님 | 수정 완료 |
| 12 | 낮음 | 보안 헤더 없음 (CSP, X-Frame-Options 등) | XSS 가 발견될 경우 피해 확대, 클릭재킹 | 수정 완료 |
| 13 | 낮음 | 비밀번호 최소 4자, 아이디 문자 제한 없음 | 약한 계정, 공백·제로폭 문자로 `admin` 유사 아이디 생성 | 수정 완료 |
| 14 | 낮음 | 요청 본문 크기 제한 없음 | 대용량 메모로 디스크/메모리 고갈 → 서비스 다운 | 수정 완료 |
| 15 | 낮음 | 로그인 시 없는 아이디는 해시 검증을 건너뜀 | 응답 시간 차이로 계정 존재 추측 | 수정 완료 |
| 16 | 낮음 | 비관리자 `/admin` 접근 시 403 | 관리자 페이지 존재 확인 | 수정 완료 (404) |

### 요청받은 항목 중 해당 없음으로 확인된 것

실제 코드를 기준으로 확인한 결과이며, 없는 취약점을 만들어 내지 않았다.

- **SQL Injection**: 모든 쿼리가 `?` 바인딩. 문자열 결합 없음. `ORDER BY` 는 고정 문자열.
- **Path traversal / 파일 접근**: 사용자 입력으로 파일 경로를 만드는 코드 없음. `FLAG_FILE` 은 환경변수(운영자 통제)만.
- **Command injection**: `subprocess`, `os.system`, `eval`, `exec` 미사용.
- **SSTI**: `render_template_string` 은 고정 템플릿 문자열에만 사용. 사용자 입력은 컨텍스트 변수로만 전달되며 자동 이스케이프됨.
- **XSS**: Flask 는 `render_template_string` 에 자동 이스케이프를 적용. 메모 내용은 `<pre>{{ }}</pre>` 로 이스케이프 출력. `|safe` 는 이미 렌더된 내부 템플릿 결과에만 적용.
- **안전하지 않은 역직렬화**: pickle/yaml/marshal 미사용. Flask 세션은 itsdangerous 서명 JSON (키 유출 시 위조는 가능하지만 역직렬화 RCE 는 없음).
- **SSRF**: 서버가 외부 URL 을 요청하는 코드 없음.
- **파일 업로드**: 업로드 기능 없음.
- **IDOR**: 메모 조회/수정/삭제 모두 `id = ? AND user_id = ?` 로 소유자 검사. 수정 전에도 안전했음.

## 4. 적용한 코드 수정 (각 변경이 막는 공격)

`app.py` 안에도 같은 내용이 `# [방어] ...` 주석으로 해당 줄 옆에 달려 있다.

**비밀값**
- `SECRET_KEY` 기본값 제거. 운영 모드에서 환경변수 없으면 기동 거부 → *유출된 키로 세션 쿠키 위조해 admin 되는 공격 차단*
- `ADMIN_PASSWORD` 기본값 제거. init 단계에서만 요구하고 앱 프로세스 환경에는 두지 않음 → *기본 비밀번호 로그인 차단, 앱 프로세스 환경 덤프로 비밀번호 유출 차단*
- init 마다 admin 비밀번호와 메모 내용을 설정값으로 동기화 → *유출 시 env 만 바꾸고 재시작하면 즉시 회전*
- `FLAG_FILE` 지원. 읽기 실패 시 init 중단 → *환경변수(프로세스 environ 에 노출)가 아닌 root 전용 파일에서 flag 공급*

**실행 환경**
- `debug=False`, `127.0.0.1` 바인딩 고정 → *Werkzeug 디버거 RCE, 트레이스백 정보 노출 차단*
- `Flask(static_folder=None)` → *`/static/` 경로로 어떤 파일도 서빙되지 않음*
- `MEMO_DB_PATH` 로 DB 를 `/var/lib/memo` 에 분리, 파일 0600 → *웹 루트/저장소에서 DB 다운로드 차단, 동일 호스트 타 계정의 DB 열람 차단*
- `MAX_CONTENT_LENGTH` 32KB, 메모 내용 10,000자 제한 → *대용량 요청 DoS 차단*
- `ProxyFix` 는 `TRUST_PROXY=1` 일 때만 → *직접 접근 시 `X-Forwarded-For` 위조로 rate limit 우회 차단*

**세션/인증**
- 쿠키 `Secure`, `HttpOnly`, `SameSite=Strict`, 만료 2시간, 이름 변경 → *쿠키 탈취·재사용 범위 축소, 크로스사이트 요청에 쿠키가 절대 붙지 않음*
- 로그인 성공 시 `session.clear()` 후 재발급 → *세션 고정 차단*
- 로그인 실패 IP 당 15분 5회 제한(429) → *admin 비밀번호 무차별 대입 차단*
- 가입 IP 당 1시간 5회 제한 → *계정 대량 생성으로 DB 채우기 차단*
- 없는 아이디도 더미 해시로 검증 → *타이밍 기반 계정 존재 추측 차단*
- 비관리자 `/admin` → 404 → *관리자 페이지 존재 확인 차단*

**입력/CSRF/헤더**
- 모든 POST 에 세션 기반 CSRF 토큰 필수(`hmac.compare_digest`), 로그아웃은 POST 로 변경 → *다른 사이트에서 로그인된 사용자 브라우저로 메모 변조·삭제·강제 로그아웃 시키는 공격 차단*
- `next` 파라미터: `/` 로 시작, `//`·백슬래시·스킴·호스트 거부 → *오픈 리다이렉트 차단*
- 아이디 `[A-Za-z0-9_]{3,20}`, 비밀번호 8~128자 → *약한 비밀번호, 유니코드 유사 아이디 차단, 초장문 비밀번호 해시 DoS 차단*
- `Content-Security-Policy: default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` → *혹시 XSS 가 생겨도 스크립트 실행·외부 전송 차단, 클릭재킹 차단, 캐시에 메모 내용 잔류 차단*
- 커스텀 400/404/413/429 페이지 → *프레임워크 기본 페이지의 정보 노출 제거*

**인프라 (deploy/)**
- `memo-seed.service`(root) 와 `memo.service`(memoapp) 분리, 플래그 파일 0400 root, `InaccessiblePaths` → *앱 권한 RCE 시에도 flag 파일 원본·시드 비밀 접근 불가*
- systemd 샌드박스(`ProtectSystem=strict`, `NoNewPrivileges`, `CapabilityBoundingSet=`, `ProtectProc=invisible`, syscall 필터 등) → *권한 상승, 소스 변조, 다른 프로세스 환경 열람 차단*
- nginx: Cloudflare 대역 real_ip, 점 경로 차단, `server_tokens off`, 알 수 없는 Host 는 444, `/login`·`/register` 요청 제한 → *`.git`/`.env` 요청 차단, 직접 IP 스캔 응답 없음, 프록시 단 무차별 대입 완화*
- ufw: 443 은 Cloudflare 대역만, 22 는 관리자 대역만, 80 미개방 → *origin IP 를 알아내도 Cloudflare 우회 접속 불가*
- 배포 스크립트가 `app.py`, `requirements.txt` 만 복사 → *서버에 `.git` 이 존재하지 않음*

## 5. flag 결정 사항 (확정)

교육과정 공방전으로 체커(자동 채점 봇)가 없다는 전제에서 아래로 확정했다.

1. **소스의 기본값 리터럴 제거 완료.** 구 값 `SBOB{mminjun_admin_only_memo_2026}` 은 공개 저장소 이력에 남아 있으므로 소각으로 간주하고 **사용하지 않는다.**
2. **새 flag 는 서버의 `/etc/memo/flag` 파일에만 존재.** root:root 0400. 저장소, 환경변수, 소스 어디에도 두지 않는다. 운영진이 다른 경로를 요구하면 `deploy/memo-seed.service` 의 `FLAG_FILE=` 한 줄만 바꾼다.
3. **git 이력**: `git filter-repo` 로 지워도 이미 클론된 사본은 남는다. 새 flag 가 이력에 없으므로 이력 정리는 필수는 아니지만, 저장소를 비공개로 전환하는 것을 권장한다.

## 6. 남는 위험과 운영 시 주의

- **앱 유저가 DB 를 읽을 수 있음**: admin 에게 flag 를 보여주려면 불가피. RCE 가 없는 한 flag 는 인증 뒤에 있다. RCE 벡터는 현재 코드에 없음.
- **rate limit 은 실제 IP 기준**: 반드시 `TRUST_PROXY=1` + nginx `real_ip` 가 같이 켜져야 한다. 아니면 모든 요청이 Cloudflare IP 로 보여 한 공격자의 실패 5회가 나 자신을 포함한 전원을 잠근다. `setup.sh` 가 둘 다 설정한다.
- **로그인 실패 제한은 IP 기준** (15분 5회): 공격자가 IP 를 바꿔가며 시도할 수 있지만, admin 비밀번호가 24바이트 무작위이므로 실질적으로 불가능하다. 계정 기준 잠금은 상대가 admin 을 고의로 잠가 내 접속을 막을 수 있어 채택하지 않았다.
- **SameSite=Strict**: 외부 사이트 링크로 들어오면 첫 요청에 쿠키가 붙지 않아 로그인 화면이 보일 수 있다. 직접 주소를 치거나 사이트 내 이동은 정상. 체커가 없으므로 Strict 를 선택했다.
- **내가 잠기는 경우**: 비밀번호를 15분에 5회 틀리면 내 IP 도 잠긴다. 급하면 서버에서 `sqlite3 /var/lib/memo/memo.db "DELETE FROM rate_hits;"` 로 초기화.
- **Cloudflare 설정도 방어의 일부**: SSL 모드 `Full (strict)`, DNS 레코드 프록시(주황 구름) 필수. `DNS only` 로 두면 origin IP 가 그대로 노출되고 ufw 규칙에 막혀 서비스가 안 된다.
- **Authenticated Origin Pulls** 를 켜면 IP 대역 스푸핑까지 막히는 가장 강한 조합이 된다. `nginx-memo.conf` 에 주석으로 준비되어 있다.

## 7. Docker 배포 형태에 따른 변화 (교육과정 지정 코드 적용)

`Dockerfile`, `compose.yaml`, `app.py` 실행 블록을 교육과정에서 지정한 형태로 맞췄다. 그 결과 systemd 경로와 비교해 달라지는 점과, 지정 코드가 건드리지 않는 파일로 보강한 내용이다.

| 항목 | systemd 경로 | Docker 경로 (현재 기본) | 보강 |
|---|---|---|---|
| 앱 실행 유저 | memoapp (권한 없음) | 컨테이너 안 root | 컨테이너 네임스페이스가 호스트와 격리. 앱 코드에 RCE 벡터 없음 |
| 플래그 공급 | `/etc/memo/flag` root 0400, 앱은 읽기 불가 | `.env` 의 `ADMIN_MEMO_CONTENT` → 프로세스 환경 | 앱은 환경변수를 어디에도 출력하지 않음. `.env` 는 호스트 root 0600 |
| 웹 서버 | gunicorn | Werkzeug 개발 서버 (`debug` 없음) | 디버거/트레이스백 노출 없음. nginx 가 앞단에서 요청 제한 |
| 이미지 내용 | 해당 없음 | `COPY . .` | `.dockerignore` 가 `.git`, DB, `.env`, 문서, `deploy/` 제외 |
| 8000 포트 | 127.0.0.1 만 | 0.0.0.0 (Docker 가 ufw 우회) | GCP VPC 방화벽이 443/22 만 허용 |

flag 도달 경로 관점에서 새로 생기는 것은 없다. 인증 계층, CSRF, rate limit, 헤더, 입력 제한은 실행 형태와 무관하게 동일하게 적용된다. 달라지는 것은 "앱이 뚫렸을 때" 의 2차 피해 범위이며, 현재 코드에 RCE 벡터가 없으므로 이 차이는 심층 방어의 한 겹이 얇아진 정도다.
