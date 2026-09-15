# GCP Ubuntu 배포 및 서버 하드닝

대상: GCP Compute Engine, Ubuntu 22.04/24.04 LTS, 도메인 `sbfmt.shop` (Cloudflare 프록시).
트래픽 경로: 참가자 → Cloudflare → nginx(443, Origin CA 인증서) → gunicorn(127.0.0.1:8000, memoapp 유저).

## 0. 열어야 할 포트 요약

| 포트 | 대상 | 허용 소스 | 비고 |
|---|---|---|---|
| 443/tcp | nginx | Cloudflare IP 대역만 | `deploy/cloudflare-allowlist.sh` 가 ufw 규칙 생성, 주 1회 자동 갱신 |
| 22/tcp | sshd | 내 공인 IP/32 또는 GCP IAP 대역 `35.235.240.0/20` | 키 인증만 |
| 80/tcp | 열지 않음 | | HTTP→HTTPS 는 Cloudflare 가 처리 |
| 8000/tcp | gunicorn | 127.0.0.1 만 | 외부 미노출 |
| 5000/tcp | 개발 서버 | 사용 안 함 | 운영에서 `python app.py` 실행 금지 |

GCP VPC 방화벽과 인스턴스 안의 ufw, 두 겹으로 같은 정책을 건다.

## 1. GCP 인스턴스 준비

```bash
# 1) 인스턴스 생성 (예시. e2-small 로 충분)
gcloud compute instances create memo-server \
  --zone=asia-northeast3-a --machine-type=e2-small \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --tags=memo-web --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring

# 2) 기본 SSH 전체 개방 규칙 제거 (프로젝트에 존재하면)
gcloud compute firewall-rules delete default-allow-ssh default-allow-rdp default-allow-icmp --quiet

# 3) SSH 는 IAP 대역만 (또는 --source-ranges="<내IP>/32")
gcloud compute firewall-rules create memo-allow-ssh-iap \
  --direction=INGRESS --action=ALLOW --rules=tcp:22 \
  --source-ranges=35.235.240.0/20 --target-tags=memo-web

# 4) 443 은 Cloudflare 대역만
CF_RANGES=$( (curl -s https://www.cloudflare.com/ips-v4; echo; curl -s https://www.cloudflare.com/ips-v6) | paste -sd, )
gcloud compute firewall-rules create memo-allow-https-cloudflare \
  --direction=INGRESS --action=ALLOW --rules=tcp:443 \
  --source-ranges="$CF_RANGES" --target-tags=memo-web

# 5) 접속 (IAP 터널)
gcloud compute ssh memo-server --zone=asia-northeast3-a --tunnel-through-iap
```

OS Login 을 켜 두면 SSH 키가 IAM 으로 관리되고 비밀번호 로그인은 처음부터 없다.
`gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE`

## 2. 앱 설치 (자동 스크립트)

서버에 저장소를 복사한 뒤 root 로 한 번 실행한다. 여러 번 실행해도 안전하다.

```bash
# 저장소 복사 (이 디렉터리는 배포 경로가 아니다. 스크립트가 app.py, requirements.txt 만 /opt/memo 로 복사)
git clone https://github.com/mminjun/Test.git ~/CI
cd ~/CI

# 내 IP 에서만 SSH 를 허용하려면 ADMIN_SSH_CIDR 지정. 생략 시 IAP 대역
sudo ADMIN_SSH_CIDR="203.0.113.10/32" bash deploy/setup.sh
```

스크립트가 하는 일: 패키지 설치, `memoapp` 시스템 유저 생성, `/opt/memo` 에 venv 구성, `/etc/memo/memo.env`(SECRET_KEY 무작위) 와 `/etc/memo/seed.env`(admin 비밀번호 무작위) 생성, systemd 유닛 2개 등록, nginx 설정, ufw(Cloudflare 443 + 관리자 22), sshd 하드닝, fail2ban, 자동 보안 업데이트, 불필요 서비스 비활성화.

스크립트가 출력하는 **admin 비밀번호를 기록**해 둔다. 다시 보려면 `sudo cat /etc/memo/seed.env`.

### 2-1. 플래그 파일 넣기

```bash
printf '%s\n' 'SBOB{운영진이_준_값}' | sudo tee /etc/memo/flag >/dev/null
sudo chown root:root /etc/memo/flag && sudo chmod 0400 /etc/memo/flag
sudo systemctl restart memo-seed memo
```

플래그가 바뀌면 파일만 교체하고 `sudo systemctl restart memo-seed memo` 하면 admin 메모 내용이 갱신된다.

### 2-2. Cloudflare Origin CA 인증서

Cloudflare 대시보드 → SSL/TLS → Origin Server → Create Certificate (호스트 `sbfmt.shop`, `*.sbfmt.shop`, 15년).

```bash
sudo tee /etc/ssl/memo/origin.pem >/dev/null   # 인증서 PEM 붙여넣기
sudo tee /etc/ssl/memo/origin.key >/dev/null   # 개인키 PEM 붙여넣기
sudo chmod 0600 /etc/ssl/memo/origin.key
sudo nginx -t && sudo systemctl reload nginx
```

### 2-3. Cloudflare 대시보드 설정

- DNS: `A sbfmt.shop → <인스턴스 외부 IP>` **Proxied(주황 구름)**. `www` 도 동일하거나 CNAME.
- SSL/TLS → Overview: **Full (strict)**
- SSL/TLS → Edge Certificates: Always Use HTTPS ON, Minimum TLS 1.2, HSTS 켜기(선택)
- SSL/TLS → Origin Server → **Authenticated Origin Pulls ON** (권장). 켠 뒤 `nginx-memo.conf` 의 `ssl_client_certificate` 두 줄 주석 해제, CA 파일은 Cloudflare 문서의 `authenticated_origin_pull_ca.pem` 을 `/etc/ssl/memo/` 에 저장.
- Security → WAF: Managed rules ON. Rate limiting rule 추가 예: `/login` 경로 1분 20회 초과 시 차단.
- Security → Bots: Bot Fight Mode ON
- Caching: 앱이 `Cache-Control: no-store` 를 보내므로 별도 설정 불필요. Development Mode 는 OFF.

### 2-4. 수동으로 할 경우의 핵심 명령

```bash
sudo apt install -y python3-venv nginx ufw fail2ban unattended-upgrades
sudo useradd --system --no-create-home --home-dir /var/lib/memo --shell /usr/sbin/nologin memoapp
sudo install -d -m 0755 /opt/memo && sudo install -d -m 0700 -o memoapp -g memoapp /var/lib/memo
sudo install -d -m 0700 /etc/memo
sudo cp app.py requirements.txt /opt/memo/
sudo python3 -m venv /opt/memo/.venv && sudo /opt/memo/.venv/bin/pip install -r /opt/memo/requirements.txt
# /etc/memo/memo.env, seed.env 는 deploy/*.env.example 참고해 작성 후 chmod 0600
sudo cp deploy/memo-seed.service deploy/memo.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now memo-seed memo
```

## 3. 실행 유저 분리가 어떻게 동작하는가

| 단계 | 유저 | 읽는 것 | 쓰는 것 |
|---|---|---|---|
| `memo-seed.service` (`python app.py init`) | root | `/etc/memo/flag` (0400), `/etc/memo/seed.env` (0600) | `/var/lib/memo/memo.db` 에 admin + 메모 시드 → 끝나면 `chown memoapp` |
| `memo.service` (gunicorn) | memoapp | `/etc/memo/memo.env` 는 systemd 가 root 로 읽어 환경으로 주입. `/opt/memo` 읽기 전용 | `/var/lib/memo` 만 쓰기 가능 |

memoapp 프로세스에서 `/etc/memo/flag` 는 파일 권한으로 거부되고, `InaccessiblePaths` 로 네임스페이스에서도 보이지 않는다. `ProtectSystem=strict` 라 `/opt/memo/app.py` 도 변조할 수 없다.

검증:
```bash
sudo -u memoapp cat /etc/memo/flag        # Permission denied 여야 정상
sudo -u memoapp cat /etc/memo/seed.env    # Permission denied
sudo systemctl show memo -p User,NoNewPrivileges,ProtectSystem
sudo systemd-analyze security memo.service # 점수 확인 (낮을수록 좋음, 2점대 목표)
```

## 4. SSH 하드닝

`deploy/sshd-99-hardening.conf` 를 `/etc/ssh/sshd_config.d/99-hardening.conf` 로 설치한다 (setup.sh 가 authorized_keys 존재 시 자동 적용).

핵심: `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `AuthenticationMethods publickey`, `PermitRootLogin no`, `MaxAuthTries 3`, 포워딩/X11 비활성.

적용 순서 (잠금 방지):
1. 현재 세션은 유지한 채 **새 터미널**에서 키로 접속되는지 확인
2. `sudo sshd -t` 로 문법 확인 후 `sudo systemctl restart ssh`
3. 다시 새 터미널로 접속 확인 후 기존 세션 종료

특정 계정만 허용하려면 파일 끝의 `AllowUsers` 주석을 해제하고 GCP 계정명을 넣는다.

## 5. 방화벽 (ufw)

setup.sh 가 아래 상태로 만든다.

```
Default: deny (incoming), allow (outgoing)
22/tcp   ALLOW  <ADMIN_SSH_CIDR>          # admin-ssh
443/tcp  ALLOW  <Cloudflare v4/v6 대역>    # cloudflare (약 22개 규칙)
```

확인과 갱신:
```bash
sudo ufw status numbered
sudo /usr/local/sbin/cloudflare-allowlist.sh   # Cloudflare 대역 수동 갱신 (주 1회 cron 자동)
```

내 IP 가 바뀌어 SSH 가 막히면 GCP 콘솔의 IAP SSH(브라우저) 로 들어가 `sudo ufw allow from <새IP>/32 to any port 22` 를 추가한다. IAP 대역을 기본 허용으로 둔 이유가 이것이다.

## 6. 불필요한 서비스/포트 정리

```bash
sudo ss -tulpn          # 기대값: 22 sshd, 443 nginx, 127.0.0.1:8000 gunicorn, 127.0.0.53 systemd-resolved 만
systemctl list-units --type=service --state=running
```

setup.sh 가 `rpcbind avahi-daemon cups bluetooth ModemManager` 를 발견하면 끈다. GCP 이미지 기본 구성에서는 대부분 없다.
유지해야 하는 것: `google-guest-agent`, `google-osconfig-agent`, `systemd-resolved`, `unattended-upgrades`, `fail2ban`, `nginx`, `memo`.

snapd 가 필요 없으면 `sudo apt purge -y snapd` 로 제거 가능 (Ubuntu 24.04 GCP 이미지에는 포함). 필수 아님.

## 7. 운영 중 점검 명령

```bash
sudo systemctl status memo memo-seed nginx
sudo journalctl -u memo -f                          # gunicorn 로그 (access/error)
sudo tail -f /var/log/nginx/memo.access.log
sudo fail2ban-client status sshd
curl -sI https://sbfmt.shop/ | grep -iE 'content-security|x-frame|server'
```

admin 비밀번호 회전: `/etc/memo/seed.env` 수정 → `sudo systemctl restart memo-seed memo`.
flag 회전: `/etc/memo/flag` 교체 → 같은 명령.
코드 업데이트: 저장소 pull → `sudo bash deploy/setup.sh` 재실행 (app.py 재복사 + 재기동).

## 8. CSRF 면제 스위치 (기본: 사용 안 함)

교육과정 공방전에는 자동 채점 봇(체커)이 없으므로 이 스위치는 필요 없다. 모든 POST 에 CSRF 토큰을 요구하는 기본 상태를 유지한다.
훗날 폼을 GET 하지 않고 `/login` 에 바로 POST 하는 외부 도구를 붙여야 할 때만 `/etc/memo/memo.env` 에 `MEMO_CSRF_EXEMPT=login,register` 를 추가하고 재시작한다.
