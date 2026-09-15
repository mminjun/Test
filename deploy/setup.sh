#!/usr/bin/env bash
# GCP Ubuntu(22.04/24.04) 인스턴스 초기 설치 + 하드닝 스크립트.
#
# 사용:
#   1) 이 저장소를 서버에 복사 (예: /home/<user>/CI)  -- .git 은 배포 경로(/opt/memo)로 복사되지 않음
#   2) sudo ADMIN_SSH_CIDR="<내 공인 IP>/32" bash deploy/setup.sh
#      ADMIN_SSH_CIDR 를 생략하면 GCP IAP TCP 포워딩 대역(35.235.240.0/20)만 22 번을 허용한다.
#   3) 스크립트 안내에 따라 /etc/memo/flag 와 Cloudflare Origin 인증서를 넣고 `systemctl start memo`
#
# 여러 번 실행해도 안전하게(idempotent) 작성됨.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "root 로 실행하세요: sudo bash deploy/setup.sh" >&2
  exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR=/opt/memo
DATA_DIR=/var/lib/memo
CONF_DIR=/etc/memo
APP_USER=memoapp
ADMIN_SSH_CIDR="${ADMIN_SSH_CIDR:-35.235.240.0/20}"   # 기본: GCP IAP 대역

log() { printf '\n==> %s\n' "$*"; }

# ---------------------------------------------------------------- packages
log "패키지 설치"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-venv python3-pip nginx ufw fail2ban unattended-upgrades curl ca-certificates

# [방어] 보안 업데이트 자동 적용
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true

# ---------------------------------------------------------------- user & dirs
log "전용 유저/디렉터리 생성"
# [방어] 로그인 불가(nologin), 홈 없음, 시스템 계정. 앱이 뚫려도 셸/홈이 없는 최소 권한 계정
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi

install -d -m 0755 -o root -g root "$APP_DIR"
install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR"
install -d -m 0700 -o root -g root "$CONF_DIR"
install -d -m 0700 -o root -g root /etc/ssl/memo

# ---------------------------------------------------------------- app files
log "앱 파일 배치 ($APP_DIR)  -- app.py, requirements.txt 만 복사. .git/README 는 배포하지 않음"
# [방어] 소스 디렉터리는 root 소유 + 읽기 전용. memoapp 이 코드를 바꿀 수 없고 .git 도 서버에 존재하지 않음
install -m 0644 -o root -g root "$SRC_DIR/app.py" "$APP_DIR/app.py"
install -m 0644 -o root -g root "$SRC_DIR/requirements.txt" "$APP_DIR/requirements.txt"

if [[ ! -x "$APP_DIR/.venv/bin/python" ]]; then
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
chown -R root:root "$APP_DIR"
chmod -R go-w "$APP_DIR"

# ---------------------------------------------------------------- secrets
log "환경변수 파일 생성 ($CONF_DIR)"
if [[ ! -f "$CONF_DIR/memo.env" ]]; then
  # [방어] SECRET_KEY 를 서버에서 무작위 생성. 저장소/이력 어디에도 존재하지 않음
  cat > "$CONF_DIR/memo.env" <<EOF
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
MEMO_DB_PATH=$DATA_DIR/memo.db
TRUST_PROXY=1
EOF
  echo "  생성: $CONF_DIR/memo.env"
fi
if [[ ! -f "$CONF_DIR/seed.env" ]]; then
  # [방어] admin 비밀번호를 서버에서 무작위 생성
  ADMIN_PW=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
  cat > "$CONF_DIR/seed.env" <<EOF
ADMIN_PASSWORD=$ADMIN_PW
EOF
  echo "  생성: $CONF_DIR/seed.env"
  echo "  *** admin 비밀번호 (이 화면 외에는 $CONF_DIR/seed.env 에서만 볼 수 있음): $ADMIN_PW"
fi
chmod 0600 "$CONF_DIR"/*.env
chown root:root "$CONF_DIR"/*.env

if [[ -f "$CONF_DIR/flag" ]]; then
  # [방어] 플래그 파일은 root 만 읽을 수 있음. memoapp(앱 실행 유저)은 읽기 불가
  chown root:root "$CONF_DIR/flag"
  chmod 0400 "$CONF_DIR/flag"
else
  echo "  !!! $CONF_DIR/flag 가 없습니다. 운영진이 준 플래그를 아래처럼 넣어주세요:"
  echo "      printf '%s\n' 'SBOB{...}' | sudo tee $CONF_DIR/flag >/dev/null && sudo chmod 0400 $CONF_DIR/flag"
fi

# ---------------------------------------------------------------- systemd
log "systemd 유닛 설치"
install -m 0644 "$SRC_DIR/deploy/memo-seed.service" /etc/systemd/system/memo-seed.service
install -m 0644 "$SRC_DIR/deploy/memo.service" /etc/systemd/system/memo.service
systemctl daemon-reload
systemctl enable memo-seed.service memo.service >/dev/null

# ---------------------------------------------------------------- nginx
log "nginx 설정"
install -d /etc/nginx/snippets
install -m 0644 "$SRC_DIR/deploy/nginx-memo.conf" /etc/nginx/sites-available/memo
install -m 0644 "$SRC_DIR/deploy/nginx-memo-proxy.conf" /etc/nginx/snippets/memo-proxy.conf
ln -sf /etc/nginx/sites-available/memo /etc/nginx/sites-enabled/memo
# [방어] 기본 사이트(80 포트, 서버 정보 노출) 제거
rm -f /etc/nginx/sites-enabled/default
# real_ip 파일이 아직 없으면 빈 파일로 두어 nginx -t 가 통과하게 함 (아래 allowlist 스크립트가 채움)
[[ -f /etc/nginx/cloudflare-realip.conf ]] || : > /etc/nginx/cloudflare-realip.conf

if [[ ! -f /etc/ssl/memo/origin.pem || ! -f /etc/ssl/memo/origin.key ]]; then
  echo "  !!! Cloudflare Origin CA 인증서가 없습니다. 대시보드 > SSL/TLS > Origin Server 에서 발급 후:"
  echo "      /etc/ssl/memo/origin.pem (인증서), /etc/ssl/memo/origin.key (개인키, chmod 0600)"
  echo "      임시로 자체서명 인증서를 만들어 nginx 가 기동되게 합니다 (Cloudflare 'Full(strict)' 에서는 교체 필수)."
  openssl req -x509 -nodes -newkey rsa:2048 -days 30 -subj "/CN=sbfmt.shop" \
    -keyout /etc/ssl/memo/origin.key -out /etc/ssl/memo/origin.pem >/dev/null 2>&1
fi
chmod 0600 /etc/ssl/memo/origin.key
chmod 0644 /etc/ssl/memo/origin.pem
nginx -t
systemctl enable nginx >/dev/null
systemctl restart nginx

# ---------------------------------------------------------------- firewall
log "방화벽(ufw)"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
# [방어] SSH 는 지정한 대역(내 IP 또는 GCP IAP)에서만
ufw allow proto tcp from "$ADMIN_SSH_CIDR" to any port 22 comment admin-ssh
# [방어] 443 은 Cloudflare 대역만 (스크립트가 등록). 80 은 열지 않음
bash "$SRC_DIR/deploy/cloudflare-allowlist.sh"
ufw logging low
ufw --force enable
# Cloudflare 대역 변경 대비 주 1회 갱신
install -m 0755 "$SRC_DIR/deploy/cloudflare-allowlist.sh" /usr/local/sbin/cloudflare-allowlist.sh
cat > /etc/cron.weekly/cloudflare-allowlist <<'EOF'
#!/bin/sh
/usr/local/sbin/cloudflare-allowlist.sh >/var/log/cloudflare-allowlist.log 2>&1
EOF
chmod 0755 /etc/cron.weekly/cloudflare-allowlist

# ---------------------------------------------------------------- ssh
log "SSH 하드닝"
HAS_KEY=0
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [[ -s "$f" ]] && HAS_KEY=1
done
if [[ $HAS_KEY -eq 1 ]] || [[ -f /etc/ssh/sshd_config.d/*oslogin* ]] || getent passwd | grep -q oslogin; then
  install -m 0644 "$SRC_DIR/deploy/sshd-99-hardening.conf" /etc/ssh/sshd_config.d/99-hardening.conf
  if sshd -t; then
    systemctl restart ssh || systemctl restart sshd
    echo "  적용 완료. 현재 세션을 끊지 말고 새 터미널에서 SSH 접속을 먼저 확인하세요."
  else
    rm -f /etc/ssh/sshd_config.d/99-hardening.conf
    echo "  !!! sshd 설정 검증 실패. 하드닝 파일을 적용하지 않았습니다."
  fi
else
  echo "  !!! authorized_keys 가 비어 있어 SSH 하드닝을 건너뜁니다 (비밀번호 로그인 차단 시 잠길 수 있음)."
fi

# [방어] SSH 무차별 대입 자동 차단
cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
maxretry = 4
findtime = 10m
bantime  = 1h
EOF
systemctl enable fail2ban >/dev/null
systemctl restart fail2ban

# ---------------------------------------------------------------- cleanup services
log "불필요 서비스 정리"
# GCP 게스트 에이전트(google-guest-agent, google-osconfig-agent)는 유지. 아래는 있으면 끈다.
for svc in rpcbind avahi-daemon cups bluetooth ModemManager; do
  if systemctl list-unit-files "$svc.service" >/dev/null 2>&1 && systemctl is-enabled "$svc" >/dev/null 2>&1; then
    systemctl disable --now "$svc" >/dev/null 2>&1 || true
    echo "  비활성화: $svc"
  fi
done

# ---------------------------------------------------------------- start
log "앱 기동"
if [[ -f "$CONF_DIR/flag" ]]; then
  systemctl restart memo-seed.service
  systemctl restart memo.service
  sleep 1
  systemctl --no-pager --lines=5 status memo.service || true
else
  echo "  플래그 파일이 없어 앱을 기동하지 않았습니다. 파일을 넣은 뒤: sudo systemctl start memo"
fi

log "완료. 확인:"
echo "  sudo ss -tulpn                      # 열린 포트: 22(sshd), 443(nginx), 127.0.0.1:8000(gunicorn) 만 있어야 함"
echo "  sudo ufw status numbered"
echo "  sudo -u $APP_USER cat $CONF_DIR/flag  # 'Permission denied' 가 나와야 정상"
echo "  curl -sk https://127.0.0.1/ -H 'Host: sbfmt.shop' | head -3"
