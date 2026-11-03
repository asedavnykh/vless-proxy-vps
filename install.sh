#!/usr/bin/env bash
# ============================================================
#  VLESS VPN (xray Reality) + Telemt + Web-панель
#  Интерактивный установщик для чистого Ubuntu/Debian
#
#  Использование:
#    sudo ./install.sh              — установка
#    ./install.sh --gen-test        — только сгенерировать конфиги
#                                     в ./gen-test (без изменений в системе)
# ============================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST=""
GEN_ONLY=0
[ "${1:-}" = "--gen-test" ] && { GEN_ONLY=1; DEST="$REPO_DIR/gen-test"; }

# ---------- вывод ----------
G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; B=$'\033[1m'; N=$'\033[0m'
info()  { echo "${G}[+]${N} $*"; }
warn()  { echo "${Y}[!]${N} $*"; }
die()   { echo "${R}[x]${N} $*" >&2; exit 1; }
step()  { echo; echo "${B}=== $* ===${N}"; }

# ---------- опрос ----------
ask() {  # ask VAR "вопрос" [дефолт]
  local __var="$1" __q="$2" __def="${3:-}" __val
  if [ -n "$__def" ]; then
    read -r -p "$__q [$__def]: " __val || true
  else
    read -r -p "$__q: " __val || true
  fi
  printf -v "$__var" '%s' "${__val:-$__def}"
}
ask_hidden() {  # ask_hidden VAR "вопрос"
  local __var="$1" __q="$2" __val
  read -r -s -p "$__q: " __val || true; echo
  printf -v "$__var" '%s' "$__val"
}
rand_hex() { openssl rand -hex "$1"; }
gen_uuid() { python3 -c "import uuid; print(uuid.uuid4())"; }

# ============================================================
#  1. Проверки окружения
# ============================================================
preflight() {
  step "Проверки окружения"
  if [ "$GEN_ONLY" -eq 1 ]; then
    info "Режим --gen-test: конфиги будут сгенерированы в $DEST (система не меняется)"
  else
    [ "$(id -u)" -eq 0 ] || die "Запустите от root: sudo ./install.sh"
  fi
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      ubuntu|debian) info "ОС: ${PRETTY_NAME:-$ID}" ;;
      *) warn "ОС '${ID:-неизвестна}' не Ubuntu/Debian — продолжаем, но не гарантируем" ;;
    esac
  fi
  command -v python3 >/dev/null || die "Нужен python3 (apt-get install -y python3)"
  command -v openssl >/dev/null || die "Нужен openssl (apt-get install -y openssl)"
  if [ "$GEN_ONLY" -eq 0 ]; then
    command -v curl >/dev/null || die "Нужен curl (apt-get install -y curl)"
    curl -4 -s --max-time 8 https://www.google.com -o /dev/null \
      || warn "Нет доступа к интернету — установка компонентов не пройдёт"
  fi
  info "Проверки пройдены"
  local rev
  rev="$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo 'нет git')"
  info "Версия install.sh: коммит $rev"
}

# ============================================================
#  2. Сбор параметров
# ============================================================
gather_config() {
  step "Параметры установки"
  local detected=""
  [ "$GEN_ONLY" -eq 1 ] || detected="$(curl -4 -s --max-time 5 https://ifconfig.me 2>/dev/null || true)"

  ask PUBLIC_HOST   "Публичный адрес сервера (IP или домен)" "${detected:-<ПУБЛИЧНЫЙ_IP>}"
  ask XRAY_PORT     "Порт VPN (VLESS Reality)"               "8443"
  ask REALITY_SNI   "Домен-маскировка Reality (SNI)"         "www.google.com"
  ask XRAY_INSTANCE "Имя инстанса xray (файл конфига)"       "main"
  ask TELEMT_PORT   "Порт Telemt (Telegram MTProxy)"         "443"
  ask TELEMT_SNI    "Домен FakeTLS для Telemt"               "google.com"
  ask PANEL_PORT    "Порт веб-панели"                        "4443"
  ask PANEL_USER    "Логин веб-панели"                       "admin"

  if [ "$GEN_ONLY" -eq 1 ]; then
    PANEL_PASSWORD="gen-test-password"
  else
    ask_hidden PANEL_PASSWORD "Пароль веб-панели (пусто — сгенерировать)"
    if [ -z "$PANEL_PASSWORD" ]; then
      PANEL_PASSWORD="$(rand_hex 8)"
      info "Сгенерирован пароль панели: $PANEL_PASSWORD"
    fi
  fi

  ask CLIENTS "Имена VPN-клиентов через запятую" "client1"
  CLIENTS="$(echo "$CLIENTS" | tr ',' ' ' | xargs)"

  echo
  info "Сервер: $PUBLIC_HOST | VPN: $XRAY_PORT | Telemt: $TELEMT_PORT | Панель: $PANEL_PORT"
  info "Клиенты: $CLIENTS"
}

# ============================================================
#  3. Генерация конфигураций
# ============================================================
gen_xray_keys() {
  if command -v xray >/dev/null 2>&1; then
    local out
    out="$(xray x25519)"
    XRAY_PRIV="$(echo "$out" | grep -iE 'private' | head -1 | sed 's/.*: *//')"
    XRAY_PUB="$(echo "$out"   | grep -iE 'password|public' | head -1 | sed 's/.*: *//')"
  else
    XRAY_PRIV="TEST_PRIVATE_KEY_$(rand_hex 16)"
    XRAY_PUB="TEST_PUBLIC_KEY_$(rand_hex 16)"
    warn "xray не установлен — ключи тестовые (перегенерируйте после установки xray)"
  fi
  XRAY_SID="$(rand_hex 4)"
}

gen_xray_config() {
  step "Генерация конфигурации xray"
  local dir="$DEST/usr/local/etc/xray"
  mkdir -p "$dir"
  PUBLIC_HOST="$PUBLIC_HOST" XRAY_PORT="$XRAY_PORT" REALITY_SNI="$REALITY_SNI" \
  XRAY_PRIV="$XRAY_PRIV" XRAY_PUB="$XRAY_PUB" XRAY_SID="$XRAY_SID" \
  CLIENTS="$CLIENTS" XRAY_TAG="vless-8443" XRAY_API="127.0.0.1:10085" \
  python3 - "$dir/$XRAY_INSTANCE.json" <<'PYEOF'
import json, os, sys, uuid

clients = []
for name in os.environ["CLIENTS"].split():
    clients.append({
        "id": str(uuid.uuid4()),
        "flow": "xtls-rprx-vision",
        "email": name,
        "level": 0,
    })

cfg = {
    "log": {"loglevel": "warning"},
    "inbounds": [{
        "listen": "0.0.0.0",
        "port": int(os.environ["XRAY_PORT"]),
        "protocol": "vless",
        "settings": {"clients": clients, "decryption": "none"},
        "streamSettings": {
            "network": "raw",
            "security": "reality",
            "realitySettings": {
                "target": os.environ["REALITY_SNI"] + ":443",
                "serverNames": [os.environ["REALITY_SNI"]],
                "privateKey": os.environ["XRAY_PRIV"],
                "shortIds": [os.environ["XRAY_SID"]],
            },
        },
        "tag": os.environ["XRAY_TAG"],
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    }],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    "api": {
        "tag": "api",
        "listen": os.environ["XRAY_API"],
        "services": ["HandlerService", "StatsService"],
    },
    "stats": {},
    "policy": {
        "levels": {"0": {
            "statsUserUplink": True, "statsUserDownlink": True, "statsUserOnline": True,
        }},
        "system": {
            "statsInboundUplink": True, "statsInboundDownlink": True,
            "statsOutboundUplink": True, "statsOutboundDownlink": True,
        },
    },
}

# имена/uuid — для итоговой выдачи ссылок
linkinfo = [{"name": c["email"], "uuid": c["id"]} for c in clients]
with open(sys.argv[1], "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
with open(sys.argv[1] + ".clients.json", "w") as f:
    json.dump(linkinfo, f, indent=2)
PYEOF
  info "Конфиг xray: $dir/$XRAY_INSTANCE.json (клиентов: $(echo "$CLIENTS" | wc -w | xargs))"
}

gen_telemt() {
  step "Генерация конфигурации telemt"
  local dir="$DEST/opt/telemt"
  mkdir -p "$dir/config" "$dir/data"
  sed -e "s/__TELEMT_PORT__/$TELEMT_PORT/g" \
      "$REPO_DIR/telemt/docker-compose.yml" > "$dir/docker-compose.yml"
  sed -e "s/__PUBLIC_HOST__/$PUBLIC_HOST/g" \
      -e "s/__PUBLIC_PORT__/$TELEMT_PORT/g" \
      -e "s/__TLS_DOMAIN__/$TELEMT_SNI/g" \
      "$REPO_DIR/telemt/config.toml.example" > "$dir/config/config.toml"
  cat > "$dir/.env" <<EOF
PUBLIC_HOST=$PUBLIC_HOST
PROXY_SECRET=$(rand_hex 16)
API_TOKEN=$(rand_hex 32)
EOF
  chmod 600 "$dir/.env"
  info "Конфиг telemt: $dir (порт $TELEMT_PORT)"
}

gen_panel() {
  step "Установка веб-панели"
  local dir="$DEST/opt/telemt-web" vdir="$DEST/var/lib/telemt-web"
  mkdir -p "$dir" "$vdir"
  cp "$REPO_DIR/web/server.py" "$REPO_DIR/web/xray_panel.py" \
     "$REPO_DIR/web/qrcode.js" "$dir/"
  cat > "$dir/.env" <<EOF
PANEL_USER=$PANEL_USER
PANEL_PASSWORD=$PANEL_PASSWORD
PANEL_PORT=$PANEL_PORT
PANEL_HOME=$dir
DATA_DIR=$vdir

TELEMT_API=http://127.0.0.1:9091
TELEMT_CONTAINER=telemt
TELEMT_CONFIG=$DEST/opt/telemt/config/config.toml
TELEMT_ENV=$DEST/opt/telemt/.env

XRAY_BIN=$(command -v xray >/dev/null 2>&1 && command -v xray || echo /usr/local/bin/xray)
XRAY_CONFIG=$DEST/usr/local/etc/xray/$XRAY_INSTANCE.json
XRAY_SERVICE=xray@$XRAY_INSTANCE.service
XRAY_API=127.0.0.1:10085
XRAY_TAG=vless-8443
XRAY_PORT=$XRAY_PORT
XRAY_PUBLIC_HOST=$PUBLIC_HOST
XRAY_STATE=$vdir/xray-disabled-users.json
XRAY_HISTORY=$vdir/xray_history.jsonl
EOF
  chmod 600 "$dir/.env"
  mkdir -p "$DEST/etc/systemd/system"
  sed -e "s|__PANEL_HOME__|$dir|g" \
      "$REPO_DIR/web/telemt-web.service" > "$DEST/etc/systemd/system/telemt-web.service"
  info "Панель: $dir (порт $PANEL_PORT)"
}

# ============================================================
#  4. Установка компонентов
# ============================================================
install_deps() {
  step "Установка компонентов"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates python3 openssl

  if ! command -v docker >/dev/null 2>&1; then
    info "Установка Docker..."
    curl -fsSL https://get.docker.com | sh
  fi
  docker info >/dev/null 2>&1 || die "Docker не запустился"
  info "Docker: $(docker --version | head -1)"

  if ! command -v xray >/dev/null 2>&1; then
    info "Установка xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  fi
  info "Xray: $(xray version 2>/dev/null | head -1)"
  systemctl daemon-reload
}

# ============================================================
#  5. Запуск сервисов
# ============================================================
start_services() {
  step "Запуск сервисов"

  # юнит xray@ (шаблонный) — ставим один раз
  if [ ! -f /etc/systemd/system/xray@.service ]; then
    cp "$REPO_DIR/xray/xray@.service" /etc/systemd/system/xray@.service
    systemctl daemon-reload
  fi

  # проверка конфига (синтаксис команды зависит от версии xray)
  if xray run -test -config "/usr/local/etc/xray/$XRAY_INSTANCE.json" >/dev/null 2>&1 \
     || xray test -config "/usr/local/etc/xray/$XRAY_INSTANCE.json" >/dev/null 2>&1; then
    info "Конфиг xray корректен"
  else
    die "Конфиг xray не прошёл проверку"
  fi

  # telemt пишет свой конфиг из-под uid 65532 (nonroot в образе)
  if chown -R 65532:65532 /opt/telemt 2>/dev/null; then
    info "Права /opt/telemt: 65532 (nonroot) — telemt может писать конфиг"
  else
    warn "Не удалось выставить права 65532 на /opt/telemt — создание пользователей telemt может падать"
  fi

  info "Запуск telemt (docker compose)..."
  ( cd /opt/telemt && docker compose up -d )

  systemctl enable --now "xray@$XRAY_INSTANCE" >/dev/null 2>&1
  systemctl enable --now telemt-web >/dev/null 2>&1

  sleep 2
  systemctl is-active --quiet "xray@$XRAY_INSTANCE" && info "xray@$XRAY_INSTANCE: работает" \
    || warn "xray@$XRAY_INSTANCE: не активен (journalctl -u xray@$XRAY_INSTANCE)"
  docker ps --format '{{.Names}}' | grep -q '^telemt$' && info "telemt: работает" \
    || warn "telemt: контейнер не поднялся (docker logs telemt)"
  systemctl is-active --quiet telemt-web && info "telemt-web (панель): работает" \
    || warn "telemt-web: не активен (journalctl -u telemt-web)"

  # брандмауэр — только если ufw уже включён
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw allow "$XRAY_PORT"/tcp >/dev/null
    ufw allow "$TELEMT_PORT"/tcp >/dev/null
    ufw allow "$PANEL_PORT"/tcp >/dev/null
    info "ufw: порты $XRAY_PORT, $TELEMT_PORT, $PANEL_PORT открыты"
  fi
}

# ============================================================
#  6. Итоговая сводка
# ============================================================
summary() {
  step "Готово"
  local links=""
  links="$(PUBLIC_HOST="$PUBLIC_HOST" XRAY_PORT="$XRAY_PORT" REALITY_SNI="$REALITY_SNI" \
           XRAY_PUB="$XRAY_PUB" XRAY_SID="$XRAY_SID" \
           CLIENTS_FILE="$DEST/usr/local/etc/xray/$XRAY_INSTANCE.json.clients.json" \
           python3 - <<'PYEOF'
import json, os
with open(os.environ["CLIENTS_FILE"]) as f:
    for c in json.load(f):
        link = (f"vless://{c['uuid']}@{os.environ['PUBLIC_HOST']}:{os.environ['XRAY_PORT']}"
                f"?security=reality&sni={os.environ['REALITY_SNI']}&fp=chrome"
                f"&pbk={os.environ['XRAY_PUB']}&sid={os.environ['XRAY_SID']}"
                f"&type=tcp&flow=xtls-rprx-vision#{c['name']}")
        print(f"{c['name']}: {link}")
PYEOF
)"
  echo "$links" | tee "$DEST/vless-links.txt"
  echo
  info "Веб-панель:  http://$PUBLIC_HOST:$PANEL_PORT/  (логин: $PANEL_USER)"
  info "VPN (VLESS Reality):  порт $XRAY_PORT — ссылки клиентов выше (vless-links.txt)"
  info "Telemt (Telegram MTProxy):  порт $TELEMT_PORT"
  echo
  warn "Сохраните ссылки клиентов и пароль панели. Смена пароля: /opt/telemt-web/.env"
}

# ============================================================
main() {
  preflight
  gather_config
  # компоненты ставим ДО генерации: нужны бинарь xray (ключи x25519) и docker
  [ "$GEN_ONLY" -eq 1 ] || install_deps
  gen_xray_keys
  gen_xray_config
  gen_telemt
  gen_panel
  if [ "$GEN_ONLY" -eq 1 ]; then
    summary
    info "Режим --gen-test: файлы в $DEST, система не изменена"
    exit 0
  fi
  start_services
  summary
}
main
