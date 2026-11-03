#!/bin/bash

CONTAINER="telemt"
PORT=5443
INTERVAL=10

LOG_DIR="/var/log/telemt"
DB="$LOG_DIR/clients.csv"

# Хранить историю не более 31 дня
RETENTION_DAYS=31

mkdir -p "$LOG_DIR"

if [ ! -f "$DB" ]; then
    echo "ip,first_seen,last_seen,checks,max_connections,total_connections" > "$DB"
fi

TMP=$(mktemp)
trap 'rm -f "$TMP" "$DB.tmp" "$DB.clean"' EXIT

get_clients() {
    docker exec "$CONTAINER" cat /proc/net/tcp 2>/dev/null |
    python3 - "$PORT" <<'PY'
import sys
import socket
from collections import Counter

port = int(sys.argv[1])
clients = Counter()

for line in sys.stdin:
    p = line.split()

    if len(p) < 4:
        continue

    try:
        local = p[1]
        remote = p[2]
        state = p[3]

        lp = int(local.split(":")[1], 16)

        # 01 = ESTABLISHED
        if lp != port or state != "01":
            continue

        remote_ip = remote.split(":")[0]

        ip = socket.inet_ntoa(
            int(remote_ip, 16).to_bytes(4, "little")
        )

        clients[ip] += 1

    except Exception:
        pass

for ip in sorted(clients):
    print(ip, clients[ip])
PY
}

# Удаляет записи старше RETENTION_DAYS
cleanup_old_records() {
    python3 - "$DB" "$RETENTION_DAYS" <<'PY'
import sys
import csv
from datetime import datetime, timedelta

file = sys.argv[1]
days = int(sys.argv[2])

cutoff = datetime.now() - timedelta(days=days)

try:
    with open(file, newline="") as f:
        rows = list(csv.DictReader(f))
except Exception:
    return

if not rows:
    return

kept = []

for row in rows:
    try:
        last_seen = datetime.strptime(
            row["last_seen"],
            "%Y-%m-%d %H:%M:%S"
        )

        if last_seen >= cutoff:
            kept.append(row)

    except Exception:
        # Если запись повреждена — не сохраняем её
        pass

fieldnames = [
    "ip",
    "first_seen",
    "last_seen",
    "checks",
    "max_connections",
    "total_connections"
]

with open(file + ".clean", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(kept)

import os
os.replace(file + ".clean", file)
PY
}

update_db() {
    NOW="$1"

    cp "$DB" "$DB.tmp"

    while read -r IP CONNS; do
        [ -z "$IP" ] && continue

        OLD=$(grep "^${IP}," "$DB" || true)

        if [ -n "$OLD" ]; then

            FIRST=$(echo "$OLD" | cut -d',' -f2)
            CHECKS=$(echo "$OLD" | cut -d',' -f4)
            MAX=$(echo "$OLD" | cut -d',' -f5)
            TOTAL=$(echo "$OLD" | cut -d',' -f6)

            CHECKS=$((CHECKS + 1))
            TOTAL=$((TOTAL + CONNS))

            if [ "$CONNS" -gt "$MAX" ]; then
                MAX="$CONNS"
            fi

            sed -i "/^${IP},/d" "$DB.tmp"

            echo "$IP,$FIRST,$NOW,$CHECKS,$MAX,$TOTAL" >> "$DB.tmp"

        else

            echo "$IP,$NOW,$NOW,1,$CONNS,$CONNS" >> "$DB.tmp"

        fi

    done < "$TMP"

    mv "$DB.tmp" "$DB"
}

show_screen() {

    clear

    echo "============================================================"
    echo "                 TELEMT CLIENT MONITOR"
    echo "============================================================"
    echo
    echo "Container : $CONTAINER"
    echo "Port      : $PORT"
    echo "Interval  : ${INTERVAL}s"
    echo "History   : ${RETENTION_DAYS} days"
    echo
    echo "============================================================"
    echo "CURRENT ACTIVE CLIENTS"
    echo "============================================================"
    echo

    if [ ! -s "$TMP" ]; then
        echo "Нет активных клиентов."
    else

        printf "%-20s %10s\n" "CLIENT IP" "CONNS"
        echo "----------------------------------------"

        sort "$TMP" |
        while read -r IP CONNS; do
            printf "%-20s %10s\n" "$IP" "$CONNS"
        done
    fi

    echo
    echo "============================================================"
    echo "ALL KNOWN CLIENTS (${RETENTION_DAYS} DAYS)"
    echo "============================================================"
    echo

    python3 - "$DB" <<'PY'
import sys
import csv

file = sys.argv[1]

with open(file, newline="") as f:
    rows = list(csv.DictReader(f))

if not rows:
    print("История пока пустая.")
    sys.exit()

print(
    f"{'IP':20} "
    f"{'FIRST SEEN':19} "
    f"{'LAST SEEN':19} "
    f"{'MAX':5} "
    f"{'CHECKS':7}"
)

print("-" * 78)

for r in sorted(rows, key=lambda x: x["last_seen"], reverse=True):
    print(
        f'{r["ip"]:20} '
        f'{r["first_seen"]:19} '
        f'{r["last_seen"]:19} '
        f'{r["max_connections"]:5} '
        f'{r["checks"]:7}'
    )

print()
print(f"Всего известных IP: {len(rows)}")
PY

    echo
    echo "============================================================"
    echo "LOG: $DB"
    echo "============================================================"
    echo
    echo "Хранение истории: ${RETENTION_DAYS} дней"
    echo "Последняя проверка: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Следующая проверка через ${INTERVAL} секунд..."
    echo
    echo "Ctrl+C — остановить монитор"
}

while true; do

    if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
        echo "ERROR: контейнер $CONTAINER не найден"
        sleep "$INTERVAL"
        continue
    fi

    if [ "$(docker inspect -f '{{.State.Status}}' "$CONTAINER")" != "running" ]; then
        echo "ERROR: контейнер $CONTAINER не запущен"
        sleep "$INTERVAL"
        continue
    fi

    # Сначала удаляем старые записи
    cleanup_old_records

    # Получаем текущих клиентов
    get_clients > "$TMP"

    # Обновляем базу
    update_db "$(date '+%Y-%m-%d %H:%M:%S')"

    # Ещё раз очищаем после обновления,
    # чтобы гарантировать лимит хранения
    cleanup_old_records

    # Показываем результат
    show_screen

    sleep "$INTERVAL"

done
