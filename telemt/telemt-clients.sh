#!/bin/bash

CONTAINER="telemt"
TELEMT_PORT=5443

echo
echo "============================================================"
echo "                 TELEMT ACTIVE CLIENTS"
echo "============================================================"
echo

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
    echo "ERROR: контейнер $CONTAINER не найден"
    exit 1
fi

STATUS=$(docker inspect -f '{{.State.Status}}' "$CONTAINER")

echo "Container: $CONTAINER"
echo "Status:    $STATUS"
echo "Port:      $TELEMT_PORT"
echo

if [ "$STATUS" != "running" ]; then
    echo "ERROR: контейнер не запущен"
    exit 1
fi

echo "Собираю активные TCP-соединения..."
echo

TMP=$(mktemp)

trap 'rm -f "$TMP"' EXIT

docker exec "$CONTAINER" cat /proc/net/tcp > "$TMP"

python3 - "$TMP" "$TELEMT_PORT" <<'PY'
import sys
import socket
from collections import defaultdict

filename = sys.argv[1]
telemt_port = int(sys.argv[2])

clients = defaultdict(list)

def hex_to_ip(value):
    # /proc/net/tcp хранит IPv4 в little-endian
    n = int(value, 16)
    return socket.inet_ntoa(n.to_bytes(4, "little"))

with open(filename, "r") as f:
    for line in f:
        parts = line.split()

        if len(parts) < 4:
            continue

        local = parts[1]
        remote = parts[2]
        state = parts[3]

        try:
            local_ip_hex, local_port_hex = local.split(":")
            remote_ip_hex, remote_port_hex = remote.split(":")

            local_port = int(local_port_hex, 16)
            remote_port = int(remote_port_hex, 16)

        except ValueError:
            continue

        # 01 = ESTABLISHED
        # Нас интересуют только входящие соединения,
        # где локальный порт Telemt = 5443.
        if local_port != telemt_port:
            continue

        if state != "01":
            continue

        try:
            client_ip = hex_to_ip(remote_ip_hex)
        except Exception:
            continue

        clients[client_ip].append(remote_port)

print("CONNS  CLIENT IP")
print("--------------------------------")

if not clients:
    print("Нет активных клиентов.")
else:
    for ip in sorted(clients, key=lambda x: tuple(map(int, x.split(".")))):
        ports = clients[ip]
        print(f"{len(ports):5d}  {ip}")

print("--------------------------------")
print(f"Всего уникальных IP: {len(clients)}")
print(f"Всего активных соединений: {sum(len(x) for x in clients.values())}")

if clients:
    print()
    print("Детализация:")
    print("--------------------------------")

    for ip in sorted(clients, key=lambda x: tuple(map(int, x.split(".")))):
        ports = clients[ip]
        print(f"{ip}: {len(ports)} соединений")
        print(f"  source ports: {', '.join(map(str, ports))}")
PY

echo
echo "============================================================"
echo
