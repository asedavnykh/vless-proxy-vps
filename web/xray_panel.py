import copy
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode


XRAY_BIN = os.getenv("XRAY_BIN", "/usr/local/bin/xray")
XRAY_CONFIG = Path(os.getenv("XRAY_CONFIG", "/usr/local/etc/xray/native-8443.json"))
XRAY_SERVICE = os.getenv("XRAY_SERVICE", "xray@native-8443.service")
XRAY_API = os.getenv("XRAY_API", "127.0.0.1:10085")
XRAY_TAG = os.getenv("XRAY_TAG", "vless-8443")
XRAY_PUBLIC_HOST = os.getenv("XRAY_PUBLIC_HOST", "")
XRAY_PORT = int(os.getenv("XRAY_PORT", "8443"))

STATE_FILE = Path(os.getenv("XRAY_STATE", "/opt/telemt-443-web/xray-disabled-users.json"))

HISTORY_FILE = Path(os.getenv("XRAY_HISTORY", "/var/lib/telemt-443-web/xray_history.jsonl"))

HISTORY_INTERVAL = 30
_last_history_write = 0.0
_public_key_cache = None


def run_cmd(cmd, timeout=5):
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout
    )

    return (
        p.returncode,
        p.stdout.strip(),
        p.stderr.strip()
    )


def xray_api(args, timeout=5):
    cmd = [
        XRAY_BIN,
        "api",
        *args,
        f"--server={XRAY_API}"
    ]

    code, out, err = run_cmd(
        cmd,
        timeout=timeout
    )

    if code != 0:
        raise RuntimeError(
            err or out or "Xray API error"
        )

    try:
        return json.loads(out)
    except Exception as e:
        raise RuntimeError(
            "Invalid Xray API JSON: " +
            str(e) +
            "\n" +
            out[:1000]
        )


def load_config():
    with XRAY_CONFIG.open(
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def save_config(cfg):
    import os

    old_stat = XRAY_CONFIG.stat() if XRAY_CONFIG.exists() else None
    old_mode = old_stat.st_mode & 0o7777 if old_stat else 0o640

    tmp = XRAY_CONFIG.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )

    if old_stat is not None:
        os.chown(tmp, old_stat.st_uid, old_stat.st_gid)

    tmp.chmod(old_mode)
    tmp.replace(XRAY_CONFIG)


def get_inbound(cfg):
    for inbound in cfg.get("inbounds", []):
        if inbound.get("port") == XRAY_PORT:
            return inbound

    raise RuntimeError(
        "VLESS inbound on port 8443 not found"
    )


def load_disabled():
    if not STATE_FILE.exists():
        return {}

    try:
        data = json.loads(
            STATE_FILE.read_text(
                encoding="utf-8"
            )
        )

        return data if isinstance(data, dict) else {}

    except Exception:
        return {}


def save_disabled(data):
    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    STATE_FILE.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2
        ) + "\n",
        encoding="utf-8"
    )


def active_clients():
    cfg = load_config()
    inbound = get_inbound(cfg)

    return (
        inbound
        .get("settings", {})
        .get("clients", [])
    )


def current_users():
    active = active_clients()
    disabled = load_disabled()

    result = []

    for client in active:
        c = dict(client)
        c["enabled"] = True
        result.append(c)

    for email, client in disabled.items():
        c = dict(client)
        c["email"] = email
        c["enabled"] = False
        result.append(c)

    result.sort(
        key=lambda x:
            str(x.get("email", "")).lower()
    )

    return result


def stats_query():
    try:
        data = xray_api([
            "statsquery",
            "-pattern",
            "user>>>"
        ])

        rows = data.get("stat", [])

        result = {}

        for row in rows:
            name = str(
                row.get("name", "")
            )

            value = int(
                row.get("value") or 0
            )

            result[name] = value

        return result

    except Exception:
        return {}


def recursive_int(obj, keys):
    if isinstance(obj, dict):

        for key in keys:
            if key in obj:
                try:
                    return int(obj[key])
                except Exception:
                    pass

        for value in obj.values():
            found = recursive_int(
                value,
                keys
            )

            if found is not None:
                return found

    elif isinstance(obj, list):

        for value in obj:
            found = recursive_int(
                value,
                keys
            )

            if found is not None:
                return found

    return None


def online_count(email):
    try:
        data = xray_api([
            "statsonline",
            "-email",
            email
        ])

        value = recursive_int(
            data,
            (
                "online",
                "count",
                "sessions"
            )
        )

        return value or 0

    except Exception:
        return 0


def extract_ips(obj):
    text = json.dumps(
        obj,
        ensure_ascii=False
    )

    # IPv4
    found = re.findall(
        r'(?<![\d.])'
        r'(?:\d{1,3}\.){3}\d{1,3}'
        r'(?![\d.])',
        text
    )

    # IPv6-like strings
    found += re.findall(
        r'(?<![A-Za-z0-9:])'
        r'[0-9A-Fa-f:]{3,}'
        r':'
        r'[0-9A-Fa-f:]{2,}'
        r'(?![A-Za-z0-9:])',
        text
    )

    result = []

    for value in found:
        if value not in result:
            result.append(value)

    return result


def online_ips(email):
    try:
        data = xray_api([
            "statsonlineiplist",
            "-email",
            email
        ])

        return extract_ips(data)

    except Exception:
        return []


def get_private_key(cfg):
    inbound = get_inbound(cfg)

    reality = (
        inbound
        .get("streamSettings", {})
        .get("realitySettings", {})
    )

    return reality.get("privateKey")


def public_key(cfg):
    global _public_key_cache

    private_key = get_private_key(cfg)

    if not private_key:
        return ""

    if _public_key_cache:
        return _public_key_cache[0] == private_key and _public_key_cache[1]

    code, out, err = run_cmd(
        [
            XRAY_BIN,
            "x25519",
            "-i",
            private_key
        ],
        timeout=5
    )

    if code != 0:
        return ""

    value = ""

    for line in out.splitlines():
        line = line.strip()

        if "Password (PublicKey):" in line:
            value = line.split(
                "Password (PublicKey):",
                1
            )[1].strip()
            break

        if "Public key:" in line:
            value = line.split(
                "Public key:",
                1
            )[1].strip()
            break

    if value:
        _public_key_cache = (
            private_key,
            value
        )

    return value


def build_vless_link(client, cfg):
    inbound = get_inbound(cfg)

    stream = inbound.get(
        "streamSettings",
        {}
    )

    reality = stream.get(
        "realitySettings",
        {}
    )

    sni_list = reality.get(
        "serverNames",
        []
    )

    sni = (
        sni_list[0]
        if sni_list
        else ""
    )

    short_ids = reality.get(
        "shortIds",
        []
    )

    sid = (
        short_ids[0]
        if short_ids
        else ""
    )

    network = stream.get(
        "network",
        "raw"
    )

    network = (
        "tcp"
        if network == "raw"
        else network
    )

    params = {
        "type": network,
        "security": "reality",
        "sni": sni,
        "pbk": public_key(cfg),
        "sid": sid,
        "flow": client.get(
            "flow",
            "xtls-rprx-vision"
        ),
        "encryption": "none"
    }

    fp = reality.get(
        "fingerprint"
    )

    if fp:
        params["fp"] = fp

    query = urlencode(
        {
            k: v
            for k, v in params.items()
            if v not in (
                None,
                ""
            )
        }
    )

    email = str(
        client.get(
            "email",
            ""
        )
    )

    user_id = str(
        client.get(
            "id",
            ""
        )
    )

    return (
        "vless://" +
        user_id +
        "@" +
        XRAY_PUBLIC_HOST +
        ":" +
        str(XRAY_PORT) +
        "?" +
        query +
        "#" +
        quote(
            email,
            safe=""
        )
    )


def user_config_for_api(client):
    cfg = load_config()
    inbound = copy.deepcopy(
        get_inbound(cfg)
    )

    inbound["settings"][
        "clients"
    ] = [
        dict(client)
    ]

    return {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            inbound
        ],
        "outbounds": [
            {
                "protocol": "freedom"
            }
        ]
    }


def add_runtime_user(client):
    tmp_path = None

    try:

        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".json",
            delete=False
        ) as f:

            json.dump(
                user_config_for_api(client),
                f,
                ensure_ascii=False,
                indent=2
            )

            tmp_path = f.name

        code, out, err = run_cmd(
            [
                XRAY_BIN,
                "api",
                "adu",
                f"--server={XRAY_API}",
                tmp_path
            ],
            timeout=8
        )

        if code != 0:
            raise RuntimeError(
                err or out or
                "Unable to add Xray user"
            )

    finally:

        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def remove_runtime_user(email):
    code, out, err = run_cmd(
        [
            XRAY_BIN,
            "api",
            "rmu",
            f"--server={XRAY_API}",
            "-tag",
            XRAY_TAG,
            email
        ],
        timeout=8
    )

    if code != 0:
        raise RuntimeError(
            err or out or
            "Unable to remove Xray user"
        )


def service_active():
    code, out, _ = run_cmd(
        [
            "systemctl",
            "is-active",
            XRAY_SERVICE
        ],
        timeout=3
    )

    return (
        code == 0 and
        out.strip() == "active"
    )


def service_uptime():
    code, out, _ = run_cmd(
        [
            "systemctl",
            "show",
            XRAY_SERVICE,
            "--property=ActiveEnterTimestamp"
        ],
        timeout=3
    )

    if code != 0:
        return 0

    value = out.split(
        "=",
        1
    )[-1].strip()

    if not value:
        return 0

    try:
        started = datetime.strptime(
            value,
            "%a %Y-%m-%d %H:%M:%S %Z"
        ).replace(
            tzinfo=timezone.utc
        )

        return max(
            0,
            int(
                (
                    datetime.now(timezone.utc) -
                    started
                ).total_seconds()
            )
        )

    except Exception:
        return 0


def read_memory():
    total = 0
    available = 0

    try:
        for line in Path(
            "/proc/meminfo"
        ).read_text().splitlines():

            parts = line.split()

            if len(parts) < 2:
                continue

            key = parts[0].rstrip(":")

            if key == "MemTotal":
                total = int(parts[1]) * 1024

            elif key == "MemAvailable":
                available = int(parts[1]) * 1024

    except Exception:
        pass

    used = max(
        0,
        total - available
    )

    percent = (
        (used / total * 100)
        if total
        else 0
    )

    return {
        "total_bytes": total,
        "used_bytes": used,
        "percent": round(
            percent,
            1
        )
    }


def read_network():
    rx = 0
    tx = 0

    try:
        for line in Path(
            "/proc/net/dev"
        ).read_text().splitlines():

            if ":" not in line:
                continue

            iface, values = line.split(
                ":",
                1
            )

            iface = iface.strip()

            if iface == "lo":
                continue

            parts = values.split()

            if len(parts) >= 9:
                rx += int(parts[0])
                tx += int(parts[8])

    except Exception:
        pass

    return {
        "rx_bytes": rx,
        "tx_bytes": tx
    }


def read_cpu():
    try:
        load = os.getloadavg()[0]
        cores = max(
            1,
            os.cpu_count() or 1
        )

        return round(
            min(
                100,
                load / cores * 100
            ),
            1
        )
    except Exception:
        return 0.0


def system_metrics():
    disk = shutil.disk_usage("/")

    cpu = read_cpu()
    memory = read_memory()
    net = read_network()

    return {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "cpu_percent": cpu,
        "memory": memory,
        "disk": {
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
            "percent": round(
                disk.used /
                disk.total *
                100,
                1
            )
        },
        "network": net
    }


def history_append(connections, traffic):
    global _last_history_write

    now = time.time()

    if (
        now - _last_history_write
        < HISTORY_INTERVAL
    ):
        return

    _last_history_write = now

    system = system_metrics()

    row = {
        "timestamp": system["timestamp"],
        "cpu_percent": system["cpu_percent"],
        "memory_percent": system["memory"]["percent"],
        "disk_percent": system["disk"]["percent"],
        "rx_bytes": system["network"]["rx_bytes"],
        "tx_bytes": system["network"]["tx_bytes"],
        "connections": connections,
        "traffic_bytes": traffic,
        "users": len(current_users()),
    }

    HISTORY_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with HISTORY_FILE.open(
        "a",
        encoding="utf-8"
    ) as f:
        f.write(
            json.dumps(
                row,
                ensure_ascii=False
            ) + "\n"
        )


def load_history(period):
    seconds = {
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
        "31d": 2678400,
    }.get(
        period,
        86400
    )

    if not HISTORY_FILE.exists():
        return []

    cutoff = time.time() - seconds
    rows = []

    try:
        with HISTORY_FILE.open(
            "r",
            encoding="utf-8"
        ) as f:

            for line in f:
                try:
                    row = json.loads(line)
                    ts = datetime.fromisoformat(
                        row["timestamp"]
                    ).timestamp()

                    if ts >= cutoff:
                        rows.append(row)

                except Exception:
                    continue

    except Exception:
        return []

    if len(rows) <= 1400:
        return rows

    step = max(
        1,
        len(rows) // 1400
    )

    return rows[::step]


def dashboard():
    cfg = load_config()
    clients = current_users()
    stats = stats_query()

    users = []
    total_connections = 0
    total_traffic = 0

    for client in clients:

        email = str(
            client.get(
                "email",
                ""
            )
        )

        rx_name = (
            f"user>>>{email}"
            ">>>traffic>>>downlink"
        )

        tx_name = (
            f"user>>>{email}"
            ">>>traffic>>>uplink"
        )

        rx = int(
            stats.get(
                rx_name,
                0
            )
        )

        tx = int(
            stats.get(
                tx_name,
                0
            )
        )

        online = (
            online_count(email)
            if client.get("enabled", True)
            else 0
        )

        ips = (
            online_ips(email)
            if client.get("enabled", True)
            else []
        )

        total = rx + tx

        total_connections += online
        total_traffic += total

        users.append({
            "username": email,
            "email": email,
            "id": client.get("id"),
            "flow": client.get(
                "flow",
                "xtls-rprx-vision"
            ),
            "enabled": bool(
                client.get(
                    "enabled",
                    True
                )
            ),
            "current_connections": online,
            "active_unique_ips": len(ips),
            "active_unique_ips_list": ips,
            "rx_bytes": rx,
            "tx_bytes": tx,
            "total_bytes": total,
            "link": build_vless_link(
                client,
                cfg
            ),
        })

    history_append(
        total_connections,
        total_traffic
    )

    return {
        "ok": True,
        "service": {
            "running": service_active(),
            "port": XRAY_PORT,
            "connections": total_connections,
            "user_count": len(users),
            "traffic_bytes": total_traffic,
            "uptime_seconds": service_uptime(),
        },
        "reality": {
            "host": XRAY_PUBLIC_HOST,
            "port": XRAY_PORT,
            "server_names": (
                get_inbound(cfg)
                .get("streamSettings", {})
                .get("realitySettings", {})
                .get("serverNames", [])
            ),
            "short_ids": (
                get_inbound(cfg)
                .get("streamSettings", {})
                .get("realitySettings", {})
                .get("shortIds", [])
            ),
        },
        "users": users,
        "system": system_metrics(),
    }


def create_user(username):
    username = str(
        username or ""
    ).strip()

    if not re.fullmatch(
        r"[A-Za-z0-9_.@-]{1,64}",
        username
    ):
        raise ValueError(
            "Недопустимое имя пользователя"
        )

    cfg = load_config()
    disabled = load_disabled()

    for client in (
        cfg.get("inbounds", [])[0]
        .get("settings", {})
        .get("clients", [])
    ):
        if client.get("email") == username:
            raise ValueError(
                "Пользователь уже существует"
            )

    if username in disabled:
        raise ValueError(
            "Пользователь уже существует"
        )

    client = {
        "id": str(uuid.uuid4()),
        "flow": "xtls-rprx-vision",
        "email": username,
        "level": 0,
    }

    inbound = get_inbound(cfg)
    clients = inbound.setdefault(
        "settings",
        {}
    ).setdefault(
        "clients",
        []
    )

    clients.append(client)

    save_config(cfg)

    try:
        add_runtime_user(client)

    except Exception:
        clients[:] = [
            x
            for x in clients
            if x.get("email") != username
        ]
        save_config(cfg)
        raise

    return dashboard()["users"][-1]


def set_user_enabled(
    username,
    enabled
):
    cfg = load_config()
    disabled = load_disabled()

    inbound = get_inbound(cfg)

    clients = inbound.setdefault(
        "settings",
        {}
    ).setdefault(
        "clients",
        []
    )

    found = None

    for client in clients:
        if client.get("email") == username:
            found = dict(client)
            break

    if enabled:

        if found:
            return {
                "ok": True,
                "already": True
            }

        client = disabled.get(
            username
        )

        if not client:
            raise ValueError(
                "Отключенный пользователь не найден"
            )

        client = dict(client)

        clients.append(client)

        save_config(cfg)

        try:
            add_runtime_user(client)
        except Exception:
            clients[:] = [
                x
                for x in clients
                if x.get("email") != username
            ]
            save_config(cfg)
            raise

        disabled.pop(
            username,
            None
        )

        save_disabled(disabled)

        return {
            "ok": True,
            "enabled": True
        }

    if not found:

        if username in disabled:
            return {
                "ok": True,
                "already": True
            }

        raise ValueError(
            "Пользователь не найден"
        )

    try:
        remove_runtime_user(
            username
        )
    except Exception:
        pass

    disabled[username] = found
    save_disabled(disabled)

    clients[:] = [
        x
        for x in clients
        if x.get("email") != username
    ]

    save_config(cfg)

    return {
        "ok": True,
        "enabled": False
    }


def delete_user(username):
    cfg = load_config()
    disabled = load_disabled()

    inbound = get_inbound(cfg)

    clients = inbound.setdefault(
        "settings",
        {}
    ).setdefault(
        "clients",
        []
    )

    found = [
        dict(x)
        for x in clients
        if x.get("email") == username
    ]

    try:
        remove_runtime_user(
            username
        )
    except Exception:
        pass

    clients[:] = [
        x
        for x in clients
        if x.get("email") != username
    ]

    disabled.pop(
        username,
        None
    )

    save_config(cfg)
    save_disabled(disabled)

    return {
        "ok": True,
        "deleted": True
    }


def page_html():
    return r'''<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Native Xray VPN</title>

<script src="/xray/qrcode.js"></script>

<style>
:root {
    --bg: #0f1115;
    --panel: #171a21;
    --panel2: #1d212a;
    --border: #2a303c;
    --text: #edf1f7;
    --muted: #929baa;
    --green: #35d07f;
    --red: #ff5f56;
    --yellow: #ffc857;
    --blue: #58a6ff;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

header {
    padding: 20px;
    border-bottom: 1px solid var(--border);
    background: #11141a;
    position: sticky;
    top: 0;
    z-index: 10;
}

.header-row {
    max-width: 1500px;
    margin: auto;
    display: flex;
    gap: 14px;
    justify-content: space-between;
    align-items: center;
}

.title {
    font-size: 24px;
    font-weight: 700;
}

.subtitle {
    color: var(--muted);
    margin-top: 4px;
    font-size: 13px;
}

.container {
    max-width: 1500px;
    margin: auto;
    padding: 20px;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(4, minmax(0, 1fr));
    gap: 14px;
}

.grid-2 {
    display: grid;
    grid-template-columns:
        repeat(2, minmax(0, 1fr));
    gap: 14px;
}

.card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px;
}

.card-title {
    font-size: 14px;
    font-weight: 700;
    margin-bottom: 12px;
}

.metric {
    font-size: 28px;
    font-weight: 700;
}

.muted {
    color: var(--muted);
}

.status {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-weight: 700;
}

.dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    display: inline-block;
}

.dot.green {
    background: var(--green);
}

.dot.red {
    background: var(--red);
}

.dot.yellow {
    background: var(--yellow);
}

.actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}

button {
    border: 1px solid var(--border);
    background: var(--panel2);
    color: var(--text);
    padding: 9px 13px;
    border-radius: 8px;
    cursor: pointer;
}

button:hover {
    filter: brightness(1.15);
}

button.danger {
    border-color: #633338;
    color: #ff8d8d;
}

button.good {
    border-color: #285c43;
    color: #78e4a8;
}

input,
select {
    width: 100%;
    border: 1px solid var(--border);
    background: #101319;
    color: var(--text);
    padding: 9px 10px;
    border-radius: 8px;
}

.form-grid {
    display: grid;
    grid-template-columns:
        1.2fr 1fr 1fr 1fr auto;
    gap: 8px;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    border-bottom: 1px solid var(--border);
    padding: 9px 7px;
    text-align: left;
    font-size: 13px;
    vertical-align: top;
}

th {
    color: var(--muted);
    font-weight: 600;
}

code {
    word-break: break-all;
    font-size: 12px;
    color: #b9d7ff;
}

.progress {
    width: 100%;
    height: 8px;
    background: #0c0f13;
    border-radius: 4px;
    overflow: hidden;
}

.progress > div {
    height: 100%;
    background: var(--blue);
}

pre {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 420px;
    overflow: auto;
    background: #0b0d11;
    padding: 12px;
    border-radius: 8px;
    font-size: 12px;
    line-height: 1.45;
}

.spark {
    width: 100%;
    height: 90px;
    background: #101319;
    border-radius: 8px;
    border: 1px solid var(--border);
}

.badge {
    display: inline-block;
    padding: 4px 7px;
    border-radius: 7px;
    background: var(--panel2);
    color: var(--muted);
    font-size: 12px;
}

.links {
    display: flex;
    flex-direction: column;
    gap: 6px;
}

.link-row {
    background: #101319;
    padding: 9px;
    border: 1px solid var(--border);
    border-radius: 8px;
}

.small {
    font-size: 12px;
}

footer {
    color: var(--muted);
    text-align: center;
    padding: 30px;
}

@media (max-width: 1100px) {
    .grid {
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
    }

    .form-grid {
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
    }
}

@media (max-width: 700px) {
    .grid,
    .grid-2,
    .form-grid {
        grid-template-columns: 1fr;
    }

    .container {
        padding: 12px;
    }

    header {
        padding: 14px;
    }

    .title {
        font-size: 20px;
    }

    th:nth-child(n+5),
    td:nth-child(n+5) {
        display: none;
    }
}


/* ==========================================================
   Native Xray VPN specific elements
   ========================================================== */

.users-table{
    width:100%;
    border-collapse:collapse;
}

.users-table th,
.users-table td{
    text-align:left;
    padding:9px 7px;
    border-bottom:1px solid var(--border);
    vertical-align:top;
}

.users-table th{
    color:var(--muted);
    font-size:12px;
}

.users-table td{
    font-size:13px;
}

.actions{
    display:flex;
    flex-wrap:wrap;
    gap:6px;
}

.form-grid{
    display:grid;
    grid-template-columns:minmax(0,1fr) auto;
    gap:8px;
}

.form-grid input{
    width:100%;
    min-height:42px;
    padding:8px 10px;
    border-radius:7px;
    border:1px solid var(--border);
    background:#0d1218;
    color:var(--text);
}

.qr-modal{
    display:none;
    position:fixed;
    inset:0;
    z-index:10000;
    background:rgba(0,0,0,.72);
    align-items:center;
    justify-content:center;
    padding:20px;
}

.qr-modal-inner{
    width:min(420px,100%);
    background:var(--card);
    border:1px solid var(--border);
    border-radius:14px;
    padding:20px;
    text-align:center;
}

.qr-box{
    background:#fff;
    border-radius:10px;
    padding:12px;
    display:inline-block;
}

.qr-box img{
    display:block;
    width:260px;
    height:260px;
    max-width:70vw;
    max-height:70vw;
}

.qr-link{
    margin-top:12px;
    color:var(--muted);
    font-size:12px;
    word-break:break-all;
    text-align:left;
}

/* VPN traffic chart — visually same as Telegram traffic panel */
.traffic-main-panel{
    width:100%;
}

.traffic-main-metrics{
    display:grid;
    grid-template-columns:
        repeat(2,minmax(0,1fr));
    gap:30px;
    margin-bottom:12px;
}

.traffic-main-chart{
    width:100%;
    height:190px;
    background:#101319;
    border:1px solid var(--border);
    border-radius:8px;
    overflow:hidden;
}

.traffic-main-chart canvas{
    display:block;
    width:100%;
    height:100%;
}

/* Keep VPN responsive behavior */
@media (max-width:700px){

    .traffic-main-metrics{
        grid-template-columns:1fr;
        gap:10px;
    }

    .traffic-main-chart{
        height:160px;
    }

}

@media (max-width:700px) and (orientation:portrait){

    .users-table{
        width:100%;
        min-width:0;
        table-layout:fixed;
    }

    .users-table th:nth-child(n+4),
    .users-table td:nth-child(n+4){
        display:none;
    }

    .users-table th:nth-child(1),
    .users-table td:nth-child(1){
        width:38%;
    }

    .users-table th:nth-child(2),
    .users-table td:nth-child(2){
        width:24%;
    }

    .users-table th:nth-child(3),
    .users-table td:nth-child(3){
        width:38%;
    }

    .users-table td{
        overflow-wrap:anywhere;
        word-break:break-word;
    }

}

</style>

<style id="unified-header-tabs-v1">

/* ===== UNIFIED PAGE HEADER ===== */

header{
    padding:0 !important;
}

header .header-row{
    width:100% !important;
    max-width:1450px !important;
    margin:0 auto !important;
    padding:18px 20px 12px !important;
    box-sizing:border-box !important;
}

/* ===== UNIFIED NAVIGATION TABS ===== */

.panel-tabs{
    width:100% !important;
    max-width:1450px !important;
    margin:0 auto !important;
    padding:10px 20px 0 !important;
    box-sizing:border-box !important;

    display:flex !important;
    justify-content:flex-start !important;
    align-items:flex-end !important;
    gap:8px !important;

    border-bottom:1px solid var(--border) !important;
}

.panel-tabs a{
    display:inline-flex !important;
    align-items:center !important;
    justify-content:center !important;

    min-height:42px !important;
    padding:9px 14px !important;

    border-radius:8px 8px 0 0 !important;
    border:1px solid transparent !important;
    border-bottom-color:transparent !important;

    color:var(--muted) !important;
    background:transparent !important;

    text-decoration:none !important;
    box-sizing:border-box !important;
}

.panel-tabs a.active{
    color:var(--text) !important;
    background:var(--card) !important;
    border-color:var(--border) !important;
    border-bottom-color:var(--card) !important;
}

</style>


<style id="xray-top-summary-width-v1">
.top-summary{
    width:100% !important;
    max-width:none !important;
    grid-template-columns:
        repeat(3, minmax(0, 1fr)) !important;
    gap:12px !important;
    box-sizing:border-box !important;
}

@media (max-width:700px){
    .top-summary{
        grid-template-columns:1fr !important;
    }
}
</style>

</head>

<body>

<header>
<div class="header-row">
    <div>
        <div class="title">Native Xray VPN</div>
        <div class="subtitle">
            VLESS · Reality · TCP 8443
        </div>
    </div>
    <div id="lastUpdate" class="badge">—</div>
</div>
</header>

<div class="panel-tabs">
    <a href="/">Telegram</a>
    <a href="/xray" class="active">VPN</a>
</div>




<div class="container">

<div class="grid top-summary">

<div class="card">
    <div class="card-title">Сервис</div>
    <div id="serviceStatus" class="status">
        <span class="dot yellow"></span>
        проверка…
    </div>
</div>

<div class="card">
    <div class="card-title">Порт</div>
    <div class="metric">8443</div>
    <div class="muted">TCP · VLESS Reality</div>
</div>

<div class="card">
    <div class="card-title">Подключения</div>
    <div id="connections" class="metric">0</div>
    <div class="muted">сейчас</div>
</div>

</div>

<div class="history-toolbar">

    <div class="history-title">
        История
    </div>

    <button class="history-range-btn active"
            data-range="1h">
        1 час
    </button>

    <button class="history-range-btn"
            data-range="6h">
        6 часов
    </button>

    <button class="history-range-btn"
            data-range="24h">
        24 часа
    </button>

    <button class="history-range-btn"
            data-range="7d">
        7 дней
    </button>

    <button class="history-range-btn"
            data-range="31d">
        31 день
    </button>

    <div id="historyInfo"
         class="history-info">
        Загрузка…
    </div>

</div>

<div class="card">
    <div class="card-title">
        Сетевой трафик сервера
    </div>

    <div class="traffic-main-metrics">

        <div>
            <div class="small muted">RX</div>
            <div id="rxRate" class="traffic-value">
                0 Mbit/s
            </div>
        </div>

        <div>
            <div class="small muted">TX</div>
            <div id="txRate" class="traffic-value">
                0 Mbit/s
            </div>
        </div>

    </div>

    <div class="traffic-main-chart">
        <canvas id="xrayTraffic"></canvas>
    </div>
</div>

<br>

<div class="card">

    <div class="card-title">
        Пользователи Xray
    </div>

    <div style="overflow:auto">

    <table class="users-table">

    <thead>
    <tr>
        <th>Пользователь</th>
        <th>Статус</th>
        <th>IP</th>
        <th>Подключения</th>
        <th>RX / сек</th>
        <th>TX / сек</th>
        <th>Всего</th>
        <th>VLESS</th>
        <th>Управление</th>
    </tr>
    </thead>

    <tbody id="usersBody">
    <tr>
        <td colspan="9"
            class="muted">
            Загрузка…
        </td>
    </tr>
    </tbody>

    </table>

    </div>

</div>

<br>

<div class="card">

    <div class="card-title">
        Добавить пользователя
    </div>

    <div class="form-grid">

        <input
            id="newXrayUser"
            maxlength="64"
            placeholder="имя пользователя">

        <button
            class="good"
            onclick="createXrayUser()">
            Создать
        </button>

    </div>

    <div id="createResult"
         class="small muted"
         style="margin-top:8px">
    </div>

</div>

</div>

<div id="qrModal"
     class="qr-modal"
     onclick="if(event.target===this)closeQR()">

    <div class="qr-modal-inner">

        <div style="font-size:18px;font-weight:700">
            VLESS
        </div>

        <div class="qr-box"
             style="margin-top:14px">

            <div id="qrContainer"></div>

        </div>

        <div id="qrLink"
             class="qr-link">
        </div>

        <div style="margin-top:14px">
            <button class="good"
                    onclick="closeQR()">
                Закрыть
            </button>
        </div>

    </div>
</div>

<script>
let selectedRange = "1h";
let selectedRows = [];
let lastRows = [];

function esc(value){
    return String(value ?? "")
        .replace(/&/g,"&amp;")
        .replace(/</g,"&lt;")
        .replace(/>/g,"&gt;")
        .replace(/"/g,"&quot;")
        .replace(/'/g,"&#039;");
}

function fmtBytes(value){
    let n = Number(value || 0);
    const units = ["B","KB","MB","GB","TB"];
    let i = 0;

    while(n >= 1024 && i < units.length-1){
        n /= 1024;
        i++;
    }

    if(i === 0){
        return Math.round(n) + " B";
    }

    if(n >= 100){
        return n.toFixed(0) + " " + units[i];
    }

    if(n >= 10){
        return n.toFixed(1) + " " + units[i];
    }

    return n.toFixed(2) + " " + units[i];
}

function fmtDuration(seconds){
    seconds = Number(seconds || 0);

    const d = Math.floor(seconds / 86400);
    seconds %= 86400;

    const h = Math.floor(seconds / 3600);
    seconds %= 3600;

    const m = Math.floor(seconds / 60);

    if(d) return `${d} д ${h} ч`;
    if(h) return `${h} ч ${m} мин`;
    return `${m} мин`;
}

async function api(path, options={}){
    const response =
        await fetch(path, {
            cache:"no-store",
            ...options
        });

    const data =
        await response.json();

    if(!response.ok || data.ok === false){
        throw new Error(
            data.error ||
            `HTTP ${response.status}`
        );
    }

    return data;
}

function historyValue(row,key){
    return Number(row[key] || 0);
}

function drawMini(canvas, rows, key, maxValue=100, suffix="%"){
    if(!canvas || !rows.length){
        return;
    }

    const dpr = window.devicePixelRatio || 1;
    const width = Math.max(
        240,
        canvas.clientWidth || 240
    );
    const height = Math.max(
        130,
        canvas.clientHeight || 130
    );

    canvas.width = width * dpr;
    canvas.height = height * dpr;

    const ctx =
        canvas.getContext("2d");

    ctx.setTransform(
        dpr,0,0,dpr,0,0
    );

    ctx.clearRect(
        0,0,width,height
    );

    const left = 44;
    const right = 8;
    const top = 8;
    const bottom = 18;

    const pw =
        width-left-right;

    const ph =
        height-top-bottom;

    ctx.strokeStyle =
        "rgba(148,163,184,.16)";

    ctx.fillStyle =
        "rgba(148,163,184,.82)";

    ctx.font =
        "9px system-ui";

    for(let i=0;i<=4;i++){

        const ratio = i/4;
        const y =
            top + ph*ratio;

        const value =
            maxValue*(1-ratio);

        ctx.beginPath();
        ctx.moveTo(left,y);
        ctx.lineTo(left+pw,y);
        ctx.stroke();

        ctx.textAlign = "right";
        ctx.textBaseline = "middle";

        ctx.fillText(
            suffix === "%"
            ? Math.round(value)+"%"
            : fmtBytes(value),
            left-5,
            y
        );
    }

    ctx.strokeStyle =
        "rgba(148,163,184,.38)";

    ctx.beginPath();
    ctx.moveTo(left,top);
    ctx.lineTo(left,top+ph);
    ctx.lineTo(left+pw,top+ph);
    ctx.stroke();

    ctx.beginPath();

    rows.forEach((row,index)=>{
        const x =
            left +
            (
                rows.length===1
                ? 0
                : index/(rows.length-1)
            )*pw;

        const value =
            historyValue(row,key);

        const ratio =
            Math.max(
                0,
                Math.min(
                    1,
                    value/Math.max(1,maxValue)
                )
            );

        const y =
            top + ph*(1-ratio);

        if(index===0){
            ctx.moveTo(x,y);
        }else{
            ctx.lineTo(x,y);
        }
    });

    ctx.strokeStyle =
        "#58a6ff";

    ctx.lineWidth = 1.8;
    ctx.stroke();
}

function drawTraffic(canvas, rows){

    if(!canvas || !rows || !rows.length){
        return;
    }

    const data = rows.map((row, index) => ({
        rx: Number(row.rx_bytes || 0),
        tx: Number(row.tx_bytes || 0),
        timestamp: row.timestamp,
        index
    }));

    const rates = data.map((point, index) => {

        if(index === 0){
            return {
                rx: 0,
                tx: 0
            };
        }

        const prev = data[index - 1];

        const dt = Math.max(
            1,
            (
                new Date(point.timestamp) -
                new Date(prev.timestamp)
            ) / 1000
        );

        return {
            rx:
                Math.max(
                    0,
                    point.rx - prev.rx
                ) *
                8 /
                dt /
                1000000,

            tx:
                Math.max(
                    0,
                    point.tx - prev.tx
                ) *
                8 /
                dt /
                1000000
        };
    });

    const maxValue = Math.max(
        1,
        ...rates.map(
            p => Math.max(p.rx, p.tx)
        )
    );

    const dpr =
        window.devicePixelRatio || 1;

    const width =
        Math.max(
            240,
            canvas.clientWidth || 240
        );

    const height =
        Math.max(
            190,
            canvas.clientHeight || 190
        );

    canvas.width =
        Math.floor(width * dpr);

    canvas.height =
        Math.floor(height * dpr);

    const ctx =
        canvas.getContext("2d");

    ctx.setTransform(
        dpr,
        0,
        0,
        dpr,
        0,
        0
    );

    function drawGraph(activeIndex = -1){

        ctx.clearRect(
            0,
            0,
            width,
            height
        );

        const left = 52;
        const right = 8;
        const top = 8;
        const bottom = 30;

        const plotWidth =
            Math.max(
                80,
                width - left - right
            );

        const plotHeight =
            Math.max(
                60,
                height - top - bottom
            );

        /*
         * Grid + Y axis.
         */
        ctx.font =
            "9px system-ui, sans-serif";

        for(let i = 0; i <= 4; i++){

            const ratio = i / 4;

            const y =
                top +
                plotHeight * ratio;

            const value =
                maxValue * (1 - ratio);

            ctx.strokeStyle =
                "rgba(148,163,184,.16)";

            ctx.lineWidth = 1;

            ctx.beginPath();
            ctx.moveTo(left, y);
            ctx.lineTo(
                left + plotWidth,
                y
            );
            ctx.stroke();

            ctx.fillStyle =
                "rgba(148,163,184,.82)";

            ctx.textAlign = "right";
            ctx.textBaseline = "middle";

            ctx.fillText(
                value.toFixed(
                    value >= 100 ? 0 : 1
                ) + " Mbps",
                left - 6,
                y
            );
        }

        /*
         * Axes.
         */
        ctx.strokeStyle =
            "rgba(148,163,184,.38)";

        ctx.beginPath();

        ctx.moveTo(
            left,
            top
        );

        ctx.lineTo(
            left,
            top + plotHeight
        );

        ctx.lineTo(
            left + plotWidth,
            top + plotHeight
        );

        ctx.stroke();

        /*
         * Time labels.
         */
        function formatTime(value){

            const d =
                new Date(value);

            if(
                Number.isNaN(
                    d.getTime()
                )
            ){
                return "";
            }

            return d.toLocaleTimeString(
                "ru-RU",
                {
                    hour: "2-digit",
                    minute: "2-digit"
                }
            );
        }

        if(data.length){

            const indexes = [
                0,
                Math.floor(
                    (data.length - 1) / 2
                ),
                data.length - 1
            ];

            const uniqueIndexes =
                [...new Set(indexes)];

            ctx.fillStyle =
                "rgba(148,163,184,.82)";

            ctx.textBaseline =
                "top";

            uniqueIndexes.forEach(index => {

                const x =
                    left +
                    (
                        data.length === 1
                        ? 0
                        : index /
                          (data.length - 1)
                    ) *
                    plotWidth;

                if(index === 0){
                    ctx.textAlign = "left";
                }else if(
                    index === data.length - 1
                ){
                    ctx.textAlign = "right";
                }else{
                    ctx.textAlign = "center";
                }

                ctx.fillText(
                    formatTime(
                        data[index].timestamp
                    ),
                    x,
                    top + plotHeight + 7
                );
            });
        }

        /*
         * RX / TX lines.
         */
        function drawSeries(
            key,
            dashed
        ){

            ctx.beginPath();

            rates.forEach((point, index) => {

                const x =
                    left +
                    (
                        rates.length === 1
                        ? 0
                        : index /
                          (rates.length - 1)
                    ) *
                    plotWidth;

                const ratio =
                    Math.max(
                        0,
                        Math.min(
                            1,
                            point[key] /
                            maxValue
                        )
                    );

                const y =
                    top +
                    plotHeight *
                    (1 - ratio);

                if(index === 0){
                    ctx.moveTo(x, y);
                }else{
                    ctx.lineTo(x, y);
                }
            });

            ctx.setLineDash(
                dashed
                ? [5, 4]
                : []
            );

            ctx.strokeStyle =
                key === "rx"
                ? "#58a6ff"
                : "#a78bfa";

            ctx.lineWidth = 1.8;

            ctx.stroke();

            ctx.setLineDash([]);
        }

        drawSeries("rx", false);
        drawSeries("tx", true);

        /*
         * Hover marker + vertical guide.
         */
        if(
            activeIndex >= 0 &&
            activeIndex < data.length
        ){

            const x =
                left +
                (
                    data.length === 1
                    ? 0
                    : activeIndex /
                      (data.length - 1)
                ) *
                plotWidth;

            ctx.strokeStyle =
                "rgba(255,255,255,.28)";

            ctx.lineWidth = 1;

            ctx.beginPath();
            ctx.moveTo(
                x,
                top
            );
            ctx.lineTo(
                x,
                top + plotHeight
            );
            ctx.stroke();

            const rxRatio =
                Math.max(
                    0,
                    Math.min(
                        1,
                        rates[activeIndex].rx /
                        maxValue
                    )
                );

            const txRatio =
                Math.max(
                    0,
                    Math.min(
                        1,
                        rates[activeIndex].tx /
                        maxValue
                    )
                );

            const rxY =
                top +
                plotHeight *
                (1 - rxRatio);

            const txY =
                top +
                plotHeight *
                (1 - txRatio);

            ctx.fillStyle =
                "#58a6ff";

            ctx.beginPath();
            ctx.arc(
                x,
                rxY,
                4,
                0,
                Math.PI * 2
            );
            ctx.fill();

            ctx.fillStyle =
                "#a78bfa";

            ctx.beginPath();
            ctx.arc(
                x,
                txY,
                4,
                0,
                Math.PI * 2
            );
            ctx.fill();
        }
    }

    drawGraph();

    /*
     * One persistent tooltip handler.
     * Data is refreshed on every drawTraffic() call.
     */
    canvas._xrayTrafficHoverData = {
        data,
        rates,
        width,
        height,
        drawGraph
    };

    if(!canvas._xrayTrafficHoverBound){

        canvas._xrayTrafficHoverBound = true;

        let tooltip =
            canvas.parentElement
            ? canvas.parentElement
                .querySelector(
                    ".xray-traffic-tooltip"
                )
            : null;

        if(!tooltip){

            tooltip =
                document.createElement(
                    "div"
                );

            tooltip.className =
                "xray-traffic-tooltip";

            tooltip.style.position =
                "absolute";

            tooltip.style.display =
                "none";

            tooltip.style.zIndex =
                "20";

            tooltip.style.pointerEvents =
                "none";

            tooltip.style.padding =
                "8px 10px";

            tooltip.style.borderRadius =
                "7px";

            tooltip.style.border =
                "1px solid rgba(148,163,184,.35)";

            tooltip.style.background =
                "rgba(15,23,42,.96)";

            tooltip.style.color =
                "#e5e7eb";

            tooltip.style.fontSize =
                "12px";

            tooltip.style.lineHeight =
                "1.45";

            tooltip.style.whiteSpace =
                "nowrap";

            tooltip.style.boxShadow =
                "0 8px 24px rgba(0,0,0,.35)";

            if(canvas.parentElement){

                canvas.parentElement.style.position =
                    "relative";

                canvas.parentElement.appendChild(
                    tooltip
                );
            }
        }

        canvas.addEventListener(
            "mousemove",
            event => {

                const state =
                    canvas._xrayTrafficHoverData;

                if(
                    !state ||
                    !state.data ||
                    !state.data.length
                ){
                    return;
                }

                const rect =
                    canvas.getBoundingClientRect();

                const left = 52;
                const right = 8;

                const plotWidth =
                    Math.max(
                        80,
                        rect.width -
                        left -
                        right
                    );

                let px =
                    event.clientX -
                    rect.left;

                px =
                    Math.max(
                        left,
                        Math.min(
                            rect.width - right,
                            px
                        )
                    );

                const ratio =
                    plotWidth > 0
                    ? (
                        px - left
                    ) / plotWidth
                    : 0;

                const index =
                    Math.max(
                        0,
                        Math.min(
                            state.data.length - 1,
                            Math.round(
                                ratio *
                                (
                                    state.data.length -
                                    1
                                )
                            )
                        )
                    );

                /*
                 * Always use the drawGraph() belonging to
                 * the currently loaded history range.
                 *
                 * The mouse handler itself is persistent,
                 * therefore calling the drawGraph() captured
                 * during the first drawTraffic() would redraw
                 * the original range (usually 1h).
                 */
                if(
                    typeof state.drawGraph === "function"
                ){
                    state.drawGraph(index);
                }

                const point =
                    state.data[index];

                const rate =
                    state.rates[index];

                const date =
                    new Date(
                        point.timestamp
                    );

                const dateText =
                    Number.isNaN(
                        date.getTime()
                    )
                    ? ""
                    : date.toLocaleString(
                        "ru-RU",
                        {
                            day: "2-digit",
                            month: "2-digit",
                            hour: "2-digit",
                            minute: "2-digit"
                        }
                    );

                const total =
                    Number(rate.rx || 0) +
                    Number(rate.tx || 0);

                tooltip.innerHTML =
                    "<b>" +
                    dateText +
                    "</b><br>" +
                    "RX: <b>" +
                    Number(
                        rate.rx || 0
                    ).toFixed(2) +
                    " Mbit/s</b><br>" +
                    "TX: <b>" +
                    Number(
                        rate.tx || 0
                    ).toFixed(2) +
                    " Mbit/s</b><br>" +
                    "Всего: <b>" +
                    total.toFixed(2) +
                    " Mbit/s</b>";

                tooltip.style.display =
                    "block";

                const parentRect =
                    canvas.parentElement
                    ? canvas.parentElement
                        .getBoundingClientRect()
                    : rect;

                let tooltipLeft =
                    event.clientX -
                    parentRect.left +
                    12;

                let tooltipTop =
                    event.clientY -
                    parentRect.top -
                    tooltip.offsetHeight -
                    10;

                const maxLeft =
                    parentRect.width -
                    tooltip.offsetWidth -
                    8;

                tooltipLeft =
                    Math.max(
                        8,
                        Math.min(
                            maxLeft,
                            tooltipLeft
                        )
                    );

                if(tooltipTop < 8){

                    tooltipTop =
                        event.clientY -
                        parentRect.top +
                        12;
                }

                tooltip.style.left =
                    tooltipLeft + "px";

                tooltip.style.top =
                    tooltipTop + "px";
            }
        );

        canvas.addEventListener(
            "mouseleave",
            () => {

                if(tooltip){

                    tooltip.style.display =
                        "none";
                }

                const state =
                    canvas._xrayTrafficHoverData;

                if(
                    state &&
                    typeof state.drawGraph === "function"
                ){
                    state.drawGraph();
                }
            }
        );
    }
}


function drawConnections(canvas, rows){
    drawMini(
        canvas,
        rows,
        "connections",
        Math.max(
            1,
            ...rows.map(
                x => Number(
                    x.connections || 0
                )
            )
        ),
        ""
    );
}

function refreshSystem(rows){
    drawMini(
        document.getElementById("xrayCpu"),
        rows,
        "cpu_percent",
        100,
        "%"
    );

    const ramTotal =
        Number(
            window._xrayRamTotal || 1
        );

    drawMini(
        document.getElementById("xrayRam"),
        rows,
        "memory_percent",
        100,
        "%"
    );

    drawMini(
        document.getElementById("xrayDisk"),
        rows,
        "disk_percent",
        100,
        "%"
    );

    drawConnections(
        document.getElementById("xrayConn"),
        rows
    );

    drawTraffic(
        document.getElementById("xrayTraffic"),
        rows
    );
}

function showQR(value){

    const modal =
        document.getElementById(
            "qrModal"
        );

    const box =
        document.getElementById(
            "qrContainer"
        );

    const link =
        document.getElementById(
            "qrLink"
        );

    if (!box || !link || !modal) {
        console.error("QR DOM elements not found");
        return;
    }

    box.innerHTML = "";

    link.textContent = value;

    try{

        const qr =
            qrcode(
                0,
                "M"
            );

        qr.addData(value);
        qr.make();

        const img =
            document.createElement("img");

        img.src =
            qr.createDataURL(8,4);

        img.style.width =
            "260px";

        img.style.height =
            "260px";

        box.appendChild(img);

        modal.style.display =
            "flex";

    }catch(e){

        alert(
            "Ошибка создания QR: " +
            e.message
        );
    }
}

async function copyText(value){

    try{
        await navigator.clipboard.writeText(value);
    }catch(_){
        try{
            const ta =
                document.createElement("textarea");

            ta.value=value;
            ta.style.position="fixed";
            ta.style.opacity="0";

            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            document.execCommand("copy");
            ta.remove();
        }catch(_){}
    }

    showQR(value);
}

function closeQR(){
    const modal = document.getElementById("qrModal");
    if (modal) {
        modal.style.display = "none";
    }
}

function historyDate(value){
    const d = new Date(value);

    if(Number.isNaN(d.getTime())){
        return "";
    }

    return d.toLocaleTimeString(
        "ru-RU",
        {
            hour:"2-digit",
            minute:"2-digit"
        }
    );
}


const userRateState = new Map();

function formatUserRate(bytesPerSecond){

    const value = Number(bytesPerSecond || 0);

    if(!Number.isFinite(value) || value <= 0){
        return "0 B/s";
    }

    const units = [
        "B/s",
        "KB/s",
        "MB/s",
        "GB/s"
    ];

    let n = value;
    let i = 0;

    while(n >= 1024 && i < units.length - 1){
        n /= 1024;
        i++;
    }

    if(i === 0){
        return Math.round(n) + " " + units[i];
    }

    return n.toFixed(2) + " " + units[i];
}

function getUserRates(username, rxBytes, txBytes){

    const now = Date.now();

    const current = {
        rx: Number(rxBytes || 0),
        tx: Number(txBytes || 0),
        time: now
    };

    const previous =
        userRateState.get(username);

    userRateState.set(
        username,
        current
    );

    if(!previous){
        return {
            rx: 0,
            tx: 0
        };
    }

    const dt =
        (now - previous.time) / 1000;

    if(
        !Number.isFinite(dt) ||
        dt <= 0 ||
        dt > 30
    ){
        return {
            rx: 0,
            tx: 0
        };
    }

    return {
        rx:
            current.rx >= previous.rx
            ? (current.rx - previous.rx) / dt
            : 0,

        tx:
            current.tx >= previous.tx
            ? (current.tx - previous.tx) / dt
            : 0
    };
}

function renderUsers(users){

    const body =
        document.getElementById(
            "usersBody"
        );

    if(!body){
        console.error("usersBody not found");
        return;
    }

    if(!users.length){
        body.innerHTML =
            '<tr><td colspan="9" class="muted">' +
            'Пользователей нет</td></tr>';
        return;
    }

    body.innerHTML =
        users.map(u=>{

            const ips =
                Array.isArray(
                    u.active_unique_ips_list
                )
                ? u.active_unique_ips_list.join(", ")
                : "—";

            const rates =
                getUserRates(
                    u.username,
                    u.rx_bytes,
                    u.tx_bytes
                );

            return `
<tr>
<td><b>${esc(u.username)}</b></td>

<td>
<span class="status">
<span class="dot ${u.enabled ? "green":"red"}"></span>
${u.enabled ? "Включён":"Отключён"}
</span>
</td>

<td class="small">
${esc(ips)}
</td>

<td>${u.current_connections || 0}</td>

<td>${formatUserRate(rates.rx)}</td>

<td>${formatUserRate(rates.tx)}</td>

<td>${fmtBytes(u.total_bytes)}</td>

<td>
${
u.link
? `<button onclick="copyText('${esc(u.link)}')">Скопировать</button>`
: "—"
}
</td>

<td>
<div class="actions">

<button onclick="toggleUser(
'${encodeURIComponent(u.username)}',
${u.enabled ? "false":"true"}
)">
${u.enabled ? "Отключить":"Включить"}
</button>

<button
class="danger"
onclick="deleteUser(
'${encodeURIComponent(u.username)}'
)">
Удалить
</button>

</div>
</td>

</tr>
`;

        }).join("");
}


function setTextSafe(id, value){

    const element =
        document.getElementById(id);

    if(element){
        element.textContent =
            value;
    }
}


function setHtmlSafe(id, value){

    const element =
        document.getElementById(id);

    if(element){
        element.innerHTML =
            value;
    }
}


async function refreshDashboard(){

    try{

        const data =
            await api(
                "/api/xray/dashboard"
            );

        lastRows =
            data.users || [];

        setTextSafe(
            "connections",
            data.service?.connections ?? 0
        );

        setTextSafe(
            "userCount",
            data.service?.user_count ?? 0
        );

        setHtmlSafe(
            "serviceStatus",
            `<span class="dot ${
                data.service?.running
                ? "green"
                : "red"
            }"></span>` +
            (
                data.service?.running
                ? "RUNNING / ACTIVE"
                : "STOPPED"
            )
        );

        setTextSafe(
            "lastUpdate",
            new Date().toLocaleTimeString(
                "ru-RU"
            )
        );

        renderUsers(
            data.users || []
        );

    }catch(e){

        console.error(
            "Xray dashboard:",
            e
        );

        setHtmlSafe(
            "serviceStatus",
            '<span class="dot red"></span>ERROR'
        );
    }
}


let historyRequestId = 0;

async function loadHistory(){

    const requestId =
        ++historyRequestId;

    const requestedRange =
        selectedRange;

    try{

        const data =
            await api(
                "/api/xray/history?range=" +
                encodeURIComponent(
                    requestedRange
                )
            );

        /*
         * Ignore an older response if another history
         * request was started after this one.
         *
         * This prevents an out-of-order AJAX response
         * from replacing the currently selected chart range.
         */
        if(
            requestId !== historyRequestId ||
            requestedRange !== selectedRange
        ){
            return;
        }

        selectedRows =
            Array.isArray(data.data)
            ? data.data
            : [];

        refreshSystem(
            selectedRows
        );

        /*
         * Current RX/TX speed from the last two
         * history points.
         */
        let currentRxMbit = 0;
        let currentTxMbit = 0;

        if(selectedRows.length >= 2){

            const last =
                selectedRows[
                    selectedRows.length - 1
                ];

            const prev =
                selectedRows[
                    selectedRows.length - 2
                ];

            const dt =
                Math.max(
                    1,
                    (
                        new Date(
                            last.timestamp
                        ) -
                        new Date(
                            prev.timestamp
                        )
                    ) / 1000
                );

            currentRxMbit =
                Math.max(
                    0,
                    (
                        Number(
                            last.rx_bytes || 0
                        ) -
                        Number(
                            prev.rx_bytes || 0
                        )
                    )
                ) *
                8 /
                dt /
                1000000;

            currentTxMbit =
                Math.max(
                    0,
                    (
                        Number(
                            last.tx_bytes || 0
                        ) -
                        Number(
                            prev.tx_bytes || 0
                        )
                    )
                ) *
                8 /
                dt /
                1000000;
        }

        const rxRate =
            document.getElementById(
                "rxRate"
            );

        const txRate =
            document.getElementById(
                "txRate"
            );

        if(rxRate){

            rxRate.textContent =
                currentRxMbit.toFixed(2) +
                " Mbit/s";
        }

        if(txRate){

            txRate.textContent =
                currentTxMbit.toFixed(2) +
                " Mbit/s";
        }

        const info =
            document.getElementById(
                "historyInfo"
            );

        if(info && selectedRows.length){

            info.textContent =
                `${historyDate(selectedRows[0].timestamp)}` +
                " — " +
                `${historyDate(
                    selectedRows[
                        selectedRows.length-1
                    ].timestamp
                )}`;
        }

    }catch(e){

        console.error(
            "history",
            e
        );
    }
}

document
.querySelectorAll(".history-range-btn")
.forEach(button=>{

    button.addEventListener(
        "click",
        ()=>{

            selectedRange =
                button.dataset.range;

            document
            .querySelectorAll(
                ".history-range-btn"
            )
            .forEach(b=>{
                b.classList.toggle(
                    "active",
                    b.dataset.range ===
                    selectedRange
                );
            });

            loadHistory();
        }
    );
});

async function createXrayUser(){

    const input =
        document.getElementById(
            "newXrayUser"
        );

    const result =
        document.getElementById(
            "createResult"
        );

    if(!input){
        console.error("newXrayUser not found");
        return;
    }

    const username =
        input.value.trim();

    if(!username){
        alert(
            "Введите имя пользователя"
        );
        return;
    }

    try{

        const data =
            await api(
                "/api/xray/users/create",
                {
                    method:"POST",
                    headers:{
                        "Content-Type":
                            "application/json"
                    },
                    body:
                        JSON.stringify({
                            username
                        })
                }
            );

        input.value="";

        if(result){
            result.textContent =
                "Пользователь создан";
        }

        await refreshDashboard();

        if(data.link){
            copyText(data.link);
        }

    }catch(e){

        alert(
            "Ошибка: " +
            e.message
        );
    }
}

async function toggleUser(username, enabled){

    username =
        decodeURIComponent(
            username
        );

    try{

        await api(
            "/api/xray/users/" +
            encodeURIComponent(username) +
            (enabled
                ? "/enable"
                : "/disable"),
            {
                method:"POST"
            }
        );

        await refreshDashboard();

    }catch(e){

        alert(
            "Ошибка: " +
            e.message
        );
    }
}

async function deleteUser(username){

    username =
        decodeURIComponent(
            username
        );

    if(!confirm(
        "Удалить пользователя " +
        username +
        "?"
    )){
        return;
    }

    try{

        await api(
            "/api/xray/users/" +
            encodeURIComponent(username) +
            "/delete",
            {
                method:"POST"
            }
        );

        await refreshDashboard();

    }catch(e){

        alert(
            "Ошибка: " +
            e.message
        );
    }
}

/*
 * Initial page load:
 * dashboard and history are loaded independently.
 */
refreshDashboard();
loadHistory();

setInterval(
    refreshDashboard,
    5000
);

setInterval(
    loadHistory,
    30000
);
</script>

</body>
</html>
'''


def qrcode_js():
    # библиотека qrcode-generator в комплекте панели (web/qrcode.js);
    # системный путь — запасной вариант для старых установок
    for path in (
        Path(os.getenv("PANEL_HOME", "/opt/telemt-443-web")) / "qrcode.js",
        Path("/usr/share/javascript/qrcode-generator/qrcode.js"),
    ):
        if path.exists():
            return path.read_text(encoding="utf-8")

    return ""


