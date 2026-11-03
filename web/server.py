#!/usr/bin/env python3

import base64
import hashlib
import json
import os
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import re
import xray_panel
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from xray_panel import dashboard as xray_dashboard, load_history as xray_load_history, create_user as xray_create_user, set_user_enabled as xray_set_user_enabled, delete_user as xray_delete_user, page_html as xray_page_html, qrcode_js as xray_qrcode_js

APP = Path(os.getenv("PANEL_HOME", "/opt/telemt-443-web"))
DATA = Path(os.getenv("DATA_DIR", "/var/lib/telemt-443-web"))

API = os.getenv("TELEMT_API", "http://127.0.0.1:9091")
CONTAINER = os.getenv("TELEMT_CONTAINER", "telemt-443")

PORT = int(os.getenv("PANEL_PORT", "4443"))

PANEL_USER = os.getenv("PANEL_USER", "admin")
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD", "")


PUBLIC_HOST_CONFIG = Path(os.getenv("TELEMT_CONFIG", "/opt/telemt-443/config/config.toml"))
PUBLIC_HOST_ENV = Path(os.getenv("TELEMT_ENV", "/opt/telemt-443/.env"))
PANEL_ENV = APP / ".env"


def validate_public_host(value):
    import ipaddress

    host = str(value or "").strip()
    if not host or len(host) > 253:
        raise ValueError("Укажите публичный IPv4-адрес или домен")
    if any(c in host for c in "/:@?#\\ \t\r\n"):
        raise ValueError("Введите только IP-адрес или домен, без протокола и пути")

    try:
        ip = ipaddress.ip_address(host)
        if ip.version != 4:
            raise ValueError("Пока поддерживаются IPv4 и доменные имена, но не IPv6")
        return host
    except ValueError as e:
        if "IPv6" in str(e) or "IPv4" in str(e):
            raise

    if len(host) > 253 or host.endswith("."):
        host = host.rstrip(".")
    labels = host.split(".")
    if len(labels) < 2:
        raise ValueError("Укажите полный домен, например vpn.example.com")
    for label in labels:
        if (not label or len(label) > 63
                or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)):
            raise ValueError("Некорректное доменное имя")
    return host


def read_public_host():
    text = PUBLIC_HOST_CONFIG.read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^\[general\.links\]\s*\n(.*?)(?=^\[|\Z)",
        text
    )
    if not match:
        raise RuntimeError("Секция [general.links] не найдена")
    item = re.search(
        r'(?m)^\s*public_host\s*=\s*"([^"]+)"\s*(?:#.*)?$',
        match.group(1)
    )
    if not item:
        raise RuntimeError("public_host не найден в [general.links]")
    return item.group(1)


def replace_public_host_config(text, host):
    pattern = r"(?ms)(^\[general\.links\]\s*\n)(.*?)(?=^\[|\Z)"
    match = re.search(pattern, text)
    if not match:
        raise RuntimeError("Секция [general.links] не найдена")
    section = match.group(2)
    new_section, count = re.subn(
        r'(?m)^(\s*public_host\s*=\s*)"[^"]*"(.*)$',
        lambda m: m.group(1) + '"' + host + '"' + m.group(2),
        section
    )
    if count != 1:
        raise RuntimeError("Не удалось однозначно заменить public_host")
    return text[:match.start(2)] + new_section + text[match.end(2):]


def replace_env_value(text, key, value):
    lines = text.splitlines()
    found = 0
    result = []
    for line in lines:
        if re.match(r"^\s*" + re.escape(key) + r"\s*=", line):
            result.append(key + "=" + value)
            found += 1
        else:
            result.append(line)
    if found > 1:
        raise RuntimeError("Переменная " + key + " встречается несколько раз")
    if not found:
        result.append(key + "=" + value)
    return "\n".join(result) + "\n"


def atomic_write(path, text):
    import tempfile

    mode = path.stat().st_mode & 0o7777 if path.exists() else 0o640
    fd, tmp_name = tempfile.mkstemp(prefix=".public-host-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


HISTORY_FILE = DATA / "history.jsonl"

history_lock = threading.Lock()

_prev_cpu = None
_prev_net = None
_prev_time = None


# ============================================================
# UTILITIES
# ============================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def safe_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def read_json_file(path):
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def run_command(cmd, timeout=15):
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout
    except Exception as e:
        return 1, str(e)


def api_request(method, path, body=None, timeout=10):
    url = API.rstrip("/") + path

    data = None

    headers = {
        "Accept": "application/json",
        "User-Agent": "telemt-443-web/1.0",
    }

    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, {"raw": raw}

    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"raw": raw}
        return e.code, payload

    except Exception as e:
        return 0, {"ok": False, "error": str(e)}


def get_payload(obj):
    if isinstance(obj, dict) and obj.get("ok") is True:
        return obj.get("data")
    return None


# ============================================================
# SYSTEM METRICS
# ============================================================

def cpu_percent():
    global _prev_cpu, _prev_time

    try:
        line = Path("/proc/stat").read_text().splitlines()[0]
        parts = line.split()
        values = list(map(int, parts[1:]))
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values)

        current = (total, idle)
        ts = time.monotonic()

        if _prev_cpu is None:
            _prev_cpu = current
            _prev_time = ts
            return 0.0

        old_total, old_idle = _prev_cpu
        _prev_cpu = current
        _prev_time = ts

        dt = total - old_total
        di = idle - old_idle

        if dt <= 0:
            return 0.0

        value = 100.0 * (1.0 - (di / dt))

        return round(max(0.0, min(100.0, value)), 1)

    except Exception:
        return 0.0


def memory_info():
    try:
        values = {}

        for line in Path("/proc/meminfo").read_text().splitlines():
            key, rest = line.split(":", 1)
            value = int(rest.strip().split()[0])
            values[key] = value

        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", 0)

        if total <= 0:
            return {
                "total_mb": 0,
                "used_mb": 0,
                "percent": 0,
            }

        used = total - available

        return {
            "total_mb": round(total / 1024, 1),
            "used_mb": round(used / 1024, 1),
            "percent": round(used * 100 / total, 1),
        }

    except Exception:
        return {
            "total_mb": 0,
            "used_mb": 0,
            "percent": 0,
        }


def disk_info():
    try:
        u = shutil.disk_usage("/")

        return {
            "total_gb": round(u.total / (1024**3), 2),
            "used_gb": round(u.used / (1024**3), 2),
            "free_gb": round(u.free / (1024**3), 2),
            "percent": round(u.used * 100 / u.total, 1),
        }

    except Exception:
        return {
            "total_gb": 0,
            "used_gb": 0,
            "free_gb": 0,
            "percent": 0,
        }


def network_bytes():
    rx = 0
    tx = 0

    try:
        for line in Path("/proc/net/dev").read_text().splitlines():
            if ":" not in line:
                continue

            iface, values = line.split(":", 1)
            iface = iface.strip()

            if iface == "lo":
                continue

            p = values.split()

            if len(p) >= 9:
                rx += int(p[0])
                tx += int(p[8])

    except Exception:
        pass

    return {
        "rx_bytes": rx,
        "tx_bytes": tx,
    }


def system_metrics():
    mem = memory_info()
    disk = disk_info()
    net = network_bytes()

    return {
        "timestamp": now_iso(),
        "cpu_percent": cpu_percent(),
        "memory": mem,
        "disk": disk,
        "network": net,
    }


# ============================================================
# TELEMT
# ============================================================

def telemt_snapshot():
    result = {
        "health": None,
        "ready": None,
        "system": None,
        "users": [],
        "active_ips": [],
        "stats": None,
        "connections": None,
        "gates": None,
    }

    _, result["health"] = api_request("GET", "/v1/health")
    _, result["ready"] = api_request("GET", "/v1/health/ready")

    _, system = api_request("GET", "/v1/system/info")
    result["system"] = get_payload(system) or system

    _, users = api_request("GET", "/v1/users")
    result["users"] = get_payload(users) or []

    _, active_ips = api_request(
        "GET",
        "/v1/stats/users/active-ips",
    )
    result["active_ips"] = get_payload(active_ips) or []

    _, stats = api_request(
        "GET",
        "/v1/stats/summary",
    )
    result["stats"] = get_payload(stats) or stats

    result["connections"] = None
    result["events"] = None

    _, gates = api_request(
        "GET",
        "/v1/runtime/gates",
    )
    result["gates"] = get_payload(gates) or gates

    return result


def container_status():
    code, out = run_command(
        [
            "docker",
            "inspect",
            CONTAINER,
            "--format",
            "{{json .State}}",
        ],
        timeout=5,
    )

    if code != 0:
        return {
            "exists": False,
            "running": False,
            "status": "missing",
        }

    try:
        state = json.loads(out)
    except Exception:
        return {
            "exists": True,
            "running": False,
            "status": "unknown",
        }

    return {
        "exists": True,
        "running": bool(state.get("Running")),
        "status": state.get("Status", "unknown"),
        "health": (
            state.get("Health") or {}
        ).get("Status"),
        "started_at": state.get("StartedAt"),
        "restart_count": state.get("RestartCount", 0),
    }


def docker_logs(lines=80):
    code, out = run_command(
        [
            "docker",
            "logs",
            "--tail",
            str(lines),
            CONTAINER,
        ],
        timeout=10,
    )

    if code != 0:
        return out

    return out


# ============================================================
# HISTORY
# ============================================================

def total_connections(snapshot):
    total = 0

    for u in snapshot.get("users", []):
        try:
            total += int(u.get("current_connections") or 0)
        except Exception:
            pass

    con = snapshot.get("connections")

    if isinstance(con, dict):
        for key in (
            "current_connections",
            "active_connections",
            "connections",
            "total_connections",
        ):
            try:
                if con.get(key) is not None:
                    total = max(total, int(con[key]))
            except Exception:
                pass

        nested = con.get("data")
        if isinstance(nested, dict):
            for key in (
                "current_connections",
                "active_connections",
                "connections",
                "total_connections",
            ):
                try:
                    if nested.get(key) is not None:
                        total = max(total, int(nested[key]))
                except Exception:
                    pass

    return total


def total_traffic(snapshot):
    total = 0

    for u in snapshot.get("users", []):
        try:
            total += int(u.get("total_octets") or 0)
        except Exception:
            pass

    return total


def write_history():
    system = system_metrics()
    tel = telemt_snapshot()

    row = {
        "timestamp": system["timestamp"],
        "cpu_percent": system["cpu_percent"],
        "memory_percent": system["memory"]["percent"],
        "disk_percent": system["disk"]["percent"],
        "rx_bytes": system["network"]["rx_bytes"],
        "tx_bytes": system["network"]["tx_bytes"],
        "connections": total_connections(tel),
        "traffic_bytes": total_traffic(tel),
        "users": len(tel.get("users", [])),
    }

    DATA.mkdir(parents=True, exist_ok=True)

    with history_lock:
        with HISTORY_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

        try:
            lines = HISTORY_FILE.read_text(
                encoding="utf-8"
            ).splitlines()

            # Retain roughly 31 days at 30-second intervals.
            max_lines = 31 * 24 * 60 * 2

            if len(lines) > max_lines:
                HISTORY_FILE.write_text(
                    "\n".join(lines[-max_lines:]) + "\n",
                    encoding="utf-8",
                )
        except Exception:
            pass


def load_history():
    if not HISTORY_FILE.exists():
        return []

    result = []

    try:
        lines = HISTORY_FILE.read_text(
            encoding="utf-8"
        ).splitlines()

        for line in lines[-3456:]:
            try:
                result.append(json.loads(line))
            except Exception:
                continue

    except Exception:
        pass

    return result


HISTORY_RANGES = {
    "1h": 60 * 60,
    "6h": 6 * 60 * 60,
    "24h": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
    "31d": 31 * 24 * 60 * 60,
}


def _history_epoch(value):
    try:
        from datetime import datetime

        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        ).timestamp()
    except Exception:
        return None


def load_history_range(period):
    if period not in HISTORY_RANGES:
        period = "24h"

    if not HISTORY_FILE.exists():
        return []

    cutoff = time.time() - HISTORY_RANGES[period]

    rows = []

    try:
        with HISTORY_FILE.open(
            "r",
            encoding="utf-8"
        ) as f:

            for line in f:

                try:
                    row = json.loads(line)
                except Exception:
                    continue

                ts = _history_epoch(
                    row.get("timestamp")
                )

                if ts is None:
                    continue

                if ts >= cutoff:
                    rows.append(row)

    except Exception:
        return []

    # Keep browser rendering lightweight while preserving
    # the full requested time range.
    max_points = 1400

    if len(rows) <= max_points:
        return rows

    result = []

    step = (
        (len(rows) - 1) /
        (max_points - 1)
    )

    used = set()

    for i in range(max_points):

        idx = round(i * step)

        if idx < 0:
            idx = 0

        if idx >= len(rows):
            idx = len(rows) - 1

        if idx in used:
            continue

        used.add(idx)
        result.append(rows[idx])

    return result



def sampler():
    while True:
        try:
            write_history()
        except Exception:
            pass

        time.sleep(30)


# ============================================================
# HTML
# ============================================================

HTML = r"""
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Telemt 443 — Monitor</title>

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

</style>


<style>

/* ===== TELEMT 443 LAYOUT FIX ===== */

.top-summary {
    grid-template-columns:
        repeat(3, minmax(0, 1fr));
    align-items: stretch;
}

.top-summary > .card {
    min-height: 130px;
}

/* Traffic is a separate full-width row. */
.traffic-row {
    display: grid;
    grid-template-columns:
        minmax(0, 2fr)
        minmax(280px, 1fr);
    gap: 14px;
    align-items: start;
}

.traffic-row > .card {
    height: auto;
    min-width: 0;
}

/* Network traffic block */
.traffic-row .grid-2 {
    grid-template-columns:
        repeat(2, minmax(0, 1fr));
}

/* Keep charts compact and readable. */
.traffic-row .spark {
    height: 110px;
}

/* Do not allow the traffic row to become one giant stretched card. */
.traffic-row .card-title {
    margin-bottom: 12px;
}

/* Tablet */
@media (max-width: 1100px) {

    .top-summary {
        grid-template-columns:
            repeat(3, minmax(0, 1fr));
    }

    .traffic-row {
        grid-template-columns: 1fr;
    }

}

/* Mobile */
@media (max-width: 700px) {

    .top-summary {
        grid-template-columns: 1fr;
    }

    .traffic-row {
        grid-template-columns: 1fr;
    }

    .traffic-row .grid-2 {
        grid-template-columns: 1fr;
    }

}

</style>


<style>

/* =========================================================
   FINAL TELEMT 443 LAYOUT
   ========================================================= */

.top-summary {
    display: grid;
    grid-template-columns:
        repeat(3, minmax(0, 1fr));
    gap: 14px;
    align-items: stretch;
}

.top-summary > .card {
    min-height: 128px;
}

/* ===== TRAFFIC ===== */

.traffic-main-panel {
    width: 100%;
    min-height: 0;
}

.traffic-main-metrics {
    display: grid;
    grid-template-columns:
        repeat(2, minmax(0, 1fr));
    gap: 30px;
    margin-bottom: 12px;
}

.traffic-label {
    color: var(--muted);
    font-size: 12px;
    margin-bottom: 4px;
}

.traffic-value {
    font-size: 27px;
    font-weight: 700;
    line-height: 1.1;
}

.traffic-main-chart {
    width: 100%;
    height: 190px;
    background: #101319;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
}

#trafficCombinedSpark {
    display: block;
    width: 100%;
    height: 100%;
}

.traffic-legend {
    display: flex;
    justify-content: center;
    gap: 25px;
    margin-top: 8px;
    color: var(--muted);
    font-size: 12px;
}

.legend-dot {
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 50%;
    margin-right: 5px;
}

.legend-dot.rx {
    background: #58a6ff;
}

.legend-dot.tx {
    background: #a78bfa;
}

/* ===== CONNECTIONS ===== */

.connections-history-panel {
    width: 100%;
}

.connections-metrics {
    display: grid;
    grid-template-columns:
        repeat(2, minmax(0, 1fr));
    gap: 30px;
    margin-bottom: 12px;
}

.connections-chart {
    width: 100%;
    height: 150px;
    background: #101319;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
}

#connHistorySpark {
    display: block;
    width: 100%;
    height: 100%;
}

/* ===== RESPONSIVE ===== */

@media (max-width: 1100px) {

    .top-summary {
        grid-template-columns:
            repeat(3, minmax(0, 1fr));
    }

}

@media (max-width: 700px) {

    .top-summary {
        grid-template-columns: 1fr;
    }

    .traffic-main-metrics,
    .connections-metrics {
        grid-template-columns: 1fr;
        gap: 10px;
    }

    .traffic-main-chart {
        height: 160px;
    }

    .connections-chart {
        height: 130px;
    }

}

</style>


<style>


.history-toolbar {
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
    padding: 12px 14px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
}

.history-toolbar-title {
    font-weight: 700;
    white-space: nowrap;
}

.history-range-buttons {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
}

.history-range-btn {
    padding: 7px 11px;
    border-radius: 7px;
    font-size: 12px;
}

.history-range-btn.active {
    background: #26384f;
    border-color: #4f79a8;
    color: #dcecff;
}

.history-info {
    margin-left: auto;
    color: var(--muted);
    font-size: 12px;
}

.interactive-chart-wrap {
    position: relative;
}

.chart-tooltip {
    position: absolute;
    z-index: 20;
    display: none;
    pointer-events: none;
    min-width: 150px;
    max-width: 260px;
    padding: 8px 10px;
    background: rgba(15, 17, 21, 0.96);
    border: 1px solid #384151;
    border-radius: 8px;
    box-shadow: 0 8px 28px rgba(0,0,0,0.35);
    color: var(--text);
    font-size: 12px;
    line-height: 1.45;
    white-space: nowrap;
}

.interactive-chart-canvas {
    display: block;
    width: 100%;
    height: 100%;
}

.traffic-main-chart,
.connections-chart,
.system-chart-wrap {
    position: relative;
}

.traffic-main-chart {
    min-height: 190px;
}

.connections-chart {
    min-height: 150px;
}

.system-chart-wrap {
    min-height: 90px;
}

@media (max-width: 700px) {

    .history-toolbar {
        align-items: flex-start;
    }

    .history-info {
        width: 100%;
        margin-left: 0;
    }

    .history-range-buttons {
        width: 100%;
    }

    .history-range-btn {
        flex: 1 1 auto;
    }

    .chart-tooltip {
        font-size: 11px;
        min-width: 130px;
    }

}

</style>


<style>
/*
 * Users table — iPhone portrait mode.
 *
 * Portrait:
 *   1. Пользователь
 *   2. Статус
 *   3. IP
 *
 * Landscape / desktop:
 *   all columns remain visible.
 */
@media only screen
       and (max-width: 700px)
       and (orientation: portrait) {

    table.users-table {
        width: 100%;
        min-width: 0;
        table-layout: fixed;
    }

    table.users-table th:nth-child(n+4),
    table.users-table td:nth-child(n+4) {
        display: none;
    }

    table.users-table th:nth-child(1),
    table.users-table td:nth-child(1) {
        width: 38%;
    }

    table.users-table th:nth-child(2),
    table.users-table td:nth-child(2) {
        width: 24%;
    }

    table.users-table th:nth-child(3),
    table.users-table td:nth-child(3) {
        width: 38%;
    }

    table.users-table th {
        white-space: normal;
    }

    table.users-table td {
        white-space: normal;
        overflow-wrap: anywhere;
        word-break: break-word;
    }

    table.users-table td:nth-child(1) {
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    table.users-table td:nth-child(2) {
        white-space: nowrap;
    }

}
</style>



<script>
/* Local qrcode-generator 1.4.4 */
//---------------------------------------------------------------------
//
// QR Code Generator for JavaScript
//
// Copyright (c) 2009 Kazuhiko Arase
//
// URL: http://www.d-project.com/
//
// Licensed under the MIT license:
//  http://www.opensource.org/licenses/mit-license.php
//
// The word 'QR Code' is registered trademark of
// DENSO WAVE INCORPORATED
//  http://www.denso-wave.com/qrcode/faqpatent-e.html
//
//---------------------------------------------------------------------

var qrcode = function() {

  //---------------------------------------------------------------------
  // qrcode
  //---------------------------------------------------------------------

  /**
   * qrcode
   * @param typeNumber 1 to 40
   * @param errorCorrectionLevel 'L','M','Q','H'
   */
  var qrcode = function(typeNumber, errorCorrectionLevel) {

    var PAD0 = 0xEC;
    var PAD1 = 0x11;

    var _typeNumber = typeNumber;
    var _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];
    var _modules = null;
    var _moduleCount = 0;
    var _dataCache = null;
    var _dataList = [];

    var _this = {};

    var makeImpl = function(test, maskPattern) {

      _moduleCount = _typeNumber * 4 + 17;
      _modules = function(moduleCount) {
        var modules = new Array(moduleCount);
        for (var row = 0; row < moduleCount; row += 1) {
          modules[row] = new Array(moduleCount);
          for (var col = 0; col < moduleCount; col += 1) {
            modules[row][col] = null;
          }
        }
        return modules;
      }(_moduleCount);

      setupPositionProbePattern(0, 0);
      setupPositionProbePattern(_moduleCount - 7, 0);
      setupPositionProbePattern(0, _moduleCount - 7);
      setupPositionAdjustPattern();
      setupTimingPattern();
      setupTypeInfo(test, maskPattern);

      if (_typeNumber >= 7) {
        setupTypeNumber(test);
      }

      if (_dataCache == null) {
        _dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);
      }

      mapData(_dataCache, maskPattern);
    };

    var setupPositionProbePattern = function(row, col) {

      for (var r = -1; r <= 7; r += 1) {

        if (row + r <= -1 || _moduleCount <= row + r) continue;

        for (var c = -1; c <= 7; c += 1) {

          if (col + c <= -1 || _moduleCount <= col + c) continue;

          if ( (0 <= r && r <= 6 && (c == 0 || c == 6) )
              || (0 <= c && c <= 6 && (r == 0 || r == 6) )
              || (2 <= r && r <= 4 && 2 <= c && c <= 4) ) {
            _modules[row + r][col + c] = true;
          } else {
            _modules[row + r][col + c] = false;
          }
        }
      }
    };

    var getBestMaskPattern = function() {

      var minLostPoint = 0;
      var pattern = 0;

      for (var i = 0; i < 8; i += 1) {

        makeImpl(true, i);

        var lostPoint = QRUtil.getLostPoint(_this);

        if (i == 0 || minLostPoint > lostPoint) {
          minLostPoint = lostPoint;
          pattern = i;
        }
      }

      return pattern;
    };

    var setupTimingPattern = function() {

      for (var r = 8; r < _moduleCount - 8; r += 1) {
        if (_modules[r][6] != null) {
          continue;
        }
        _modules[r][6] = (r % 2 == 0);
      }

      for (var c = 8; c < _moduleCount - 8; c += 1) {
        if (_modules[6][c] != null) {
          continue;
        }
        _modules[6][c] = (c % 2 == 0);
      }
    };

    var setupPositionAdjustPattern = function() {

      var pos = QRUtil.getPatternPosition(_typeNumber);

      for (var i = 0; i < pos.length; i += 1) {

        for (var j = 0; j < pos.length; j += 1) {

          var row = pos[i];
          var col = pos[j];

          if (_modules[row][col] != null) {
            continue;
          }

          for (var r = -2; r <= 2; r += 1) {

            for (var c = -2; c <= 2; c += 1) {

              if (r == -2 || r == 2 || c == -2 || c == 2
                  || (r == 0 && c == 0) ) {
                _modules[row + r][col + c] = true;
              } else {
                _modules[row + r][col + c] = false;
              }
            }
          }
        }
      }
    };

    var setupTypeNumber = function(test) {

      var bits = QRUtil.getBCHTypeNumber(_typeNumber);

      for (var i = 0; i < 18; i += 1) {
        var mod = (!test && ( (bits >> i) & 1) == 1);
        _modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;
      }

      for (var i = 0; i < 18; i += 1) {
        var mod = (!test && ( (bits >> i) & 1) == 1);
        _modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
      }
    };

    var setupTypeInfo = function(test, maskPattern) {

      var data = (_errorCorrectionLevel << 3) | maskPattern;
      var bits = QRUtil.getBCHTypeInfo(data);

      // vertical
      for (var i = 0; i < 15; i += 1) {

        var mod = (!test && ( (bits >> i) & 1) == 1);

        if (i < 6) {
          _modules[i][8] = mod;
        } else if (i < 8) {
          _modules[i + 1][8] = mod;
        } else {
          _modules[_moduleCount - 15 + i][8] = mod;
        }
      }

      // horizontal
      for (var i = 0; i < 15; i += 1) {

        var mod = (!test && ( (bits >> i) & 1) == 1);

        if (i < 8) {
          _modules[8][_moduleCount - i - 1] = mod;
        } else if (i < 9) {
          _modules[8][15 - i - 1 + 1] = mod;
        } else {
          _modules[8][15 - i - 1] = mod;
        }
      }

      // fixed module
      _modules[_moduleCount - 8][8] = (!test);
    };

    var mapData = function(data, maskPattern) {

      var inc = -1;
      var row = _moduleCount - 1;
      var bitIndex = 7;
      var byteIndex = 0;
      var maskFunc = QRUtil.getMaskFunction(maskPattern);

      for (var col = _moduleCount - 1; col > 0; col -= 2) {

        if (col == 6) col -= 1;

        while (true) {

          for (var c = 0; c < 2; c += 1) {

            if (_modules[row][col - c] == null) {

              var dark = false;

              if (byteIndex < data.length) {
                dark = ( ( (data[byteIndex] >>> bitIndex) & 1) == 1);
              }

              var mask = maskFunc(row, col - c);

              if (mask) {
                dark = !dark;
              }

              _modules[row][col - c] = dark;
              bitIndex -= 1;

              if (bitIndex == -1) {
                byteIndex += 1;
                bitIndex = 7;
              }
            }
          }

          row += inc;

          if (row < 0 || _moduleCount <= row) {
            row -= inc;
            inc = -inc;
            break;
          }
        }
      }
    };

    var createBytes = function(buffer, rsBlocks) {

      var offset = 0;

      var maxDcCount = 0;
      var maxEcCount = 0;

      var dcdata = new Array(rsBlocks.length);
      var ecdata = new Array(rsBlocks.length);

      for (var r = 0; r < rsBlocks.length; r += 1) {

        var dcCount = rsBlocks[r].dataCount;
        var ecCount = rsBlocks[r].totalCount - dcCount;

        maxDcCount = Math.max(maxDcCount, dcCount);
        maxEcCount = Math.max(maxEcCount, ecCount);

        dcdata[r] = new Array(dcCount);

        for (var i = 0; i < dcdata[r].length; i += 1) {
          dcdata[r][i] = 0xff & buffer.getBuffer()[i + offset];
        }
        offset += dcCount;

        var rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
        var rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);

        var modPoly = rawPoly.mod(rsPoly);
        ecdata[r] = new Array(rsPoly.getLength() - 1);
        for (var i = 0; i < ecdata[r].length; i += 1) {
          var modIndex = i + modPoly.getLength() - ecdata[r].length;
          ecdata[r][i] = (modIndex >= 0)? modPoly.getAt(modIndex) : 0;
        }
      }

      var totalCodeCount = 0;
      for (var i = 0; i < rsBlocks.length; i += 1) {
        totalCodeCount += rsBlocks[i].totalCount;
      }

      var data = new Array(totalCodeCount);
      var index = 0;

      for (var i = 0; i < maxDcCount; i += 1) {
        for (var r = 0; r < rsBlocks.length; r += 1) {
          if (i < dcdata[r].length) {
            data[index] = dcdata[r][i];
            index += 1;
          }
        }
      }

      for (var i = 0; i < maxEcCount; i += 1) {
        for (var r = 0; r < rsBlocks.length; r += 1) {
          if (i < ecdata[r].length) {
            data[index] = ecdata[r][i];
            index += 1;
          }
        }
      }

      return data;
    };

    var createData = function(typeNumber, errorCorrectionLevel, dataList) {

      var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, errorCorrectionLevel);

      var buffer = qrBitBuffer();

      for (var i = 0; i < dataList.length; i += 1) {
        var data = dataList[i];
        buffer.put(data.getMode(), 4);
        buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );
        data.write(buffer);
      }

      // calc num max data.
      var totalDataCount = 0;
      for (var i = 0; i < rsBlocks.length; i += 1) {
        totalDataCount += rsBlocks[i].dataCount;
      }

      if (buffer.getLengthInBits() > totalDataCount * 8) {
        throw 'code length overflow. ('
          + buffer.getLengthInBits()
          + '>'
          + totalDataCount * 8
          + ')';
      }

      // end code
      if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
        buffer.put(0, 4);
      }

      // padding
      while (buffer.getLengthInBits() % 8 != 0) {
        buffer.putBit(false);
      }

      // padding
      while (true) {

        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD0, 8);

        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD1, 8);
      }

      return createBytes(buffer, rsBlocks);
    };

    _this.addData = function(data, mode) {

      mode = mode || 'Byte';

      var newData = null;

      switch(mode) {
      case 'Numeric' :
        newData = qrNumber(data);
        break;
      case 'Alphanumeric' :
        newData = qrAlphaNum(data);
        break;
      case 'Byte' :
        newData = qr8BitByte(data);
        break;
      case 'Kanji' :
        newData = qrKanji(data);
        break;
      default :
        throw 'mode:' + mode;
      }

      _dataList.push(newData);
      _dataCache = null;
    };

    _this.isDark = function(row, col) {
      if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {
        throw row + ',' + col;
      }
      return _modules[row][col];
    };

    _this.getModuleCount = function() {
      return _moduleCount;
    };

    _this.make = function() {
      if (_typeNumber < 1) {
        var typeNumber = 1;

        for (; typeNumber < 40; typeNumber++) {
          var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, _errorCorrectionLevel);
          var buffer = qrBitBuffer();

          for (var i = 0; i < _dataList.length; i++) {
            var data = _dataList[i];
            buffer.put(data.getMode(), 4);
            buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );
            data.write(buffer);
          }

          var totalDataCount = 0;
          for (var i = 0; i < rsBlocks.length; i++) {
            totalDataCount += rsBlocks[i].dataCount;
          }

          if (buffer.getLengthInBits() <= totalDataCount * 8) {
            break;
          }
        }

        _typeNumber = typeNumber;
      }

      makeImpl(false, getBestMaskPattern() );
    };

    _this.createTableTag = function(cellSize, margin) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var qrHtml = '';

      qrHtml += '<table style="';
      qrHtml += ' border-width: 0px; border-style: none;';
      qrHtml += ' border-collapse: collapse;';
      qrHtml += ' padding: 0px; margin: ' + margin + 'px;';
      qrHtml += '">';
      qrHtml += '<tbody>';

      for (var r = 0; r < _this.getModuleCount(); r += 1) {

        qrHtml += '<tr>';

        for (var c = 0; c < _this.getModuleCount(); c += 1) {
          qrHtml += '<td style="';
          qrHtml += ' border-width: 0px; border-style: none;';
          qrHtml += ' border-collapse: collapse;';
          qrHtml += ' padding: 0px; margin: 0px;';
          qrHtml += ' width: ' + cellSize + 'px;';
          qrHtml += ' height: ' + cellSize + 'px;';
          qrHtml += ' background-color: ';
          qrHtml += _this.isDark(r, c)? '#000000' : '#ffffff';
          qrHtml += ';';
          qrHtml += '"/>';
        }

        qrHtml += '</tr>';
      }

      qrHtml += '</tbody>';
      qrHtml += '</table>';

      return qrHtml;
    };

    _this.createSvgTag = function(cellSize, margin, alt, title) {

      var opts = {};
      if (typeof arguments[0] == 'object') {
        // Called by options.
        opts = arguments[0];
        // overwrite cellSize and margin.
        cellSize = opts.cellSize;
        margin = opts.margin;
        alt = opts.alt;
        title = opts.title;
      }

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      // Compose alt property surrogate
      alt = (typeof alt === 'string') ? {text: alt} : alt || {};
      alt.text = alt.text || null;
      alt.id = (alt.text) ? alt.id || 'qrcode-description' : null;

      // Compose title property surrogate
      title = (typeof title === 'string') ? {text: title} : title || {};
      title.text = title.text || null;
      title.id = (title.text) ? title.id || 'qrcode-title' : null;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var c, mc, r, mr, qrSvg='', rect;

      rect = 'l' + cellSize + ',0 0,' + cellSize +
        ' -' + cellSize + ',0 0,-' + cellSize + 'z ';

      qrSvg += '<svg version="1.1" xmlns="http://www.w3.org/2000/svg"';
      qrSvg += !opts.scalable ? ' width="' + size + 'px" height="' + size + 'px"' : '';
      qrSvg += ' viewBox="0 0 ' + size + ' ' + size + '" ';
      qrSvg += ' preserveAspectRatio="xMinYMin meet"';
      qrSvg += (title.text || alt.text) ? ' role="img" aria-labelledby="' +
          escapeXml([title.id, alt.id].join(' ').trim() ) + '"' : '';
      qrSvg += '>';
      qrSvg += (title.text) ? '<title id="' + escapeXml(title.id) + '">' +
          escapeXml(title.text) + '</title>' : '';
      qrSvg += (alt.text) ? '<description id="' + escapeXml(alt.id) + '">' +
          escapeXml(alt.text) + '</description>' : '';
      qrSvg += '<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>';
      qrSvg += '<path d="';

      for (r = 0; r < _this.getModuleCount(); r += 1) {
        mr = r * cellSize + margin;
        for (c = 0; c < _this.getModuleCount(); c += 1) {
          if (_this.isDark(r, c) ) {
            mc = c*cellSize+margin;
            qrSvg += 'M' + mc + ',' + mr + rect;
          }
        }
      }

      qrSvg += '" stroke="transparent" fill="black"/>';
      qrSvg += '</svg>';

      return qrSvg;
    };

    _this.createDataURL = function(cellSize, margin) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      return createDataURL(size, size, function(x, y) {
        if (min <= x && x < max && min <= y && y < max) {
          var c = Math.floor( (x - min) / cellSize);
          var r = Math.floor( (y - min) / cellSize);
          return _this.isDark(r, c)? 0 : 1;
        } else {
          return 1;
        }
      } );
    };

    _this.createImgTag = function(cellSize, margin, alt) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;

      var img = '';
      img += '<img';
      img += '\u0020src="';
      img += _this.createDataURL(cellSize, margin);
      img += '"';
      img += '\u0020width="';
      img += size;
      img += '"';
      img += '\u0020height="';
      img += size;
      img += '"';
      if (alt) {
        img += '\u0020alt="';
        img += escapeXml(alt);
        img += '"';
      }
      img += '/>';

      return img;
    };

    var escapeXml = function(s) {
      var escaped = '';
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charAt(i);
        switch(c) {
        case '<': escaped += '&lt;'; break;
        case '>': escaped += '&gt;'; break;
        case '&': escaped += '&amp;'; break;
        case '"': escaped += '&quot;'; break;
        default : escaped += c; break;
        }
      }
      return escaped;
    };

    var _createHalfASCII = function(margin) {
      var cellSize = 1;
      margin = (typeof margin == 'undefined')? cellSize * 2 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      var y, x, r1, r2, p;

      var blocks = {
        '██': '█',
        '█ ': '▀',
        ' █': '▄',
        '  ': ' '
      };

      var blocksLastLineNoMargin = {
        '██': '▀',
        '█ ': '▀',
        ' █': ' ',
        '  ': ' '
      };

      var ascii = '';
      for (y = 0; y < size; y += 2) {
        r1 = Math.floor((y - min) / cellSize);
        r2 = Math.floor((y + 1 - min) / cellSize);
        for (x = 0; x < size; x += 1) {
          p = '█';

          if (min <= x && x < max && min <= y && y < max && _this.isDark(r1, Math.floor((x - min) / cellSize))) {
            p = ' ';
          }

          if (min <= x && x < max && min <= y+1 && y+1 < max && _this.isDark(r2, Math.floor((x - min) / cellSize))) {
            p += ' ';
          }
          else {
            p += '█';
          }

          // Output 2 characters per pixel, to create full square. 1 character per pixels gives only half width of square.
          ascii += (margin < 1 && y+1 >= max) ? blocksLastLineNoMargin[p] : blocks[p];
        }

        ascii += '\n';
      }

      if (size % 2 && margin > 0) {
        return ascii.substring(0, ascii.length - size - 1) + Array(size+1).join('▀');
      }

      return ascii.substring(0, ascii.length-1);
    };

    _this.createASCII = function(cellSize, margin) {
      cellSize = cellSize || 1;

      if (cellSize < 2) {
        return _createHalfASCII(margin);
      }

      cellSize -= 1;
      margin = (typeof margin == 'undefined')? cellSize * 2 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      var y, x, r, p;

      var white = Array(cellSize+1).join('██');
      var black = Array(cellSize+1).join('  ');

      var ascii = '';
      var line = '';
      for (y = 0; y < size; y += 1) {
        r = Math.floor( (y - min) / cellSize);
        line = '';
        for (x = 0; x < size; x += 1) {
          p = 1;

          if (min <= x && x < max && min <= y && y < max && _this.isDark(r, Math.floor((x - min) / cellSize))) {
            p = 0;
          }

          // Output 2 characters per pixel, to create full square. 1 character per pixels gives only half width of square.
          line += p ? white : black;
        }

        for (r = 0; r < cellSize; r += 1) {
          ascii += line + '\n';
        }
      }

      return ascii.substring(0, ascii.length-1);
    };

    _this.renderTo2dContext = function(context, cellSize) {
      cellSize = cellSize || 2;
      var length = _this.getModuleCount();
      for (var row = 0; row < length; row++) {
        for (var col = 0; col < length; col++) {
          context.fillStyle = _this.isDark(row, col) ? 'black' : 'white';
          context.fillRect(row * cellSize, col * cellSize, cellSize, cellSize);
        }
      }
    }

    return _this;
  };

  //---------------------------------------------------------------------
  // qrcode.stringToBytes
  //---------------------------------------------------------------------

  qrcode.stringToBytesFuncs = {
    'default' : function(s) {
      var bytes = [];
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charCodeAt(i);
        bytes.push(c & 0xff);
      }
      return bytes;
    }
  };

  qrcode.stringToBytes = qrcode.stringToBytesFuncs['default'];

  //---------------------------------------------------------------------
  // qrcode.createStringToBytes
  //---------------------------------------------------------------------

  /**
   * @param unicodeData base64 string of byte array.
   * [16bit Unicode],[16bit Bytes], ...
   * @param numChars
   */
  qrcode.createStringToBytes = function(unicodeData, numChars) {

    // create conversion map.

    var unicodeMap = function() {

      var bin = base64DecodeInputStream(unicodeData);
      var read = function() {
        var b = bin.read();
        if (b == -1) throw 'eof';
        return b;
      };

      var count = 0;
      var unicodeMap = {};
      while (true) {
        var b0 = bin.read();
        if (b0 == -1) break;
        var b1 = read();
        var b2 = read();
        var b3 = read();
        var k = String.fromCharCode( (b0 << 8) | b1);
        var v = (b2 << 8) | b3;
        unicodeMap[k] = v;
        count += 1;
      }
      if (count != numChars) {
        throw count + ' != ' + numChars;
      }

      return unicodeMap;
    }();

    var unknownChar = '?'.charCodeAt(0);

    return function(s) {
      var bytes = [];
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charCodeAt(i);
        if (c < 128) {
          bytes.push(c);
        } else {
          var b = unicodeMap[s.charAt(i)];
          if (typeof b == 'number') {
            if ( (b & 0xff) == b) {
              // 1byte
              bytes.push(b);
            } else {
              // 2bytes
              bytes.push(b >>> 8);
              bytes.push(b & 0xff);
            }
          } else {
            bytes.push(unknownChar);
          }
        }
      }
      return bytes;
    };
  };

  //---------------------------------------------------------------------
  // QRMode
  //---------------------------------------------------------------------

  var QRMode = {
    MODE_NUMBER :    1 << 0,
    MODE_ALPHA_NUM : 1 << 1,
    MODE_8BIT_BYTE : 1 << 2,
    MODE_KANJI :     1 << 3
  };

  //---------------------------------------------------------------------
  // QRErrorCorrectionLevel
  //---------------------------------------------------------------------

  var QRErrorCorrectionLevel = {
    L : 1,
    M : 0,
    Q : 3,
    H : 2
  };

  //---------------------------------------------------------------------
  // QRMaskPattern
  //---------------------------------------------------------------------

  var QRMaskPattern = {
    PATTERN000 : 0,
    PATTERN001 : 1,
    PATTERN010 : 2,
    PATTERN011 : 3,
    PATTERN100 : 4,
    PATTERN101 : 5,
    PATTERN110 : 6,
    PATTERN111 : 7
  };

  //---------------------------------------------------------------------
  // QRUtil
  //---------------------------------------------------------------------

  var QRUtil = function() {

    var PATTERN_POSITION_TABLE = [
      [],
      [6, 18],
      [6, 22],
      [6, 26],
      [6, 30],
      [6, 34],
      [6, 22, 38],
      [6, 24, 42],
      [6, 26, 46],
      [6, 28, 50],
      [6, 30, 54],
      [6, 32, 58],
      [6, 34, 62],
      [6, 26, 46, 66],
      [6, 26, 48, 70],
      [6, 26, 50, 74],
      [6, 30, 54, 78],
      [6, 30, 56, 82],
      [6, 30, 58, 86],
      [6, 34, 62, 90],
      [6, 28, 50, 72, 94],
      [6, 26, 50, 74, 98],
      [6, 30, 54, 78, 102],
      [6, 28, 54, 80, 106],
      [6, 32, 58, 84, 110],
      [6, 30, 58, 86, 114],
      [6, 34, 62, 90, 118],
      [6, 26, 50, 74, 98, 122],
      [6, 30, 54, 78, 102, 126],
      [6, 26, 52, 78, 104, 130],
      [6, 30, 56, 82, 108, 134],
      [6, 34, 60, 86, 112, 138],
      [6, 30, 58, 86, 114, 142],
      [6, 34, 62, 90, 118, 146],
      [6, 30, 54, 78, 102, 126, 150],
      [6, 24, 50, 76, 102, 128, 154],
      [6, 28, 54, 80, 106, 132, 158],
      [6, 32, 58, 84, 110, 136, 162],
      [6, 26, 54, 82, 110, 138, 166],
      [6, 30, 58, 86, 114, 142, 170]
    ];
    var G15 = (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0);
    var G18 = (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0);
    var G15_MASK = (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1);

    var _this = {};

    var getBCHDigit = function(data) {
      var digit = 0;
      while (data != 0) {
        digit += 1;
        data >>>= 1;
      }
      return digit;
    };

    _this.getBCHTypeInfo = function(data) {
      var d = data << 10;
      while (getBCHDigit(d) - getBCHDigit(G15) >= 0) {
        d ^= (G15 << (getBCHDigit(d) - getBCHDigit(G15) ) );
      }
      return ( (data << 10) | d) ^ G15_MASK;
    };

    _this.getBCHTypeNumber = function(data) {
      var d = data << 12;
      while (getBCHDigit(d) - getBCHDigit(G18) >= 0) {
        d ^= (G18 << (getBCHDigit(d) - getBCHDigit(G18) ) );
      }
      return (data << 12) | d;
    };

    _this.getPatternPosition = function(typeNumber) {
      return PATTERN_POSITION_TABLE[typeNumber - 1];
    };

    _this.getMaskFunction = function(maskPattern) {

      switch (maskPattern) {

      case QRMaskPattern.PATTERN000 :
        return function(i, j) { return (i + j) % 2 == 0; };
      case QRMaskPattern.PATTERN001 :
        return function(i, j) { return i % 2 == 0; };
      case QRMaskPattern.PATTERN010 :
        return function(i, j) { return j % 3 == 0; };
      case QRMaskPattern.PATTERN011 :
        return function(i, j) { return (i + j) % 3 == 0; };
      case QRMaskPattern.PATTERN100 :
        return function(i, j) { return (Math.floor(i / 2) + Math.floor(j / 3) ) % 2 == 0; };
      case QRMaskPattern.PATTERN101 :
        return function(i, j) { return (i * j) % 2 + (i * j) % 3 == 0; };
      case QRMaskPattern.PATTERN110 :
        return function(i, j) { return ( (i * j) % 2 + (i * j) % 3) % 2 == 0; };
      case QRMaskPattern.PATTERN111 :
        return function(i, j) { return ( (i * j) % 3 + (i + j) % 2) % 2 == 0; };

      default :
        throw 'bad maskPattern:' + maskPattern;
      }
    };

    _this.getErrorCorrectPolynomial = function(errorCorrectLength) {
      var a = qrPolynomial([1], 0);
      for (var i = 0; i < errorCorrectLength; i += 1) {
        a = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0) );
      }
      return a;
    };

    _this.getLengthInBits = function(mode, type) {

      if (1 <= type && type < 10) {

        // 1 - 9

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 10;
        case QRMode.MODE_ALPHA_NUM : return 9;
        case QRMode.MODE_8BIT_BYTE : return 8;
        case QRMode.MODE_KANJI     : return 8;
        default :
          throw 'mode:' + mode;
        }

      } else if (type < 27) {

        // 10 - 26

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 12;
        case QRMode.MODE_ALPHA_NUM : return 11;
        case QRMode.MODE_8BIT_BYTE : return 16;
        case QRMode.MODE_KANJI     : return 10;
        default :
          throw 'mode:' + mode;
        }

      } else if (type < 41) {

        // 27 - 40

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 14;
        case QRMode.MODE_ALPHA_NUM : return 13;
        case QRMode.MODE_8BIT_BYTE : return 16;
        case QRMode.MODE_KANJI     : return 12;
        default :
          throw 'mode:' + mode;
        }

      } else {
        throw 'type:' + type;
      }
    };

    _this.getLostPoint = function(qrcode) {

      var moduleCount = qrcode.getModuleCount();

      var lostPoint = 0;

      // LEVEL1

      for (var row = 0; row < moduleCount; row += 1) {
        for (var col = 0; col < moduleCount; col += 1) {

          var sameCount = 0;
          var dark = qrcode.isDark(row, col);

          for (var r = -1; r <= 1; r += 1) {

            if (row + r < 0 || moduleCount <= row + r) {
              continue;
            }

            for (var c = -1; c <= 1; c += 1) {

              if (col + c < 0 || moduleCount <= col + c) {
                continue;
              }

              if (r == 0 && c == 0) {
                continue;
              }

              if (dark == qrcode.isDark(row + r, col + c) ) {
                sameCount += 1;
              }
            }
          }

          if (sameCount > 5) {
            lostPoint += (3 + sameCount - 5);
          }
        }
      };

      // LEVEL2

      for (var row = 0; row < moduleCount - 1; row += 1) {
        for (var col = 0; col < moduleCount - 1; col += 1) {
          var count = 0;
          if (qrcode.isDark(row, col) ) count += 1;
          if (qrcode.isDark(row + 1, col) ) count += 1;
          if (qrcode.isDark(row, col + 1) ) count += 1;
          if (qrcode.isDark(row + 1, col + 1) ) count += 1;
          if (count == 0 || count == 4) {
            lostPoint += 3;
          }
        }
      }

      // LEVEL3

      for (var row = 0; row < moduleCount; row += 1) {
        for (var col = 0; col < moduleCount - 6; col += 1) {
          if (qrcode.isDark(row, col)
              && !qrcode.isDark(row, col + 1)
              &&  qrcode.isDark(row, col + 2)
              &&  qrcode.isDark(row, col + 3)
              &&  qrcode.isDark(row, col + 4)
              && !qrcode.isDark(row, col + 5)
              &&  qrcode.isDark(row, col + 6) ) {
            lostPoint += 40;
          }
        }
      }

      for (var col = 0; col < moduleCount; col += 1) {
        for (var row = 0; row < moduleCount - 6; row += 1) {
          if (qrcode.isDark(row, col)
              && !qrcode.isDark(row + 1, col)
              &&  qrcode.isDark(row + 2, col)
              &&  qrcode.isDark(row + 3, col)
              &&  qrcode.isDark(row + 4, col)
              && !qrcode.isDark(row + 5, col)
              &&  qrcode.isDark(row + 6, col) ) {
            lostPoint += 40;
          }
        }
      }

      // LEVEL4

      var darkCount = 0;

      for (var col = 0; col < moduleCount; col += 1) {
        for (var row = 0; row < moduleCount; row += 1) {
          if (qrcode.isDark(row, col) ) {
            darkCount += 1;
          }
        }
      }

      var ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
      lostPoint += ratio * 10;

      return lostPoint;
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // QRMath
  //---------------------------------------------------------------------

  var QRMath = function() {

    var EXP_TABLE = new Array(256);
    var LOG_TABLE = new Array(256);

    // initialize tables
    for (var i = 0; i < 8; i += 1) {
      EXP_TABLE[i] = 1 << i;
    }
    for (var i = 8; i < 256; i += 1) {
      EXP_TABLE[i] = EXP_TABLE[i - 4]
        ^ EXP_TABLE[i - 5]
        ^ EXP_TABLE[i - 6]
        ^ EXP_TABLE[i - 8];
    }
    for (var i = 0; i < 255; i += 1) {
      LOG_TABLE[EXP_TABLE[i] ] = i;
    }

    var _this = {};

    _this.glog = function(n) {

      if (n < 1) {
        throw 'glog(' + n + ')';
      }

      return LOG_TABLE[n];
    };

    _this.gexp = function(n) {

      while (n < 0) {
        n += 255;
      }

      while (n >= 256) {
        n -= 255;
      }

      return EXP_TABLE[n];
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // qrPolynomial
  //---------------------------------------------------------------------

  function qrPolynomial(num, shift) {

    if (typeof num.length == 'undefined') {
      throw num.length + '/' + shift;
    }

    var _num = function() {
      var offset = 0;
      while (offset < num.length && num[offset] == 0) {
        offset += 1;
      }
      var _num = new Array(num.length - offset + shift);
      for (var i = 0; i < num.length - offset; i += 1) {
        _num[i] = num[i + offset];
      }
      return _num;
    }();

    var _this = {};

    _this.getAt = function(index) {
      return _num[index];
    };

    _this.getLength = function() {
      return _num.length;
    };

    _this.multiply = function(e) {

      var num = new Array(_this.getLength() + e.getLength() - 1);

      for (var i = 0; i < _this.getLength(); i += 1) {
        for (var j = 0; j < e.getLength(); j += 1) {
          num[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i) ) + QRMath.glog(e.getAt(j) ) );
        }
      }

      return qrPolynomial(num, 0);
    };

    _this.mod = function(e) {

      if (_this.getLength() - e.getLength() < 0) {
        return _this;
      }

      var ratio = QRMath.glog(_this.getAt(0) ) - QRMath.glog(e.getAt(0) );

      var num = new Array(_this.getLength() );
      for (var i = 0; i < _this.getLength(); i += 1) {
        num[i] = _this.getAt(i);
      }

      for (var i = 0; i < e.getLength(); i += 1) {
        num[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i) ) + ratio);
      }

      // recursive call
      return qrPolynomial(num, 0).mod(e);
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // QRRSBlock
  //---------------------------------------------------------------------

  var QRRSBlock = function() {

    var RS_BLOCK_TABLE = [

      // L
      // M
      // Q
      // H

      // 1
      [1, 26, 19],
      [1, 26, 16],
      [1, 26, 13],
      [1, 26, 9],

      // 2
      [1, 44, 34],
      [1, 44, 28],
      [1, 44, 22],
      [1, 44, 16],

      // 3
      [1, 70, 55],
      [1, 70, 44],
      [2, 35, 17],
      [2, 35, 13],

      // 4
      [1, 100, 80],
      [2, 50, 32],
      [2, 50, 24],
      [4, 25, 9],

      // 5
      [1, 134, 108],
      [2, 67, 43],
      [2, 33, 15, 2, 34, 16],
      [2, 33, 11, 2, 34, 12],

      // 6
      [2, 86, 68],
      [4, 43, 27],
      [4, 43, 19],
      [4, 43, 15],

      // 7
      [2, 98, 78],
      [4, 49, 31],
      [2, 32, 14, 4, 33, 15],
      [4, 39, 13, 1, 40, 14],

      // 8
      [2, 121, 97],
      [2, 60, 38, 2, 61, 39],
      [4, 40, 18, 2, 41, 19],
      [4, 40, 14, 2, 41, 15],

      // 9
      [2, 146, 116],
      [3, 58, 36, 2, 59, 37],
      [4, 36, 16, 4, 37, 17],
      [4, 36, 12, 4, 37, 13],

      // 10
      [2, 86, 68, 2, 87, 69],
      [4, 69, 43, 1, 70, 44],
      [6, 43, 19, 2, 44, 20],
      [6, 43, 15, 2, 44, 16],

      // 11
      [4, 101, 81],
      [1, 80, 50, 4, 81, 51],
      [4, 50, 22, 4, 51, 23],
      [3, 36, 12, 8, 37, 13],

      // 12
      [2, 116, 92, 2, 117, 93],
      [6, 58, 36, 2, 59, 37],
      [4, 46, 20, 6, 47, 21],
      [7, 42, 14, 4, 43, 15],

      // 13
      [4, 133, 107],
      [8, 59, 37, 1, 60, 38],
      [8, 44, 20, 4, 45, 21],
      [12, 33, 11, 4, 34, 12],

      // 14
      [3, 145, 115, 1, 146, 116],
      [4, 64, 40, 5, 65, 41],
      [11, 36, 16, 5, 37, 17],
      [11, 36, 12, 5, 37, 13],

      // 15
      [5, 109, 87, 1, 110, 88],
      [5, 65, 41, 5, 66, 42],
      [5, 54, 24, 7, 55, 25],
      [11, 36, 12, 7, 37, 13],

      // 16
      [5, 122, 98, 1, 123, 99],
      [7, 73, 45, 3, 74, 46],
      [15, 43, 19, 2, 44, 20],
      [3, 45, 15, 13, 46, 16],

      // 17
      [1, 135, 107, 5, 136, 108],
      [10, 74, 46, 1, 75, 47],
      [1, 50, 22, 15, 51, 23],
      [2, 42, 14, 17, 43, 15],

      // 18
      [5, 150, 120, 1, 151, 121],
      [9, 69, 43, 4, 70, 44],
      [17, 50, 22, 1, 51, 23],
      [2, 42, 14, 19, 43, 15],

      // 19
      [3, 141, 113, 4, 142, 114],
      [3, 70, 44, 11, 71, 45],
      [17, 47, 21, 4, 48, 22],
      [9, 39, 13, 16, 40, 14],

      // 20
      [3, 135, 107, 5, 136, 108],
      [3, 67, 41, 13, 68, 42],
      [15, 54, 24, 5, 55, 25],
      [15, 43, 15, 10, 44, 16],

      // 21
      [4, 144, 116, 4, 145, 117],
      [17, 68, 42],
      [17, 50, 22, 6, 51, 23],
      [19, 46, 16, 6, 47, 17],

      // 22
      [2, 139, 111, 7, 140, 112],
      [17, 74, 46],
      [7, 54, 24, 16, 55, 25],
      [34, 37, 13],

      // 23
      [4, 151, 121, 5, 152, 122],
      [4, 75, 47, 14, 76, 48],
      [11, 54, 24, 14, 55, 25],
      [16, 45, 15, 14, 46, 16],

      // 24
      [6, 147, 117, 4, 148, 118],
      [6, 73, 45, 14, 74, 46],
      [11, 54, 24, 16, 55, 25],
      [30, 46, 16, 2, 47, 17],

      // 25
      [8, 132, 106, 4, 133, 107],
      [8, 75, 47, 13, 76, 48],
      [7, 54, 24, 22, 55, 25],
      [22, 45, 15, 13, 46, 16],

      // 26
      [10, 142, 114, 2, 143, 115],
      [19, 74, 46, 4, 75, 47],
      [28, 50, 22, 6, 51, 23],
      [33, 46, 16, 4, 47, 17],

      // 27
      [8, 152, 122, 4, 153, 123],
      [22, 73, 45, 3, 74, 46],
      [8, 53, 23, 26, 54, 24],
      [12, 45, 15, 28, 46, 16],

      // 28
      [3, 147, 117, 10, 148, 118],
      [3, 73, 45, 23, 74, 46],
      [4, 54, 24, 31, 55, 25],
      [11, 45, 15, 31, 46, 16],

      // 29
      [7, 146, 116, 7, 147, 117],
      [21, 73, 45, 7, 74, 46],
      [1, 53, 23, 37, 54, 24],
      [19, 45, 15, 26, 46, 16],

      // 30
      [5, 145, 115, 10, 146, 116],
      [19, 75, 47, 10, 76, 48],
      [15, 54, 24, 25, 55, 25],
      [23, 45, 15, 25, 46, 16],

      // 31
      [13, 145, 115, 3, 146, 116],
      [2, 74, 46, 29, 75, 47],
      [42, 54, 24, 1, 55, 25],
      [23, 45, 15, 28, 46, 16],

      // 32
      [17, 145, 115],
      [10, 74, 46, 23, 75, 47],
      [10, 54, 24, 35, 55, 25],
      [19, 45, 15, 35, 46, 16],

      // 33
      [17, 145, 115, 1, 146, 116],
      [14, 74, 46, 21, 75, 47],
      [29, 54, 24, 19, 55, 25],
      [11, 45, 15, 46, 46, 16],

      // 34
      [13, 145, 115, 6, 146, 116],
      [14, 74, 46, 23, 75, 47],
      [44, 54, 24, 7, 55, 25],
      [59, 46, 16, 1, 47, 17],

      // 35
      [12, 151, 121, 7, 152, 122],
      [12, 75, 47, 26, 76, 48],
      [39, 54, 24, 14, 55, 25],
      [22, 45, 15, 41, 46, 16],

      // 36
      [6, 151, 121, 14, 152, 122],
      [6, 75, 47, 34, 76, 48],
      [46, 54, 24, 10, 55, 25],
      [2, 45, 15, 64, 46, 16],

      // 37
      [17, 152, 122, 4, 153, 123],
      [29, 74, 46, 14, 75, 47],
      [49, 54, 24, 10, 55, 25],
      [24, 45, 15, 46, 46, 16],

      // 38
      [4, 152, 122, 18, 153, 123],
      [13, 74, 46, 32, 75, 47],
      [48, 54, 24, 14, 55, 25],
      [42, 45, 15, 32, 46, 16],

      // 39
      [20, 147, 117, 4, 148, 118],
      [40, 75, 47, 7, 76, 48],
      [43, 54, 24, 22, 55, 25],
      [10, 45, 15, 67, 46, 16],

      // 40
      [19, 148, 118, 6, 149, 119],
      [18, 75, 47, 31, 76, 48],
      [34, 54, 24, 34, 55, 25],
      [20, 45, 15, 61, 46, 16]
    ];

    var qrRSBlock = function(totalCount, dataCount) {
      var _this = {};
      _this.totalCount = totalCount;
      _this.dataCount = dataCount;
      return _this;
    };

    var _this = {};

    var getRsBlockTable = function(typeNumber, errorCorrectionLevel) {

      switch(errorCorrectionLevel) {
      case QRErrorCorrectionLevel.L :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
      case QRErrorCorrectionLevel.M :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
      case QRErrorCorrectionLevel.Q :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
      case QRErrorCorrectionLevel.H :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
      default :
        return undefined;
      }
    };

    _this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {

      var rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);

      if (typeof rsBlock == 'undefined') {
        throw 'bad rs block @ typeNumber:' + typeNumber +
            '/errorCorrectionLevel:' + errorCorrectionLevel;
      }

      var length = rsBlock.length / 3;

      var list = [];

      for (var i = 0; i < length; i += 1) {

        var count = rsBlock[i * 3 + 0];
        var totalCount = rsBlock[i * 3 + 1];
        var dataCount = rsBlock[i * 3 + 2];

        for (var j = 0; j < count; j += 1) {
          list.push(qrRSBlock(totalCount, dataCount) );
        }
      }

      return list;
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // qrBitBuffer
  //---------------------------------------------------------------------

  var qrBitBuffer = function() {

    var _buffer = [];
    var _length = 0;

    var _this = {};

    _this.getBuffer = function() {
      return _buffer;
    };

    _this.getAt = function(index) {
      var bufIndex = Math.floor(index / 8);
      return ( (_buffer[bufIndex] >>> (7 - index % 8) ) & 1) == 1;
    };

    _this.put = function(num, length) {
      for (var i = 0; i < length; i += 1) {
        _this.putBit( ( (num >>> (length - i - 1) ) & 1) == 1);
      }
    };

    _this.getLengthInBits = function() {
      return _length;
    };

    _this.putBit = function(bit) {

      var bufIndex = Math.floor(_length / 8);
      if (_buffer.length <= bufIndex) {
        _buffer.push(0);
      }

      if (bit) {
        _buffer[bufIndex] |= (0x80 >>> (_length % 8) );
      }

      _length += 1;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrNumber
  //---------------------------------------------------------------------

  var qrNumber = function(data) {

    var _mode = QRMode.MODE_NUMBER;
    var _data = data;

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _data.length;
    };

    _this.write = function(buffer) {

      var data = _data;

      var i = 0;

      while (i + 2 < data.length) {
        buffer.put(strToNum(data.substring(i, i + 3) ), 10);
        i += 3;
      }

      if (i < data.length) {
        if (data.length - i == 1) {
          buffer.put(strToNum(data.substring(i, i + 1) ), 4);
        } else if (data.length - i == 2) {
          buffer.put(strToNum(data.substring(i, i + 2) ), 7);
        }
      }
    };

    var strToNum = function(s) {
      var num = 0;
      for (var i = 0; i < s.length; i += 1) {
        num = num * 10 + chatToNum(s.charAt(i) );
      }
      return num;
    };

    var chatToNum = function(c) {
      if ('0' <= c && c <= '9') {
        return c.charCodeAt(0) - '0'.charCodeAt(0);
      }
      throw 'illegal char :' + c;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrAlphaNum
  //---------------------------------------------------------------------

  var qrAlphaNum = function(data) {

    var _mode = QRMode.MODE_ALPHA_NUM;
    var _data = data;

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _data.length;
    };

    _this.write = function(buffer) {

      var s = _data;

      var i = 0;

      while (i + 1 < s.length) {
        buffer.put(
          getCode(s.charAt(i) ) * 45 +
          getCode(s.charAt(i + 1) ), 11);
        i += 2;
      }

      if (i < s.length) {
        buffer.put(getCode(s.charAt(i) ), 6);
      }
    };

    var getCode = function(c) {

      if ('0' <= c && c <= '9') {
        return c.charCodeAt(0) - '0'.charCodeAt(0);
      } else if ('A' <= c && c <= 'Z') {
        return c.charCodeAt(0) - 'A'.charCodeAt(0) + 10;
      } else {
        switch (c) {
        case ' ' : return 36;
        case '$' : return 37;
        case '%' : return 38;
        case '*' : return 39;
        case '+' : return 40;
        case '-' : return 41;
        case '.' : return 42;
        case '/' : return 43;
        case ':' : return 44;
        default :
          throw 'illegal char :' + c;
        }
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qr8BitByte
  //---------------------------------------------------------------------

  var qr8BitByte = function(data) {

    var _mode = QRMode.MODE_8BIT_BYTE;
    var _data = data;
    var _bytes = qrcode.stringToBytes(data);

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _bytes.length;
    };

    _this.write = function(buffer) {
      for (var i = 0; i < _bytes.length; i += 1) {
        buffer.put(_bytes[i], 8);
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrKanji
  //---------------------------------------------------------------------

  var qrKanji = function(data) {

    var _mode = QRMode.MODE_KANJI;
    var _data = data;

    var stringToBytes = qrcode.stringToBytesFuncs['SJIS'];
    if (!stringToBytes) {
      throw 'sjis not supported.';
    }
    !function(c, code) {
      // self test for sjis support.
      var test = stringToBytes(c);
      if (test.length != 2 || ( (test[0] << 8) | test[1]) != code) {
        throw 'sjis not supported.';
      }
    }('\u53cb', 0x9746);

    var _bytes = stringToBytes(data);

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return ~~(_bytes.length / 2);
    };

    _this.write = function(buffer) {

      var data = _bytes;

      var i = 0;

      while (i + 1 < data.length) {

        var c = ( (0xff & data[i]) << 8) | (0xff & data[i + 1]);

        if (0x8140 <= c && c <= 0x9FFC) {
          c -= 0x8140;
        } else if (0xE040 <= c && c <= 0xEBBF) {
          c -= 0xC140;
        } else {
          throw 'illegal char at ' + (i + 1) + '/' + c;
        }

        c = ( (c >>> 8) & 0xff) * 0xC0 + (c & 0xff);

        buffer.put(c, 13);

        i += 2;
      }

      if (i < data.length) {
        throw 'illegal char at ' + (i + 1);
      }
    };

    return _this;
  };

  //=====================================================================
  // GIF Support etc.
  //

  //---------------------------------------------------------------------
  // byteArrayOutputStream
  //---------------------------------------------------------------------

  var byteArrayOutputStream = function() {

    var _bytes = [];

    var _this = {};

    _this.writeByte = function(b) {
      _bytes.push(b & 0xff);
    };

    _this.writeShort = function(i) {
      _this.writeByte(i);
      _this.writeByte(i >>> 8);
    };

    _this.writeBytes = function(b, off, len) {
      off = off || 0;
      len = len || b.length;
      for (var i = 0; i < len; i += 1) {
        _this.writeByte(b[i + off]);
      }
    };

    _this.writeString = function(s) {
      for (var i = 0; i < s.length; i += 1) {
        _this.writeByte(s.charCodeAt(i) );
      }
    };

    _this.toByteArray = function() {
      return _bytes;
    };

    _this.toString = function() {
      var s = '';
      s += '[';
      for (var i = 0; i < _bytes.length; i += 1) {
        if (i > 0) {
          s += ',';
        }
        s += _bytes[i];
      }
      s += ']';
      return s;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // base64EncodeOutputStream
  //---------------------------------------------------------------------

  var base64EncodeOutputStream = function() {

    var _buffer = 0;
    var _buflen = 0;
    var _length = 0;
    var _base64 = '';

    var _this = {};

    var writeEncoded = function(b) {
      _base64 += String.fromCharCode(encode(b & 0x3f) );
    };

    var encode = function(n) {
      if (n < 0) {
        // error.
      } else if (n < 26) {
        return 0x41 + n;
      } else if (n < 52) {
        return 0x61 + (n - 26);
      } else if (n < 62) {
        return 0x30 + (n - 52);
      } else if (n == 62) {
        return 0x2b;
      } else if (n == 63) {
        return 0x2f;
      }
      throw 'n:' + n;
    };

    _this.writeByte = function(n) {

      _buffer = (_buffer << 8) | (n & 0xff);
      _buflen += 8;
      _length += 1;

      while (_buflen >= 6) {
        writeEncoded(_buffer >>> (_buflen - 6) );
        _buflen -= 6;
      }
    };

    _this.flush = function() {

      if (_buflen > 0) {
        writeEncoded(_buffer << (6 - _buflen) );
        _buffer = 0;
        _buflen = 0;
      }

      if (_length % 3 != 0) {
        // padding
        var padlen = 3 - _length % 3;
        for (var i = 0; i < padlen; i += 1) {
          _base64 += '=';
        }
      }
    };

    _this.toString = function() {
      return _base64;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // base64DecodeInputStream
  //---------------------------------------------------------------------

  var base64DecodeInputStream = function(str) {

    var _str = str;
    var _pos = 0;
    var _buffer = 0;
    var _buflen = 0;

    var _this = {};

    _this.read = function() {

      while (_buflen < 8) {

        if (_pos >= _str.length) {
          if (_buflen == 0) {
            return -1;
          }
          throw 'unexpected end of file./' + _buflen;
        }

        var c = _str.charAt(_pos);
        _pos += 1;

        if (c == '=') {
          _buflen = 0;
          return -1;
        } else if (c.match(/^\s$/) ) {
          // ignore if whitespace.
          continue;
        }

        _buffer = (_buffer << 6) | decode(c.charCodeAt(0) );
        _buflen += 6;
      }

      var n = (_buffer >>> (_buflen - 8) ) & 0xff;
      _buflen -= 8;
      return n;
    };

    var decode = function(c) {
      if (0x41 <= c && c <= 0x5a) {
        return c - 0x41;
      } else if (0x61 <= c && c <= 0x7a) {
        return c - 0x61 + 26;
      } else if (0x30 <= c && c <= 0x39) {
        return c - 0x30 + 52;
      } else if (c == 0x2b) {
        return 62;
      } else if (c == 0x2f) {
        return 63;
      } else {
        throw 'c:' + c;
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // gifImage (B/W)
  //---------------------------------------------------------------------

  var gifImage = function(width, height) {

    var _width = width;
    var _height = height;
    var _data = new Array(width * height);

    var _this = {};

    _this.setPixel = function(x, y, pixel) {
      _data[y * _width + x] = pixel;
    };

    _this.write = function(out) {

      //---------------------------------
      // GIF Signature

      out.writeString('GIF87a');

      //---------------------------------
      // Screen Descriptor

      out.writeShort(_width);
      out.writeShort(_height);

      out.writeByte(0x80); // 2bit
      out.writeByte(0);
      out.writeByte(0);

      //---------------------------------
      // Global Color Map

      // black
      out.writeByte(0x00);
      out.writeByte(0x00);
      out.writeByte(0x00);

      // white
      out.writeByte(0xff);
      out.writeByte(0xff);
      out.writeByte(0xff);

      //---------------------------------
      // Image Descriptor

      out.writeString(',');
      out.writeShort(0);
      out.writeShort(0);
      out.writeShort(_width);
      out.writeShort(_height);
      out.writeByte(0);

      //---------------------------------
      // Local Color Map

      //---------------------------------
      // Raster Data

      var lzwMinCodeSize = 2;
      var raster = getLZWRaster(lzwMinCodeSize);

      out.writeByte(lzwMinCodeSize);

      var offset = 0;

      while (raster.length - offset > 255) {
        out.writeByte(255);
        out.writeBytes(raster, offset, 255);
        offset += 255;
      }

      out.writeByte(raster.length - offset);
      out.writeBytes(raster, offset, raster.length - offset);
      out.writeByte(0x00);

      //---------------------------------
      // GIF Terminator
      out.writeString(';');
    };

    var bitOutputStream = function(out) {

      var _out = out;
      var _bitLength = 0;
      var _bitBuffer = 0;

      var _this = {};

      _this.write = function(data, length) {

        if ( (data >>> length) != 0) {
          throw 'length over';
        }

        while (_bitLength + length >= 8) {
          _out.writeByte(0xff & ( (data << _bitLength) | _bitBuffer) );
          length -= (8 - _bitLength);
          data >>>= (8 - _bitLength);
          _bitBuffer = 0;
          _bitLength = 0;
        }

        _bitBuffer = (data << _bitLength) | _bitBuffer;
        _bitLength = _bitLength + length;
      };

      _this.flush = function() {
        if (_bitLength > 0) {
          _out.writeByte(_bitBuffer);
        }
      };

      return _this;
    };

    var getLZWRaster = function(lzwMinCodeSize) {

      var clearCode = 1 << lzwMinCodeSize;
      var endCode = (1 << lzwMinCodeSize) + 1;
      var bitLength = lzwMinCodeSize + 1;

      // Setup LZWTable
      var table = lzwTable();

      for (var i = 0; i < clearCode; i += 1) {
        table.add(String.fromCharCode(i) );
      }
      table.add(String.fromCharCode(clearCode) );
      table.add(String.fromCharCode(endCode) );

      var byteOut = byteArrayOutputStream();
      var bitOut = bitOutputStream(byteOut);

      // clear code
      bitOut.write(clearCode, bitLength);

      var dataIndex = 0;

      var s = String.fromCharCode(_data[dataIndex]);
      dataIndex += 1;

      while (dataIndex < _data.length) {

        var c = String.fromCharCode(_data[dataIndex]);
        dataIndex += 1;

        if (table.contains(s + c) ) {

          s = s + c;

        } else {

          bitOut.write(table.indexOf(s), bitLength);

          if (table.size() < 0xfff) {

            if (table.size() == (1 << bitLength) ) {
              bitLength += 1;
            }

            table.add(s + c);
          }

          s = c;
        }
      }

      bitOut.write(table.indexOf(s), bitLength);

      // end code
      bitOut.write(endCode, bitLength);

      bitOut.flush();

      return byteOut.toByteArray();
    };

    var lzwTable = function() {

      var _map = {};
      var _size = 0;

      var _this = {};

      _this.add = function(key) {
        if (_this.contains(key) ) {
          throw 'dup key:' + key;
        }
        _map[key] = _size;
        _size += 1;
      };

      _this.size = function() {
        return _size;
      };

      _this.indexOf = function(key) {
        return _map[key];
      };

      _this.contains = function(key) {
        return typeof _map[key] != 'undefined';
      };

      return _this;
    };

    return _this;
  };

  var createDataURL = function(width, height, getPixel) {
    var gif = gifImage(width, height);
    for (var y = 0; y < height; y += 1) {
      for (var x = 0; x < width; x += 1) {
        gif.setPixel(x, y, getPixel(x, y) );
      }
    }

    var b = byteArrayOutputStream();
    gif.write(b);

    var base64 = base64EncodeOutputStream();
    var bytes = b.toByteArray();
    for (var i = 0; i < bytes.length; i += 1) {
      base64.writeByte(bytes[i]);
    }
    base64.flush();

    return 'data:image/gif;base64,' + base64;
  };

  //---------------------------------------------------------------------
  // returns qrcode function.

  return qrcode;
}();

// multibyte support
!function() {

  qrcode.stringToBytesFuncs['UTF-8'] = function(s) {
    // http://stackoverflow.com/questions/18729405/how-to-convert-utf8-string-to-byte-array
    function toUTF8Array(str) {
      var utf8 = [];
      for (var i=0; i < str.length; i++) {
        var charcode = str.charCodeAt(i);
        if (charcode < 0x80) utf8.push(charcode);
        else if (charcode < 0x800) {
          utf8.push(0xc0 | (charcode >> 6),
              0x80 | (charcode & 0x3f));
        }
        else if (charcode < 0xd800 || charcode >= 0xe000) {
          utf8.push(0xe0 | (charcode >> 12),
              0x80 | ((charcode>>6) & 0x3f),
              0x80 | (charcode & 0x3f));
        }
        // surrogate pair
        else {
          i++;
          // UTF-16 encodes 0x10000-0x10FFFF by
          // subtracting 0x10000 and splitting the
          // 20 bits of 0x0-0xFFFFF into two halves
          charcode = 0x10000 + (((charcode & 0x3ff)<<10)
            | (str.charCodeAt(i) & 0x3ff));
          utf8.push(0xf0 | (charcode >>18),
              0x80 | ((charcode>>12) & 0x3f),
              0x80 | ((charcode>>6) & 0x3f),
              0x80 | (charcode & 0x3f));
        }
      }
      return utf8;
    }
    return toUTF8Array(s);
  };

}();

(function (factory) {
  if (typeof define === 'function' && define.amd) {
      define([], factory);
  } else if (typeof exports === 'object') {
      module.exports = factory();
  }
}(function () {
    return qrcode;
}));
</script>

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



</head>

<body>

<header>
<div class="header-row">
    <div>
        <div class="title">Telemt 443</div>
        <div class="subtitle">
            Telegram MTProxy · FakeTLS · google.com · Control 4443
        </div>
    </div>

    <div>
        <span id="lastUpdate" class="badge">—</span>
    </div>
</div>
</header>

<div class="panel-tabs">
    <a href="/" class="active">Telegram</a>
    <a href="/xray">VPN</a>
</div>




<div class="container">


<div class="grid top-summary">

<div class="card">
    <div class="card-title">Сервис</div>
    <div id="serviceStatus" class="status">
        <span class="dot yellow"></span> проверка…
    </div>
    <div class="muted small" id="serviceDetail"></div>
</div>

<div class="card">
    <div class="card-title">Порт</div>
    <div class="metric">443</div>
    <div class="muted">TCP · Telegram</div>
</div>

<div class="card">
    <div class="card-title">Подключения</div>
    <div id="connections" class="metric">0</div>
    <div class="muted">сейчас</div>
</div>

</div>

<div class="card" style="margin-top:16px">
  <div class="card-title">Публичный IP или домен</div>
  <div class="muted small" style="margin-bottom:10px">
    Адрес для новых ссылок Telemt и VLESS. Применение перезапустит Telemt.
  </div>
  <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
    <input id="publicHostInput" type="text" autocomplete="off"
      placeholder="например, vpn.example.com или 203.0.113.10"
      style="flex:1;min-width:240px;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--card);color:var(--text)">
    <button id="publicHostApply" onclick="applyPublicHost()">Применить адрес</button>
  </div>
  <div id="publicHostStatus" class="muted small" style="margin-top:8px" role="status"></div>
</div>

<br>

<div class="grid-2">

<div class="card">
<div class="card-title">Telemt</div>

<table>
<tbody>
<tr><td>Версия</td><td id="version">—</td></tr>
<tr><td>Uptime</td><td id="uptime">—</td></tr>
<tr><td>FakeTLS</td><td id="tlsDomain">google.com</td></tr>
<tr><td>Режим</td><td id="modes">—</td></tr>
<tr><td>Read-only</td><td id="readonly">—</td></tr>
<tr><td>Readiness</td><td id="ready">—</td></tr>
</tbody>
</table>

<br>

<div class="actions">
<button onclick="serviceAction('start')" class="good">Запустить</button>
<button onclick="serviceAction('restart')">Перезапустить</button>
<button onclick="serviceAction('stop')" class="danger">Остановить</button>
</div>

</div>

<div class="card">
<div class="card-title">Система</div>

<div class="small">CPU <span id="cpuText">0%</span></div>
<div class="progress"><div id="cpuBar" style="width:0"></div></div>

<br>

<div class="small">RAM <span id="ramText">0%</span></div>
<div class="progress"><div id="ramBar" style="width:0"></div></div>

<br>

<div class="small">Disk <span id="diskText">0%</span></div>
<div class="progress"><div id="diskBar" style="width:0"></div></div>

<br>

<div class="small">
Network RX <span id="rxText">—</span>
· TX <span id="txText">—</span>
</div>

</div>

</div>

<br>

<div class="card">

<div class="card-title">История системы</div>

<div class="grid-2">

<div>
    <div class="small muted">CPU</div>
    <canvas id="cpuSpark" class="spark"></canvas>
</div>

<div>
    <div class="small muted">RAM</div>
    <canvas id="ramSpark" class="spark"></canvas>
</div>

<div>
    <div class="small muted">Connections</div>
    <canvas id="connSpark" class="spark"></canvas>
</div>

<div>
    <div class="small muted">Disk</div>
    <canvas id="diskSpark" class="spark"></canvas>
</div>

</div>

</div>

<br>


<br>

<!-- SINGLE TRAFFIC PANEL -->

<div class="history-toolbar">

    <div class="history-toolbar-title">
        История
    </div>

    <div class="history-range-buttons">

        <button
            class="history-range-btn"
            data-range="1h">
            1 час
        </button>

        <button
            class="history-range-btn"
            data-range="6h">
            6 часов
        </button>

        <button
            class="history-range-btn active"
            data-range="24h">
            24 часа
        </button>

        <button
            class="history-range-btn"
            data-range="7d">
            7 дней
        </button>

        <button
            class="history-range-btn"
            data-range="31d">
            31 день
        </button>

    </div>

    <div
        id="historyInfo"
        class="history-info">
        Загрузка…
    </div>

</div>

<br>


<div class="card traffic-main-panel">

    <div class="card-title">Сетевой трафик</div>

    <div class="traffic-main-metrics">

        <div>
            <div class="traffic-label">
                RX — входящий трафик
            </div>

            <div class="traffic-value"
                 id="rxRateText">
                0 Mbit/s
            </div>
        </div>

        <div>
            <div class="traffic-label">
                TX — исходящий трафик
            </div>

            <div class="traffic-value"
                 id="txRateText">
                0 Mbit/s
            </div>
        </div>

    </div>

    <div class="traffic-main-chart">
        <canvas id="trafficCombinedSpark"></canvas>
    </div>

    <div class="traffic-legend">

        <span>
            <span class="legend-dot rx"></span>
            RX
        </span>

        <span>
            <span class="legend-dot tx"></span>
            TX
        </span>

    </div>

</div>

<br>

<!-- SINGLE CONNECTION HISTORY PANEL -->

<div class="card connections-history-panel">

    <div class="card-title">Подключения</div>

    <div class="connections-metrics">

        <div>
            <div class="traffic-label">
                Текущие
            </div>

            <div class="traffic-value"
                 id="connNowText">
                0
            </div>
        </div>

        <div>
            <div class="traffic-label">
                Всего за uptime
            </div>

            <div class="traffic-value"
                 id="connTotalText">
                0
            </div>
        </div>

    </div>

    <div class="connections-chart">
        <canvas id="connHistorySpark"></canvas>
    </div>

</div>
<div class="card">

<div class="card-title">Пользователи</div>

<div style="overflow:auto">

<table class="users-table">

<thead>
<tr>
<th>Пользователь</th>
<th>Статус</th>
<th>IP</th>
<th>Макс. IP</th>
<th>Активные соединения</th>
<th>Макс. соединений</th>
<th>Трафик</th>
<th>Квота</th>
<th>Срок действия</th>
<th>Telegram</th>
<th>Управление</th>
</tr>
</thead>

<tbody id="usersBody">
<tr>
<td colspan="11" class="muted">Загрузка…</td>
</tr>
</tbody>

</table>

</div>

</div>

<br>

<div class="card">

<div class="card-title">Добавить пользователя</div>

<div class="form-grid">

<input id="newUser"
       placeholder="username"
       maxlength="64">

<input id="maxConns"
       placeholder="max connections"
       type="number"
       min="1">

<input id="quotaGb"
       placeholder="quota GB"
       type="number"
       min="0">

<input id="expires"
       placeholder="ДД.ММ.ГГГГ — пусто: без срока"
       inputmode="numeric"
       maxlength="10"
       pattern="[0-9]{2}\.[0-9]{2}\.[0-9]{4}"
       autocomplete="off"
       title="Введите дату строго в формате ДД.ММ.ГГГГ"
       oninput="formatExpirationInput(this)">

<button onclick="createUser()" class="good">
Создать
</button>

</div>

<div id="createResult"
     class="small muted"
     style="margin-top:8px"></div>

</div>

<br>

<div class="card">

<div class="card-title">Активные IP</div>

<div style="overflow:auto">

<table>

<thead>
<tr>
<th>Пользователь</th>
<th>IP</th>
<th>Количество</th>
</tr>
</thead>

<tbody id="ipsBody">
<tr>
<td colspan="3" class="muted">Нет активных IP</td>
</tr>
</tbody>

</table>

</div>

</div>

<br>

<div class="card" style="display:none">

<div class="card-title">Подключение к Telegram</div>

<div id="links" class="links">
<div class="muted">Загрузка…</div>
</div>

</div>

<br>

<div class="card">

<div class="card-title">Статистика Telemt</div>

<table>
<tbody>

<tr>
<td>Активные соединения</td>
<td><b id="statActive">0</b></td>
</tr>

<tr>
<td>Всего соединений</td>
<td><b id="statTotal">0</b></td>
</tr>

<tr>
<td>Ошибочные соединения</td>
<td><b id="statBad">0</b></td>
</tr>

<tr>
<td>Handshake failures</td>
<td><b id="statHandshake">0</b></td>
</tr>

<tr>
<td>Активные IP</td>
<td><b id="statIPs">0</b></td>
</tr>

<tr>
<td>Трафик</td>
<td><b id="statTraffic">0 B</b></td>
</tr>

<tr>
<td>Пользователи</td>
<td><b id="statUsers">0</b></td>
</tr>

</tbody>
</table>

</div>

<br>

<div class="card">

<div class="card-title">Последние события Telemt</div>
<pre id="logs">Загрузка…</pre>

</div>

</div>

<footer>
Telemt 443 · web control 4443 · auto refresh 5 sec
</footer>

<script>

let current = null;

function esc(s) {
    return String(s ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
}

function fmtBytes(v) {
    v = Number(v || 0);

    const units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB"
    ];

    let i = 0;

    while (v >= 1024 && i < units.length - 1) {
        v /= 1024;
        i++;
    }

    return v.toFixed(i ? 2 : 0) + " " + units[i];
}

function fmtDuration(sec) {
    sec = Math.floor(Number(sec || 0));

    const d = Math.floor(sec / 86400);
    sec %= 86400;

    const h = Math.floor(sec / 3600);
    sec %= 3600;

    const m = Math.floor(sec / 60);
    sec %= 60;

    return (
        (d ? d + "д " : "") +
        String(h).padStart(2, "0") + ":" +
        String(m).padStart(2, "0") + ":" +
        String(sec).padStart(2, "0")
    );
}

function makeRateSeries(history, key) {

    const result = [];

    if (!Array.isArray(history) || history.length < 2) {
        return result;
    }

    for (let i = 1; i < history.length; i++) {

        const prev = history[i - 1];
        const cur = history[i];

        const t1 =
            new Date(prev.timestamp).getTime();

        const t2 =
            new Date(cur.timestamp).getTime();

        const dt =
            (t2 - t1) / 1000;

        if (!Number.isFinite(dt) || dt <= 0) {
            continue;
        }

        const a =
            Number(prev[key] || 0);

        const b =
            Number(cur[key] || 0);

        const delta =
            Math.max(0, b - a);

        const mbps =
            (delta * 8) / dt / 1000000;

        result.push(mbps);
    }

    return result;
}


function fmtRate(value) {

    value = Number(value || 0);

    if (value < 1) {
        return value.toFixed(3) + " Mbit/s";
    }

    if (value < 10) {
        return value.toFixed(2) + " Mbit/s";
    }

    return value.toFixed(1) + " Mbit/s";
}


function lastValue(values) {

    if (!Array.isArray(values) || !values.length) {
        return 0;
    }

    return Number(
        values[values.length - 1] || 0
    );
}



function drawStackedTraffic(
    canvas,
    rxValues,
    txValues
) {

    if (!canvas) {
        return;
    }

    const dpr =
        window.devicePixelRatio || 1;

    const width =
        Math.max(
            1,
            Math.floor(
                canvas.clientWidth * dpr
            )
        );

    const height =
        Math.max(
            1,
            Math.floor(
                canvas.clientHeight * dpr
            )
        );

    canvas.width = width;
    canvas.height = height;

    const ctx =
        canvas.getContext("2d");

    ctx.clearRect(
        0,
        0,
        width,
        height
    );

    const count = Math.max(
        rxValues.length,
        txValues.length
    );

    if (!count) {
        return;
    }

    const rx = rxValues.slice();
    const tx = txValues.slice();

    while (rx.length < count) {
        rx.unshift(0);
    }

    while (tx.length < count) {
        tx.unshift(0);
    }

    const totals = [];

    for (let i = 0; i < count; i++) {
        totals.push(
            Math.max(
                0,
                Number(rx[i] || 0)
            ) +
            Math.max(
                0,
                Number(tx[i] || 0)
            )
        );
    }

    const maxTotal =
        Math.max(
            0.1,
            ...totals
        );

    const bottom =
        height - 6 * dpr;

    const x = i =>
        count <= 1
        ? 0
        : i / (count - 1) * width;

    const y = value =>
        bottom -
        (
            Math.max(
                0,
                Math.min(
                    1,
                    value / maxTotal
                )
            ) *
            (height - 12 * dpr)
        );

    /* RX layer */

    ctx.beginPath();

    for (let i = 0; i < count; i++) {

        const py =
            y(
                Number(
                    rx[i] || 0
                )
            );

        if (i === 0) {
            ctx.moveTo(x(i), py);
        } else {
            ctx.lineTo(x(i), py);
        }
    }

    for (let i = count - 1; i >= 0; i--) {
        ctx.lineTo(
            x(i),
            bottom
        );
    }

    ctx.closePath();

    ctx.fillStyle =
        "rgba(88,166,255,0.42)";

    ctx.fill();

    /* TX stacked layer */

    ctx.beginPath();

    for (let i = 0; i < count; i++) {

        const py =
            y(totals[i]);

        if (i === 0) {
            ctx.moveTo(x(i), py);
        } else {
            ctx.lineTo(x(i), py);
        }
    }

    for (let i = count - 1; i >= 0; i--) {

        const py =
            y(
                Number(
                    rx[i] || 0
                )
            );

        ctx.lineTo(
            x(i),
            py
        );
    }

    ctx.closePath();

    ctx.fillStyle =
        "rgba(167,139,250,0.42)";

    ctx.fill();

    /* RX boundary */

    ctx.beginPath();

    for (let i = 0; i < count; i++) {

        const py =
            y(
                Number(
                    rx[i] || 0
                )
            );

        if (i === 0) {
            ctx.moveTo(
                x(i),
                py
            );
        } else {
            ctx.lineTo(
                x(i),
                py
            );
        }
    }

    ctx.strokeStyle =
        "#58a6ff";

    ctx.lineWidth =
        1.8 * dpr;

    ctx.stroke();

    /* Total boundary */

    ctx.beginPath();

    for (let i = 0; i < count; i++) {

        const py =
            y(totals[i]);

        if (i === 0) {
            ctx.moveTo(
                x(i),
                py
            );
        } else {
            ctx.lineTo(
                x(i),
                py
            );
        }
    }

    ctx.strokeStyle =
        "#a78bfa";

    ctx.lineWidth =
        1.8 * dpr;

    ctx.stroke();
}


function drawConnectionsSpark(canvas, rows) {
    if (!canvas) return;

    const dpr = window.devicePixelRatio || 1;

    const width = Math.max(
        240,
        canvas.clientWidth || 240
    );

    const height = Math.max(
        70,
        canvas.clientHeight || 70
    );

    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);

    const ctx = canvas.getContext("2d");

    ctx.setTransform(
        dpr,
        0,
        0,
        dpr,
        0,
        0
    );

    ctx.clearRect(
        0,
        0,
        width,
        height
    );

    if (!Array.isArray(rows) || !rows.length) {
        return;
    }

    const values = rows.map(
        row => Number(row.connections || 0)
    );

    const maxValue = Math.max(
        1,
        ...values
    );

    /*
     * Небольшой "круглый" максимум для оси Y:
     * 1..5, 6..10, 11..15 и т.д.
     */
    const yMax = Math.max(
        1,
        Math.ceil(maxValue / 5) * 5
    );

    /*
     * Оставляем место слева под значения Y
     * и снизу под время X.
     */
    const left = 34;
    const right = 6;
    const top = 6;
    const bottom = 20;

    const plotWidth =
        Math.max(
            80,
            width - left - right
        );

    const plotHeight =
        Math.max(
            30,
            height - top - bottom
        );

    /*
     * GRID + Y AXIS
     */
    ctx.font =
        "9px system-ui, -apple-system, BlinkMacSystemFont, sans-serif";

    ctx.lineWidth = 1;

    for (let i = 0; i <= 4; i++) {

        const ratio = i / 4;

        const y =
            top +
            plotHeight * ratio;

        const value =
            Math.round(
                yMax * (1 - ratio)
            );

        ctx.strokeStyle =
            "rgba(148,163,184,.16)";

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
            String(value),
            left - 5,
            y
        );
    }

    /*
     * AXES
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
     * CONNECTIONS LINE
     */
    ctx.beginPath();

    values.forEach((value, i) => {

        const x =
            left +
            (
                values.length === 1
                ? 0
                : i / (values.length - 1)
            ) *
            plotWidth;

        const ratio =
            Math.max(
                0,
                Math.min(
                    1,
                    value / yMax
                )
            );

        const y =
            top +
            plotHeight *
            (1 - ratio);

        if (i === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
    });

    ctx.strokeStyle =
        "#58a6ff";

    ctx.lineWidth = 1.8;

    ctx.stroke();

    /*
     * X AXIS TIME LABELS
     */
    function historyTime(value) {

        const n =
            Number(value);

        let d;

        if (
            Number.isFinite(n)
        ) {
            d = new Date(
                n < 100000000000
                    ? n * 1000
                    : n
            );
        } else {
            d = new Date(value);
        }

        if (
            Number.isNaN(
                d.getTime()
            )
        ) {
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

    const labelIndexes = [];

    if (rows.length > 1) {
        labelIndexes.push(0);

        if (rows.length > 2) {
            labelIndexes.push(
                Math.floor(
                    (rows.length - 1) / 2
                )
            );
        }

        labelIndexes.push(
            rows.length - 1
        );
    } else {
        labelIndexes.push(0);
    }

    ctx.fillStyle =
        "rgba(148,163,184,.82)";

    ctx.textBaseline = "top";

    labelIndexes.forEach(
        (idx, pos) => {

            const x =
                left +
                (
                    rows.length === 1
                    ? 0
                    : idx /
                      (rows.length - 1)
                ) *
                plotWidth;

            const label =
                historyTime(
                    rows[idx].timestamp
                );

            if (pos === 0) {
                ctx.textAlign = "left";
            } else if (
                pos ===
                labelIndexes.length - 1
            ) {
                ctx.textAlign = "right";
            } else {
                ctx.textAlign = "center";
            }

            ctx.fillText(
                label,
                x,
                top + plotHeight + 5
            );
        }
    );
}



/* RAM_DISK_ABSOLUTE_V1 */

window.systemResourceTotals = {
    ram: 0,
    disk: 0
};

function firstNumericValue(obj, keys) {
    if (!obj || typeof obj !== "object") {
        return 0;
    }

    for (const key of keys) {
        const value = Number(obj[key]);

        if (
            Number.isFinite(value) &&
            value > 0
        ) {
            return value;
        }
    }

    return 0;
}

function getMemoryTotalBytes(memory) {
    let total = firstNumericValue(
        memory,
        [
            "total_bytes",
            "total",
            "size_bytes",
            "capacity_bytes"
        ]
    );

    if (!total && memory) {
        const totalMB = Number(memory.total_mb);

        if (
            Number.isFinite(totalMB) &&
            totalMB > 0
        ) {
            total =
                totalMB *
                1024 *
                1024;
        }
    }

    if (!total) {
        const used =
            firstNumericValue(
                memory,
                [
                    "used_bytes",
                    "used"
                ]
            );

        const available =
            firstNumericValue(
                memory,
                [
                    "available_bytes",
                    "available",
                    "free_bytes",
                    "free"
                ]
            );

        if (used > 0 && available > 0) {
            total =
                used +
                available;
        }
    }

    return total;
}

function getDiskTotalBytes(disk) {
    let total = firstNumericValue(
        disk,
        [
            "total_bytes",
            "total",
            "size_bytes",
            "capacity_bytes"
        ]
    );

    if (!total && disk) {
        const totalGB = Number(disk.total_gb);

        if (
            Number.isFinite(totalGB) &&
            totalGB > 0
        ) {
            total =
                totalGB *
                1024 *
                1024 *
                1024;
        }
    }

    if (!total) {
        const used =
            firstNumericValue(
                disk,
                [
                    "used_bytes",
                    "used"
                ]
            );

        const free =
            firstNumericValue(
                disk,
                [
                    "free_bytes",
                    "free"
                ]
            );

        if (used > 0 && free > 0) {
            total =
                used +
                free;
        }
    }

    return total;
}

function formatBytesShort(value) {
    const n = Number(value);

    if (
        !Number.isFinite(n) ||
        n < 0
    ) {
        return "—";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB"
    ];

    let v = n;
    let i = 0;

    while (
        v >= 1024 &&
        i < units.length - 1
    ) {
        v /= 1024;
        i++;
    }

    if (i === 0) {
        return (
            Math.round(v) +
            " " +
            units[i]
        );
    }

    if (v >= 100) {
        return (
            v.toFixed(0) +
            " " +
            units[i]
        );
    }

    if (v >= 10) {
        return (
            v.toFixed(1) +
            " " +
            units[i]
        );
    }

    return (
        v.toFixed(2) +
        " " +
        units[i]
    );
}

function percentToBytes(percent, totalBytes) {
    const p =
        Number(percent);

    const total =
        Number(totalBytes);

    if (
        !Number.isFinite(p) ||
        !Number.isFinite(total) ||
        total <= 0
    ) {
        return 0;
    }

    return (
        Math.max(
            0,
            Math.min(100, p)
        ) /
        100
    ) * total;
}

function drawSystemMiniAxesSpark(
    canvas,
    rows,
    valueKey,
    mode = "percent",
    totalBytes = 0
) {
    if (!canvas) return;

    const dpr =
        window.devicePixelRatio || 1;

    const width = Math.max(
        240,
        canvas.clientWidth || 240
    );

    const height = Math.max(
        70,
        canvas.clientHeight || 70
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

    ctx.clearRect(
        0,
        0,
        width,
        height
    );

    if (
        !Array.isArray(rows) ||
        !rows.length
    ) {
        return;
    }

    const values =
        rows.map(row => {

            const raw =
                Number(
                    row[valueKey] ?? 0
                );

            if (
                mode === "bytes"
            ) {
                return percentToBytes(
                    raw,
                    totalBytes
                );
            }

            return raw;
        });

    let yMax;

    if (
        mode === "bytes"
    ) {
        yMax =
            Math.max(
                1,
                Number(totalBytes) || 1
            );
    } else {
        yMax = 100;
    }

    const left = 48;
    const right = 6;
    const top = 6;
    const bottom = 20;

    const plotWidth =
        Math.max(
            80,
            width - left - right
        );

    const plotHeight =
        Math.max(
            30,
            height - top - bottom
        );

    function formatAxisValue(value) {

        if (
            mode === "bytes"
        ) {
            return formatBytesShort(
                value
            );
        }

        return (
            Math.round(value) +
            "%"
        );
    }

    ctx.font =
        "9px system-ui, -apple-system, BlinkMacSystemFont, sans-serif";

    /*
     * Grid + Y axis.
     */
    for (
        let i = 0;
        i <= 4;
        i++
    ) {

        const ratio =
            i / 4;

        const y =
            top +
            plotHeight * ratio;

        const value =
            yMax *
            (1 - ratio);

        ctx.strokeStyle =
            "rgba(148,163,184,.16)";

        ctx.lineWidth = 1;

        ctx.beginPath();

        ctx.moveTo(
            left,
            y
        );

        ctx.lineTo(
            left + plotWidth,
            y
        );

        ctx.stroke();

        ctx.fillStyle =
            "rgba(148,163,184,.82)";

        ctx.textAlign =
            "right";

        ctx.textBaseline =
            "middle";

        ctx.fillText(
            formatAxisValue(value),
            left - 5,
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
     * Main line.
     */
    ctx.beginPath();

    values.forEach(
        (value, i) => {

            const x =
                left +
                (
                    values.length === 1
                    ? 0
                    : i /
                      (values.length - 1)
                ) *
                plotWidth;

            const ratio =
                Math.max(
                    0,
                    Math.min(
                        1,
                        value /
                        Math.max(
                            1,
                            yMax
                        )
                    )
                );

            const y =
                top +
                plotHeight *
                (1 - ratio);

            if (i === 0) {
                ctx.moveTo(
                    x,
                    y
                );
            } else {
                ctx.lineTo(
                    x,
                    y
                );
            }
        }
    );

    ctx.strokeStyle =
        "#58a6ff";

    ctx.lineWidth = 1.8;

    ctx.stroke();

    /*
     * X axis.
     */
    function formatTime(value) {

        const d =
            new Date(value);

        if (
            Number.isNaN(
                d.getTime()
            )
        ) {
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

    const indexes = [];

    if (rows.length === 1) {

        indexes.push(0);

    } else {

        indexes.push(0);

        if (rows.length > 2) {
            indexes.push(
                Math.floor(
                    (rows.length - 1) / 2
                )
            );
        }

        indexes.push(
            rows.length - 1
        );
    }

    ctx.fillStyle =
        "rgba(148,163,184,.82)";

    ctx.textBaseline =
        "top";

    indexes.forEach(
        (idx, position) => {

            const x =
                left +
                (
                    rows.length === 1
                    ? 0
                    : idx /
                      (rows.length - 1)
                ) *
                plotWidth;

            const label =
                formatTime(
                    rows[idx].timestamp
                );

            if (
                position === 0
            ) {
                ctx.textAlign =
                    "left";
            } else if (
                position ===
                indexes.length - 1
            ) {
                ctx.textAlign =
                    "right";
            } else {
                ctx.textAlign =
                    "center";
            }

            ctx.fillText(
                label,
                x,
                top +
                plotHeight +
                5
            );
        }
    );
}


function drawSpark(canvas, values, maxValue) {

    const ctx = canvas.getContext("2d");

    const w = canvas.width = canvas.clientWidth * devicePixelRatio;
    const h = canvas.height = canvas.clientHeight * devicePixelRatio;

    ctx.clearRect(0, 0, w, h);

    if (!values.length) {
        return;
    }

    ctx.strokeStyle = "#58a6ff";
    ctx.lineWidth = 2 * devicePixelRatio;

    ctx.beginPath();

    values.forEach((v, i) => {

        const x =
            values.length === 1
            ? 0
            : i / (values.length - 1) * w;

        const ratio =
            Math.max(0, Math.min(1,
                Number(v || 0) / maxValue
            ));

        const y = h - ratio * (h - 8 * devicePixelRatio);

        if (i === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }

    });

    ctx.stroke();
}

async function api(path, options = {}) {

    const r = await fetch(path, {
        cache: "no-store",
        ...options
    });

    const text = await r.text();

    let data;

    try {
        data = JSON.parse(text);
    } catch {
        data = {
            ok: false,
            error: text
        };
    }

    if (!r.ok) {
        throw new Error(
            data?.error?.message ||
            data?.error ||
            ("HTTP " + r.status)
        );
    }

    return data;
}

function userTelegramLink(user) {

    const links = user?.links?.tls || [];

    if (!links.length) {
        return "";
    }

    return links[0];
}

function formatUserExpiration(value) {

    if (
        value === null ||
        value === undefined ||
        String(value).trim() === ""
    ) {
        return "Не установлено";
    }

    const date =
        new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return String(value);
    }

    return date.toLocaleDateString(
        "ru-RU",
        {
            day: "2-digit",
            month: "2-digit",
            year: "numeric"
        }
    );

}


function renderUsers(users) {

    const body = document.getElementById("usersBody");

    if (!Array.isArray(users) || !users.length) {

        body.innerHTML =
            '<tr><td colspan="11" class="muted">' +
            'Пользователей нет' +
            '</td></tr>';

        return;
    }

    body.innerHTML = users.map(u => {

        const enabled = u.enabled !== false;

        const ips =
            Array.isArray(u.active_unique_ips_list)
            ? u.active_unique_ips_list.join(", ")
            : "—";

        const link = userTelegramLink(u);

        return `
<tr>
<td><b>${esc(u.username)}</b></td>

<td>
<span class="status">
<span class="dot ${enabled ? "green" : "red"}"></span>
${enabled ? "Включён" : "Отключён"}
</span>
</td>

<td class="small">${esc(ips)}</td>

<td>
${
    u.max_unique_ips !== null &&
    u.max_unique_ips !== undefined
    ? esc(u.max_unique_ips)
    : "Не установлено"
}
</td>

<td>${esc(u.current_connections ?? 0)}</td>

<td>
${
    u.max_tcp_conns !== null &&
    u.max_tcp_conns !== undefined
    ? esc(u.max_tcp_conns)
    : "Не установлено"
}
</td>

<td>${fmtBytes(u.total_octets)}</td>

<td>
${
    u.data_quota_bytes !== null &&
    u.data_quota_bytes !== undefined
    ? esc(fmtBytes(u.data_quota_bytes))
    : "Не установлена"
}
</td>

<td>
${esc(formatUserExpiration(u.expiration_rfc3339))}
</td>

<td>
${
link
? `<button onclick="copyText('${esc(link)}')">Скопировать</button>`
: "—"
}
</td>

<td>

<div class="actions">

<button onclick="toggleUser('${encodeURIComponent(u.username)}',
${enabled ? "false" : "true"})">
${enabled ? "Отключить" : "Включить"}
</button>

<button onclick="openUserSettings('${encodeURIComponent(u.username)}')">
Настройки
</button>

<button onclick="rotateSecret('${encodeURIComponent(u.username)}')">
Новый secret
</button>

<button onclick="resetQuota('${encodeURIComponent(u.username)}')">
Сброс квоты
</button>

<button class="danger"
onclick="deleteUser('${encodeURIComponent(u.username)}')">
Удалить
</button>

</div>

</td>
</tr>
`;

    }).join("");

}


function renderIPs(activeIps) {

    const body = document.getElementById("ipsBody");

    if (!Array.isArray(activeIps) || !activeIps.length) {

        body.innerHTML =
            '<tr><td colspan="3" class="muted">' +
            'Нет активных IP' +
            '</td></tr>';

        return;
    }

    const rows = [];

    for (const item of activeIps) {

        const username =
            item.username ||
            item.user ||
            "—";

        const ips =
            item.active_unique_ips_list ||
            item.ips ||
            item.active_ips ||
            [];

        if (Array.isArray(ips)) {

            ips.forEach(ip => {
                rows.push(`
<tr>
<td>${esc(username)}</td>
<td><code>${esc(ip)}</code></td>
<td>1</td>
</tr>
`);
            });

        } else {

            rows.push(`
<tr>
<td>${esc(username)}</td>
<td>—</td>
<td>—</td>
</tr>
`);

        }

    }

    body.innerHTML = rows.join("");

}


function renderLinks(users) {

    const node = document.getElementById("links");

    const rows = [];

    for (const u of users || []) {

        const link = userTelegramLink(u);

        if (!link) {
            continue;
        }

        rows.push(`
<div class="link-row">

<div>
<b>${esc(u.username)}</b>
</div>

<br>

<code>${esc(link)}</code>

<br><br>

<button onclick="copyText('${esc(link)}')">
Скопировать
</button>

</div>
`);

    }

    node.innerHTML =
        rows.length
        ? rows.join("")
        : '<div class="muted">Ссылок пока нет</div>';

}


async function copyText(value) {

    if (!value) {
        return;
    }

    try {

        await navigator.clipboard.writeText(
            value
        );

    } catch {

        try {
            const ta =
                document.createElement("textarea");

            ta.value = value;
            ta.style.position = "fixed";
            ta.style.opacity = "0";

            document.body.appendChild(ta);

            ta.focus();
            ta.select();

            document.execCommand("copy");

            ta.remove();

        } catch (_) {
            // QR is still shown even if clipboard
            // access is unavailable.
        }

    }

    showTelegramQr(value);

}


function showTelegramQr(value) {

    const modal =
        document.getElementById(
            "telegramQrModal"
        );

    const container =
        document.getElementById(
            "telegramQrContainer"
        );

    const link =
        document.getElementById(
            "telegramQrLink"
        );

    if (
        !modal ||
        !container ||
        !link
    ) {
        return;
    }

    link.textContent = value;

    container.innerHTML = "";

    modal.style.display = "flex";

    if (
        typeof qrcode !== "function"
    ) {

        container.textContent =
            "QR-код недоступен";

        return;
    }

    try {

        const qr =
            qrcode(
                0,
                "M"
            );

        qr.addData(
            value
        );

        qr.make();

        const img =
            document.createElement(
                "img"
            );

        img.alt =
            "QR-код Telegram";

        img.src =
            qr.createDataURL(
                8,
                4
            );

        img.style.width =
            "260px";

        img.style.height =
            "260px";

        img.style.maxWidth =
            "70vw";

        img.style.maxHeight =
            "70vw";

        img.style.display =
            "block";

        container.appendChild(
            img
        );

    } catch (e) {

        console.error(
            "QR generation error:",
            e
        );

        container.textContent =
            "Ошибка создания QR-кода";

    }

}



function closeTelegramQr() {

    const modal =
        document.getElementById(
            "telegramQrModal"
        );

    if (modal) {
        modal.style.display =
            "none";
    }

}



function formatExpirationInput(input) {

    if (!input) {
        return;
    }

    let digits =
        String(input.value || "")
            .replace(/\D/g, "")
            .slice(0, 8);

    let result = "";

    if (digits.length > 0) {
        result += digits.slice(0, 2);
    }

    if (digits.length > 2) {
        result += "." + digits.slice(2, 4);
    }

    if (digits.length > 4) {
        result += "." + digits.slice(4, 8);
    }

    input.value = result;

}


function parseExpirationDate(value) {

    value = value.trim();

    if (!value) {
        return "";
    }

    if (!/^\d{2}\.\d{2}\.\d{4}$/.test(value)) {
        throw new Error(
            "Введите дату строго в формате ДД.ММ.ГГГГ"
        );
    }

    const match =
        value.match(/^(\d{2})\.(\d{2})\.(\d{4})$/);

    if (!match) {
        throw new Error(
            "Введите дату строго в формате ДД.ММ.ГГГГ"
        );
    }

    const day =
        Number(match[1]);

    const month =
        Number(match[2]);

    const year =
        Number(match[3]);

    const date =
        new Date(
            year,
            month - 1,
            day,
            23,
            59,
            59
        );

    if (
        date.getFullYear() !== year ||
        date.getMonth() !== month - 1 ||
        date.getDate() !== day
    ) {
        throw new Error(
            "Некорректная дата"
        );
    }

    const pad =
        n =>
            String(n).padStart(2, "0");

    const offset =
        -date.getTimezoneOffset();

    const sign =
        offset >= 0
        ? "+"
        : "-";

    const abs =
        Math.abs(offset);

    const offsetHours =
        Math.floor(abs / 60);

    const offsetMinutes =
        abs % 60;

    return (
        year +
        "-" +
        pad(month) +
        "-" +
        pad(day) +
        "T23:59:59" +
        sign +
        pad(offsetHours) +
        ":" +
        pad(offsetMinutes)
    );
}


async function createUser() {

    const username =
        document.getElementById("newUser").value.trim();

    const maxConns =
        document.getElementById("maxConns").value.trim();

    const quotaGb =
        document.getElementById("quotaGb").value.trim();

    let expires = "";

    try {

        expires =
            parseExpirationDate(
                document
                    .getElementById("expires")
                    .value
            );

    } catch (e) {

        alert(e.message);
        return;

    }

    const result =
        document.getElementById("createResult");

    if (!username) {
        result.textContent = "Введите username";
        return;
    }

    const body = {
        username
    };

    if (maxConns) {
        body.max_tcp_conns = Number(maxConns);
    }

    if (quotaGb) {
        body.data_quota_bytes =
            Number(quotaGb) * 1024 * 1024 * 1024;
    }

    if (expires) {
        body.expiration_rfc3339 = expires;
    }

    try {

        const r =
            await api(
                "/api/users/create",
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify(body)
                }
            );

        result.textContent =
            "Пользователь создан";

        document.getElementById("newUser").value = "";
        document.getElementById("maxConns").value = "";
        document.getElementById("quotaGb").value = "";
        document.getElementById("expires").value = "";

        await refresh();

    } catch (e) {

        result.textContent =
            "Ошибка: " + e.message;

    }

}


function openUserSettings(username) {

    username =
        decodeURIComponent(username);

    const users =
        current &&
        current.telemt &&
        Array.isArray(current.telemt.users)
        ? current.telemt.users
        : [];

    const user =
        users.find(
            x => x.username === username
        );

    if (!user) {
        alert(
            "Пользователь не найден"
        );
        return;
    }

    document.getElementById(
        "userSettingsTitle"
    ).textContent =
        "Настройки пользователя";

    document.getElementById(
        "userSettingsSubtitle"
    ).textContent =
        username;

    const maxConns =
        document.getElementById(
            "settingsMaxConns"
        );

    const quotaGb =
        document.getElementById(
            "settingsQuotaGb"
        );

    const maxIps =
        document.getElementById(
            "settingsMaxIps"
        );

    const expiration =
        document.getElementById(
            "settingsExpiration"
        );

    maxConns.value =
        user.max_tcp_conns != null
        ? String(user.max_tcp_conns)
        : "";

    quotaGb.value =
        user.data_quota_bytes != null
        ? (
            Number(user.data_quota_bytes) /
            1024 /
            1024 /
            1024
          ).toFixed(2)
        : "";

    maxIps.value =
        user.max_unique_ips != null
        ? String(user.max_unique_ips)
        : "";

    expiration.value = "";

    if (
        user.expiration_rfc3339
    ) {
        const date =
            new Date(
                user.expiration_rfc3339
            );

        if (
            !Number.isNaN(
                date.getTime()
            )
        ) {
            const pad =
                n =>
                    String(n).padStart(
                        2,
                        "0"
                    );

            expiration.value =
                pad(date.getDate()) +
                "." +
                pad(date.getMonth() + 1) +
                "." +
                date.getFullYear();
        }
    }

    document.getElementById(
        "userSettingsModal"
    ).style.display =
        "flex";

    setTimeout(
        () => maxConns.focus(),
        50
    );

}


function closeUserSettings() {

    const modal =
        document.getElementById(
            "userSettingsModal"
        );

    if (modal) {
        modal.style.display =
            "none";
    }

}


async function clearUserLimits() {

    const username =
        document.getElementById(
            "userSettingsSubtitle"
        ).textContent.trim();

    if (!username) {
        return;
    }

    const confirmed =
        confirm(
            "Сбросить все ограничения пользователя " +
            username +
            "?\n\n" +
            "Будут сняты:\n" +
            "• максимальное число соединений\n" +
            "• квота\n" +
            "• срок действия\n" +
            "• максимальное число IP\n\n" +
            "Пользователь останется включённым."
        );

    if (!confirmed) {
        return;
    }

    try {

        await api(
            "/api/users/" +
            encodeURIComponent(username) +
            "/patch",
            {
                method: "POST",
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body:
                    JSON.stringify({
                        max_tcp_conns: null,
                        data_quota_bytes: null,
                        expiration_rfc3339: null,
                        max_unique_ips: null
                    })
            }
        );

        closeUserSettings();

        await refresh();

        alert(
            "Все ограничения пользователя сняты."
        );

    } catch (e) {

        alert(
            "Ошибка сброса ограничений: " +
            e.message
        );

    }

}


async function saveUserSettings() {

    const username =
        document.getElementById(
            "userSettingsSubtitle"
        ).textContent.trim();

    if (!username) {
        closeUserSettings();
        return;
    }

    const maxConns =
        document.getElementById(
            "settingsMaxConns"
        ).value.trim();

    const quotaGb =
        document.getElementById(
            "settingsQuotaGb"
        ).value.trim();

    const maxIps =
        document.getElementById(
            "settingsMaxIps"
        ).value.trim();

    const expiration =
        document.getElementById(
            "settingsExpiration"
        ).value.trim();

    if (
        maxConns !== "" &&
        (
            !/^\d+$/.test(maxConns) ||
            Number(maxConns) < 1
        )
    ) {
        alert(
            "Максимальное число соединений " +
            "должно быть целым числом больше 0."
        );
        return;
    }

    if (
        quotaGb !== "" &&
        (
            !/^\d+(\.\d+)?$/.test(quotaGb) ||
            Number(quotaGb) < 0
        )
    ) {
        alert(
            "Квота должна быть числом " +
            "0 или больше."
        );
        return;
    }

    if (
        maxIps !== "" &&
        (
            !/^\d+$/.test(maxIps) ||
            Number(maxIps) < 1
        )
    ) {
        alert(
            "Максимум уникальных IP " +
            "должен быть целым числом больше 0."
        );
        return;
    }

    const body = {};

    if (maxConns !== "") {
        body.max_tcp_conns =
            Number(maxConns);
    }

    if (quotaGb !== "") {
        body.data_quota_bytes =
            Number(quotaGb) *
            1024 *
            1024 *
            1024;
    }

    if (maxIps !== "") {
        body.max_unique_ips =
            Number(maxIps);
    }

    if (expiration !== "") {

        try {

            body.expiration_rfc3339 =
                parseExpirationDate(
                    expiration
                );

        } catch (e) {

            alert(e.message);
            return;

        }

    }

    if (
        !Object.keys(body).length
    ) {
        alert(
            "Нет изменений для сохранения."
        );
        return;
    }

    try {

        await api(
            "/api/users/" +
            encodeURIComponent(username) +
            "/patch",
            {
                method: "POST",
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body:
                    JSON.stringify(body)
            }
        );

        closeUserSettings();

        await refresh();

        alert(
            "Настройки пользователя обновлены."
        );

    } catch (e) {

        alert(
            "Ошибка: " +
            e.message
        );

    }

}



async function rotateSecret(username) {

    username = decodeURIComponent(username);

    if (!confirm(
        "Сгенерировать новый secret для " +
        username +
        "?\n\n" +
        "Старая Telegram-ссылка перестанет работать."
    )) {
        return;
    }

    try {

        const result =
            await api(
                "/api/users/" +
                encodeURIComponent(username) +
                "/rotate-secret",
                {
                    method: "POST"
                }
            );

        const user =
            result?.data || {};

        const links =
            user?.links?.tls || [];

        const link =
            links.length
            ? links[0]
            : "";

        alert(
            "Secret обновлён.\n\n" +
            (link
                ? "Новая Telegram-ссылка:\n\n" +
                  link
                : "Новая ссылка доступна в таблице.")
        );

        await refresh();

    } catch (e) {

        alert(
            "Ошибка ротации secret: " +
            e.message
        );

    }
}


async function resetQuota(username) {

    username = decodeURIComponent(username);

    if (!confirm(
        "Сбросить счётчик трафика пользователя " +
        username +
        "?"
    )) {
        return;
    }

    try {

        await api(
            "/api/users/" +
            encodeURIComponent(username) +
            "/reset-quota",
            {
                method: "POST"
            }
        );

        alert("Квота сброшена");

        await refresh();

    } catch (e) {

        alert(
            "Ошибка сброса квоты: " +
            e.message
        );

    }
}


async function deleteUser(username) {

    username = decodeURIComponent(username);

    if (!confirm(
        "Удалить пользователя " +
        username +
        "?"
    )) {
        return;
    }

    try {

        await api(
            "/api/users/" +
            encodeURIComponent(username),
            {
                method: "DELETE"
            }
        );

        await refresh();

    } catch (e) {

        alert("Ошибка: " + e.message);

    }

}


async function toggleUser(username, enabled) {

    username = decodeURIComponent(username);

    try {

        await api(
            "/api/users/" +
            encodeURIComponent(username) +
            (enabled ? "/enable" : "/disable"),
            {
                method: "POST"
            }
        );

        await refresh();

    } catch (e) {

        alert("Ошибка: " + e.message);

    }

}


async function loadPublicHost() {
    try {
        const r = await fetch("/api/public-host", {cache: "no-store"});
        const d = await r.json();
        if (r.ok && d.ok) {
            document.getElementById("publicHostInput").value = d.host;
        }
    } catch (_) {}
}

async function applyPublicHost() {
    const input = document.getElementById("publicHostInput");
    const button = document.getElementById("publicHostApply");
    const status = document.getElementById("publicHostStatus");
    const host = input.value.trim();

    if (!host) {
        status.textContent = "Введите IP-адрес или домен.";
        return;
    }

    button.disabled = true;
    status.textContent = "Проверка и применение адреса…";
    try {
        const r = await fetch("/api/public-host", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({host})
        });
        const d = await r.json();
        if (!r.ok || !d.ok) {
            throw new Error(d.error || "Не удалось применить адрес");
        }
        status.textContent = d.message + ": " + d.host;
        if (typeof refresh === "function") {
            await refresh();
        }
    } catch (e) {
        status.textContent = "Ошибка: " + e.message;
    } finally {
        button.disabled = false;
    }
}

loadPublicHost();

async function serviceAction(action) {

    const names = {
        start: "Запустить",
        restart: "Перезапустить",
        stop: "Остановить"
    };

    if (!confirm(
        names[action] +
        " Telemt 443?"
    )) {
        return;
    }

    try {

        const r =
            await api(
                "/api/service/" + action,
                {
                    method: "POST"
                }
            );

        alert(r.message || "Готово");

        setTimeout(refresh, 2500);

    } catch (e) {

        alert("Ошибка: " + e.message);

    }

}


async function refresh() {

    try {

        const data =
            await api("/api/dashboard");

        current = data;

        const service =
            data.service;

        const dot =
            service.running
            ? (
                service.health === "healthy"
                ? "green"
                : "yellow"
            )
            : "red";

        document.getElementById(
            "serviceStatus"
        ).innerHTML =
            `<span class="dot ${dot}"></span>` +
            (service.running
                ? (
                    service.health === "healthy"
                    ? "RUNNING / HEALTHY"
                    : "RUNNING"
                  )
                : "STOPPED");

        document.getElementById(
            "serviceDetail"
        ).textContent =
            service.status +
            (service.restart_count
                ? " · restarts " +
                  service.restart_count
                : "");

        document.getElementById(
            "connections"
        ).textContent =
            service.connections;

        document.getElementById(
            "statUsers"
        ).textContent =
            service.user_count;

        const system =
            data.system;

        window.systemResourceTotals.ram =
            getMemoryTotalBytes(
                system.memory
            );

        window.systemResourceTotals.disk =
            getDiskTotalBytes(
                system.disk
            );

        document.getElementById(
            "cpuText"
        ).textContent =
            system.cpu_percent + "%";

        document.getElementById(
            "cpuBar"
        ).style.width =
            system.cpu_percent + "%";

        const ramUsedBytes =
            window.systemResourceTotals.ram > 0
            ? percentToBytes(
                system.memory.percent,
                window.systemResourceTotals.ram
            )
            : 0;

        document.getElementById(
            "ramText"
        ).textContent =
            window.systemResourceTotals.ram > 0
            ? formatBytesShort(
                ramUsedBytes
            )
            : system.memory.percent + "%";

        document.getElementById(
            "ramBar"
        ).style.width =
            system.memory.percent + "%";

        const diskUsedBytes =
            window.systemResourceTotals.disk > 0
            ? percentToBytes(
                system.disk.percent,
                window.systemResourceTotals.disk
            )
            : 0;

        document.getElementById(
            "diskText"
        ).textContent =
            window.systemResourceTotals.disk > 0
            ? formatBytesShort(
                diskUsedBytes
            )
            : system.disk.percent + "%";

        document.getElementById(
            "diskBar"
        ).style.width =
            system.disk.percent + "%";

        document.getElementById(
            "rxText"
        ).textContent =
            fmtBytes(system.network.rx_bytes);

        document.getElementById(
            "txText"
        ).textContent =
            fmtBytes(system.network.tx_bytes);

        const tel =
            data.telemt;

        document.getElementById(
            "version"
        ).textContent =
            tel.system?.version || "—";

        document.getElementById(
            "uptime"
        ).textContent =
            fmtDuration(
                tel.system?.uptime_seconds || 0
            );

        document.getElementById(
            "tlsDomain"
        ).textContent =
            data.config.tls_domain || "google.com";

        document.getElementById(
            "modes"
        ).textContent =
            data.config.mode || "TLS";

        document.getElementById(
            "readonly"
        ).textContent =
            tel.health?.data?.read_only
            ? "Да"
            : "Нет";

        document.getElementById(
            "ready"
        ).textContent =
            tel.ready?.ok
            ? "READY"
            : "NOT READY";

        renderUsers(tel.users);
        renderIPs(tel.active_ips);
        renderLinks(tel.users);

        document.getElementById(
            "statActive"
        ).textContent =
            service.connections ?? 0;

        document.getElementById(
            "statTotal"
        ).textContent =
            service.connections_total ?? 0;

        document.getElementById(
            "statBad"
        ).textContent =
            service.connections_bad_total ?? 0;

        document.getElementById(
            "statHandshake"
        ).textContent =
            service.handshake_failures_total ?? 0;

        document.getElementById(
            "statIPs"
        ).textContent =
            service.active_ips ?? 0;

        document.getElementById(
            "statTraffic"
        ).textContent =
            fmtBytes(
                service.traffic_bytes ?? 0
            );

        document.getElementById(
            "statUsers"
        ).textContent =
            service.user_count ?? 0;

        document.getElementById(
            "logs"
        ).textContent =
            data.logs || "Нет логов";

        const hist = data.history || [];

        drawSystemMiniAxesSpark(
            document.getElementById("cpuSpark"),
            hist,
            "cpu_percent"
        );

        drawSystemMiniAxesSpark(
            document.getElementById("ramSpark"),
            hist,
            "memory_percent",
            "bytes",
            window.systemResourceTotals.ram
        );

        drawSystemMiniAxesSpark(
            document.getElementById("diskSpark"),
            hist,
            "disk_percent",
            "bytes",
            window.systemResourceTotals.disk
        );

        drawConnectionsSpark(
            document.getElementById("connSpark"),
            hist
        );
        // ----------------------------------------------------
        // NETWORK RX/TX STACKED GRAPH
        // ----------------------------------------------------

        const rxRates =
            makeRateSeries(
                hist,
                "rx_bytes"
            );

        const txRates =
            makeRateSeries(
                hist,
                "tx_bytes"
            );

        drawStackedTraffic(
            document.getElementById(
                "trafficCombinedSpark"
            ),
            rxRates,
            txRates
        );

        document.getElementById(
            "rxRateText"
        ).textContent =
            fmtRate(
                lastValue(rxRates)
            );

        document.getElementById(
            "txRateText"
        ).textContent =
            fmtRate(
                lastValue(txRates)
            );

        // ----------------------------------------------------
        // CONNECTION HISTORY
        // ----------------------------------------------------


        // ----------------------------------------------------
        // CONNECTION HISTORY
        // ----------------------------------------------------

        const connectionHistory =
            hist.map(
                x => Number(x.connections || 0)
            );

        drawSpark(
            document.getElementById("connHistorySpark"),
            connectionHistory,
            Math.max(
                1,
                ...connectionHistory
            )
        );

        document.getElementById(
            "connNowText"
        ).textContent =
            service.connections ?? 0;

        document.getElementById(
            "connTotalText"
        ).textContent =
            service.connections_total ?? 0;

        document.getElementById(
            "lastUpdate"
        ).textContent =
            new Date().toLocaleTimeString();

    } catch (e) {

        document.getElementById(
            "serviceStatus"
        ).innerHTML =
            '<span class="dot red"></span> ERROR';

        document.getElementById(
            "serviceDetail"
        ).textContent =
            e.message;

    }

}



/* ============================================================
   INTERACTIVE HISTORY
   ============================================================ */

let selectedHistoryRange = "24h";
let selectedHistoryRows = [];


function historyDate(value) {

    const d = new Date(value);

    if (Number.isNaN(d.getTime())) {
        return "—";
    }

    if (
        selectedHistoryRange === "1h" ||
        selectedHistoryRange === "6h" ||
        selectedHistoryRange === "24h"
    ) {
        return d.toLocaleString(
            "ru-RU",
            {
                day: "2-digit",
                month: "2-digit",
                hour: "2-digit",
                minute: "2-digit"
            }
        );
    }

    return d.toLocaleString(
        "ru-RU",
        {
            day: "2-digit",
            month: "2-digit",
            hour: "2-digit",
            minute: "2-digit"
        }
    );
}


function historyAxisLabel(value) {

    const d = new Date(value);

    if (Number.isNaN(d.getTime())) {
        return "";
    }

    if (
        selectedHistoryRange === "1h" ||
        selectedHistoryRange === "6h" ||
        selectedHistoryRange === "24h"
    ) {

        return d.toLocaleTimeString(
            "ru-RU",
            {
                hour: "2-digit",
                minute: "2-digit"
            }
        );

    }

    if (
        selectedHistoryRange === "7d"
    ) {

        return d.toLocaleString(
            "ru-RU",
            {
                day: "2-digit",
                month: "2-digit",
                hour: "2-digit"
            }
        );

    }

    return d.toLocaleDateString(
        "ru-RU",
        {
            day: "2-digit",
            month: "2-digit"
        }
    );
}


function historyTooltipDate(value) {

    const d = new Date(value);

    if (Number.isNaN(d.getTime())) {
        return "—";
    }

    return d.toLocaleString(
        "ru-RU",
        {
            day: "2-digit",
            month: "2-digit",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        }
    );
}


function ensureChartTooltip(canvas) {

    const parent =
        canvas.parentElement;

    if (!parent) {
        return null;
    }

    parent.style.position =
        "relative";

    let tooltip =
        parent.querySelector(
            ".chart-tooltip"
        );

    if (!tooltip) {

        tooltip =
            document.createElement("div");

        tooltip.className =
            "chart-tooltip";

        parent.appendChild(
            tooltip
        );
    }

    return tooltip;
}


function canvasSize(canvas) {

    const dpr =
        window.devicePixelRatio || 1;

    const width =
        Math.max(
            1,
            Math.floor(
                canvas.clientWidth * dpr
            )
        );

    const height =
        Math.max(
            1,
            Math.floor(
                canvas.clientHeight * dpr
            )
        );

    canvas.width = width;
    canvas.height = height;

    return {
        width,
        height,
        dpr
    };
}


function makeSeriesRows(rows, fn) {

    return rows.map(
        (row, index) => ({
            timestamp:
                row.timestamp,
            value:
                Number(
                    fn(
                        row,
                        index,
                        rows
                    ) || 0
                )
        })
    );
}


function trafficSeries(rows) {

    const result = [];

    for (
        let i = 0;
        i < rows.length;
        i++
    ) {

        if (i === 0) {

            result.push({
                timestamp:
                    rows[i].timestamp,
                rx: 0,
                tx: 0
            });

            continue;
        }

        const prev =
            rows[i - 1];

        const cur =
            rows[i];

        const t1 =
            new Date(
                prev.timestamp
            ).getTime();

        const t2 =
            new Date(
                cur.timestamp
            ).getTime();

        let dt =
            (t2 - t1) / 1000;

        if (
            !Number.isFinite(dt) ||
            dt <= 0
        ) {
            dt = 30;
        }

        const rxDelta =
            Math.max(
                0,
                Number(
                    cur.rx_bytes || 0
                ) -
                Number(
                    prev.rx_bytes || 0
                )
            );

        const txDelta =
            Math.max(
                0,
                Number(
                    cur.tx_bytes || 0
                ) -
                Number(
                    prev.tx_bytes || 0
                )
            );

        result.push({
            timestamp:
                cur.timestamp,
            rx:
                rxDelta * 8 /
                dt /
                1000000,
            tx:
                txDelta * 8 /
                dt /
                1000000
        });
    }

    return result;
}


function drawInteractiveLine(
    canvas,
    rows,
    valueFn,
    label,
    unit = ""
) {

    if (!canvas || !rows.length) {
        return;
    }

    const {
        width,
        height,
        dpr
    } = canvasSize(canvas);

    const ctx =
        canvas.getContext("2d");

    const tooltip =
        ensureChartTooltip(
            canvas
        );

    const padLeft =
        52 * dpr;

    const padRight =
        12 * dpr;

    const padTop =
        14 * dpr;

    const padBottom =
        30 * dpr;

    const plotWidth =
        width -
        padLeft -
        padRight;

    const plotHeight =
        height -
        padTop -
        padBottom;

    const series =
        makeSeriesRows(
            rows,
            valueFn
        );

    const timestamps =
        series.map(
            x =>
                new Date(
                    x.timestamp
                ).getTime()
        );

    const minValue = 0;

    let maxValue =
        Math.max(
            1,
            ...series.map(
                x => x.value
            )
        );

    if (label === "Connections") {
        maxValue =
            Math.max(
                1,
                maxValue
            );
    }

    function xAt(index) {

        if (series.length <= 1) {
            return padLeft;
        }

        return (
            padLeft +
            index /
            (series.length - 1) *
            plotWidth
        );
    }

    function yAt(value) {

        const ratio =
            (
                value -
                minValue
            ) /
            (
                maxValue -
                minValue
            );

        return (
            padTop +
            plotHeight -
            Math.max(
                0,
                Math.min(
                    1,
                    ratio
                )
            ) *
            plotHeight
        );
    }

    function draw(hoverIndex = null) {

        ctx.clearRect(
            0,
            0,
            width,
            height
        );

        ctx.font =
            `${11 * dpr}px sans-serif`;

        ctx.lineWidth =
            1 * dpr;

        /* grid */

        ctx.strokeStyle =
            "rgba(255,255,255,0.08)";

        ctx.fillStyle =
            "#7f8998";

        for (
            let i = 0;
            i <= 4;
            i++
        ) {

            const value =
                maxValue *
                i /
                4;

            const y =
                yAt(value);

            ctx.beginPath();

            ctx.moveTo(
                padLeft,
                y
            );

            ctx.lineTo(
                width - padRight,
                y
            );

            ctx.stroke();

            ctx.textAlign =
                "right";

            ctx.fillText(
                (
                    value >= 1000
                    ? (
                        value /
                        1000
                    ).toFixed(1) +
                    "k"
                    : value.toFixed(
                        value < 10
                        ? 1
                        : 0
                    )
                ),
                padLeft - 7 * dpr,
                y + 4 * dpr
            );
        }

        /* x-axis labels */

        const labels = 5;

        ctx.textAlign =
            "center";

        for (
            let i = 0;
            i < labels;
            i++
        ) {

            const idx =
                Math.round(
                    i *
                    (
                        series.length - 1
                    ) /
                    (
                        labels - 1
                    )
                );

            const x =
                xAt(idx);

            ctx.fillText(
                historyAxisLabel(
                    series[idx].timestamp
                ),
                x,
                height -
                8 * dpr
            );
        }

        /* line */

        ctx.strokeStyle =
            "#58a6ff";

        ctx.lineWidth =
            2 * dpr;

        ctx.beginPath();

        series.forEach(
            (point, index) => {

                const x =
                    xAt(index);

                const y =
                    yAt(
                        point.value
                    );

                if (
                    index === 0
                ) {
                    ctx.moveTo(
                        x,
                        y
                    );
                } else {
                    ctx.lineTo(
                        x,
                        y
                    );
                }
            }
        );

        ctx.stroke();

        /* hover */

        if (
            hoverIndex !== null &&
            series[hoverIndex]
        ) {

            const x =
                xAt(hoverIndex);

            const point =
                series[hoverIndex];

            const y =
                yAt(
                    point.value
                );

            ctx.strokeStyle =
                "rgba(255,255,255,0.28)";

            ctx.lineWidth =
                dpr;

            ctx.beginPath();

            ctx.moveTo(
                x,
                padTop
            );

            ctx.lineTo(
                x,
                height -
                padBottom
            );

            ctx.stroke();

            ctx.fillStyle =
                "#58a6ff";

            ctx.beginPath();

            ctx.arc(
                x,
                y,
                4 * dpr,
                0,
                Math.PI * 2
            );

            ctx.fill();

            return {
                x: x / dpr,
                y: y / dpr,
                point
            };
        }

        return null;
    }

    draw();

    if (
        !canvas._interactiveHistoryBound
    ) {

        canvas._interactiveHistoryBound =
            true;

        canvas.addEventListener(
            "mousemove",
            event => {

                const rect =
                    canvas.getBoundingClientRect();

                const px =
                    (
                        event.clientX -
                        rect.left
                    ) /
                    rect.width;

                const index =
                    Math.max(
                        0,
                        Math.min(
                            series.length - 1,
                            Math.round(
                                px *
                                (
                                    series.length -
                                    1
                                )
                            )
                        )
                    );

                const info =
                    draw(index);

                if (
                    !info ||
                    !tooltip
                ) {
                    return;
                }

                const point =
                    info.point;

                tooltip.innerHTML =
                    "<b>" +
                    historyTooltipDate(
                        point.timestamp
                    ) +
                    "</b><br>" +
                    label +
                    ": <b>" +
                    Number(
                        point.value
                    ).toFixed(
                        label === "Connections"
                        ? 0
                        : 1
                    ) +
                    (
                        unit
                        ? " " + unit
                        : ""
                    ) +
                    "</b>";

                tooltip.style.display =
                    "block";

                const left =
                    Math.min(
                        rect.width -
                        tooltip.offsetWidth -
                        8,
                        Math.max(
                            8,
                            event.clientX -
                            rect.left +
                            12
                        )
                    );

                const top =
                    Math.max(
                        8,
                        event.clientY -
                        rect.top -
                        tooltip.offsetHeight -
                        10
                    );

                tooltip.style.left =
                    left + "px";

                tooltip.style.top =
                    top + "px";
            }
        );

        canvas.addEventListener(
            "mouseleave",
            () => {

                if (tooltip) {
                    tooltip.style.display =
                        "none";
                }

                draw();
            }
        );
    }
}


function drawInteractiveTraffic(
    canvas,
    rows
) {

    if (!canvas || !rows.length) {
        return;
    }

    const data =
        trafficSeries(rows);

    const {
        width,
        height,
        dpr
    } = canvasSize(canvas);

    const ctx =
        canvas.getContext("2d");

    const tooltip =
        ensureChartTooltip(canvas);

    const padLeft =
        52 * dpr;

    const padRight =
        12 * dpr;

    const padTop =
        14 * dpr;

    const padBottom =
        30 * dpr;

    const plotWidth =
        width -
        padLeft -
        padRight;

    const plotHeight =
        height -
        padTop -
        padBottom;

    const maxTotal =
        Math.max(
            1,
            ...data.map(
                p =>
                    Number(p.rx) +
                    Number(p.tx)
            )
        );

    function xAt(index) {

        if (data.length <= 1) {
            return padLeft;
        }

        return (
            padLeft +
            index /
            (
                data.length - 1
            ) *
            plotWidth
        );
    }

    function yAt(value) {

        return (
            padTop +
            plotHeight -
            (
                Math.max(
                    0,
                    Math.min(
                        1,
                        value /
                        maxTotal
                    )
                ) *
                plotHeight
            )
        );
    }

    function draw(
        hoverIndex = null
    ) {

        ctx.clearRect(
            0,
            0,
            width,
            height
        );

        ctx.font =
            `${11 * dpr}px sans-serif`;

        /* grid and Y labels */

        ctx.strokeStyle =
            "rgba(255,255,255,0.08)";

        ctx.fillStyle =
            "#7f8998";

        for (
            let i = 0;
            i <= 4;
            i++
        ) {

            const value =
                maxTotal *
                i /
                4;

            const y =
                yAt(value);

            ctx.beginPath();

            ctx.moveTo(
                padLeft,
                y
            );

            ctx.lineTo(
                width - padRight,
                y
            );

            ctx.stroke();

            ctx.textAlign =
                "right";

            ctx.fillText(
                value.toFixed(1),
                padLeft -
                7 * dpr,
                y +
                4 * dpr
            );
        }

        /* X labels */

        ctx.textAlign =
            "center";

        const labels = 5;

        for (
            let i = 0;
            i < labels;
            i++
        ) {

            const idx =
                Math.round(
                    i *
                    (
                        data.length -
                        1
                    ) /
                    (
                        labels -
                        1
                    )
                );

            ctx.fillText(
                historyAxisLabel(
                    data[idx].timestamp
                ),
                xAt(idx),
                height -
                8 * dpr
            );
        }

        /* RX layer */

        ctx.beginPath();

        data.forEach(
            (point, index) => {

                const x =
                    xAt(index);

                const y =
                    yAt(point.rx);

                if (index === 0) {
                    ctx.moveTo(x, y);
                } else {
                    ctx.lineTo(x, y);
                }
            }
        );

        for (
            let i = data.length - 1;
            i >= 0;
            i--
        ) {
            ctx.lineTo(
                xAt(i),
                height -
                padBottom
            );
        }

        ctx.closePath();

        ctx.fillStyle =
            "rgba(88,166,255,0.42)";

        ctx.fill();

        /* TX layer */

        ctx.beginPath();

        data.forEach(
            (point, index) => {

                const total =
                    point.rx +
                    point.tx;

                const x =
                    xAt(index);

                const y =
                    yAt(total);

                if (index === 0) {
                    ctx.moveTo(x, y);
                } else {
                    ctx.lineTo(x, y);
                }
            }
        );

        for (
            let i = data.length - 1;
            i >= 0;
            i--
        ) {

            ctx.lineTo(
                xAt(i),
                yAt(
                    data[i].rx
                )
            );
        }

        ctx.closePath();

        ctx.fillStyle =
            "rgba(167,139,250,0.42)";

        ctx.fill();

        /* boundaries */

        ctx.lineWidth =
            1.8 * dpr;

        ctx.strokeStyle =
            "#58a6ff";

        ctx.beginPath();

        data.forEach(
            (point, index) => {

                const x =
                    xAt(index);

                const y =
                    yAt(point.rx);

                if (index === 0) {
                    ctx.moveTo(x, y);
                } else {
                    ctx.lineTo(x, y);
                }
            }
        );

        ctx.stroke();

        ctx.strokeStyle =
            "#a78bfa";

        ctx.beginPath();

        data.forEach(
            (point, index) => {

                const total =
                    point.rx +
                    point.tx;

                const x =
                    xAt(index);

                const y =
                    yAt(total);

                if (index === 0) {
                    ctx.moveTo(x, y);
                } else {
                    ctx.lineTo(x, y);
                }
            }
        );

        ctx.stroke();

        /* hover */

        if (
            hoverIndex !== null &&
            data[hoverIndex]
        ) {

            const point =
                data[hoverIndex];

            const x =
                xAt(hoverIndex);

            const total =
                point.rx +
                point.tx;

            const y =
                yAt(total);

            ctx.strokeStyle =
                "rgba(255,255,255,0.28)";

            ctx.lineWidth =
                dpr;

            ctx.beginPath();

            ctx.moveTo(
                x,
                padTop
            );

            ctx.lineTo(
                x,
                height -
                padBottom
            );

            ctx.stroke();

            ctx.fillStyle =
                "#a78bfa";

            ctx.beginPath();

            ctx.arc(
                x,
                y,
                4 * dpr,
                0,
                Math.PI * 2
            );

            ctx.fill();

            return point;
        }

        return null;
    }

    draw();

    if (
        !canvas._interactiveHistoryBound
    ) {

        canvas._interactiveHistoryBound =
            true;

        canvas.addEventListener(
            "mousemove",
            event => {

                const rect =
                    canvas.getBoundingClientRect();

                const px =
                    (
                        event.clientX -
                        rect.left
                    ) /
                    rect.width;

                const index =
                    Math.max(
                        0,
                        Math.min(
                            data.length - 1,
                            Math.round(
                                px *
                                (
                                    data.length -
                                    1
                                )
                            )
                        )
                    );

                const point =
                    draw(index);

                if (
                    !point ||
                    !tooltip
                ) {
                    return;
                }

                tooltip.innerHTML =
                    "<b>" +
                    historyTooltipDate(
                        point.timestamp
                    ) +
                    "</b><br>" +
                    "RX: <b>" +
                    Number(
                        point.rx
                    ).toFixed(2) +
                    " Mbit/s</b><br>" +
                    "TX: <b>" +
                    Number(
                        point.tx
                    ).toFixed(2) +
                    " Mbit/s</b><br>" +
                    "Всего: <b>" +
                    Number(
                        point.rx +
                        point.tx
                    ).toFixed(2) +
                    " Mbit/s</b>";

                tooltip.style.display =
                    "block";

                const left =
                    Math.min(
                        rect.width -
                        tooltip.offsetWidth -
                        8,
                        Math.max(
                            8,
                            event.clientX -
                            rect.left +
                            12
                        )
                    );

                const top =
                    Math.max(
                        8,
                        event.clientY -
                        rect.top -
                        tooltip.offsetHeight -
                        10
                    );

                tooltip.style.left =
                    left + "px";

                tooltip.style.top =
                    top + "px";
            }
        );

        canvas.addEventListener(
            "mouseleave",
            () => {

                if (tooltip) {
                    tooltip.style.display =
                        "none";
                }

                draw();
            }
        );
    }
}


function renderInteractiveHistory() {

    const rows =
        selectedHistoryRows;

    if (!rows.length) {
        return;
    }

    /*
     * Recreate interactive canvases before each render.
     *
     * The mouse handlers inside drawInteractiveTraffic()
     * and drawInteractiveLine() close over the data series
     * that existed when the handlers were created.
     *
     * When the history range changes (for example 24h -> 1h),
     * reusing the same canvas keeps the old handlers alive.
     * On mousemove they then redraw the old series.
     *
     * Cloning the canvas removes the stale handlers while
     * preserving its DOM attributes and visual size.
     */
    let trafficCanvas =
        document.getElementById(
            "trafficCombinedSpark"
        );

    if (trafficCanvas) {

        const freshTrafficCanvas =
            trafficCanvas.cloneNode(true);

        trafficCanvas.replaceWith(
            freshTrafficCanvas
        );

        trafficCanvas =
            freshTrafficCanvas;
    }

    drawInteractiveTraffic(
        trafficCanvas,
        rows
    );


    let connHistoryCanvas =
        document.getElementById(
            "connHistorySpark"
        );

    if (connHistoryCanvas) {

        const freshConnCanvas =
            connHistoryCanvas.cloneNode(true);

        connHistoryCanvas.replaceWith(
            freshConnCanvas
        );

        connHistoryCanvas =
            freshConnCanvas;
    }

    drawInteractiveLine(
        connHistoryCanvas,
        rows,
        row =>
            row.connections,
        "Connections",
        ""
    );

    drawSystemMiniAxesSpark(
        document.getElementById("cpuSpark"),
        rows,
        "cpu_percent"
    );

    drawSystemMiniAxesSpark(
        document.getElementById("ramSpark"),
        rows,
        "memory_percent",
        "bytes",
        window.systemResourceTotals.ram
    );

    drawSystemMiniAxesSpark(
        document.getElementById("diskSpark"),
        rows,
        "disk_percent",
        "bytes",
        window.systemResourceTotals.disk
    );

    const info =
        document.getElementById(
            "historyInfo"
        );

    if (info) {

        const first =
            rows[0];

        const last =
            rows[rows.length - 1];

        info.textContent =
            `${rows.length} точек · ` +
            `${historyTooltipDate(first.timestamp)}` +
            " — " +
            `${historyTooltipDate(last.timestamp)}`;
    }
}


async function loadSelectedHistory() {

    try {

        const result =
            await api(
                "/api/history?range=" +
                encodeURIComponent(
                    selectedHistoryRange
                )
            );

        selectedHistoryRows =
            Array.isArray(result.data)
            ? result.data
            : [];

        renderInteractiveHistory();

    } catch (e) {

        console.error(
            "history error",
            e
        );

        const info =
            document.getElementById(
                "historyInfo"
            );

        if (info) {
            info.textContent =
                "Ошибка загрузки истории";
        }
    }
}


function setHistoryRange(range) {

    selectedHistoryRange =
        range;

    document
        .querySelectorAll(
            ".history-range-btn"
        )
        .forEach(button => {

            button.classList.toggle(
                "active",
                button.dataset.range ===
                range
            );

        });

    loadSelectedHistory();
}


document
    .querySelectorAll(
        ".history-range-btn"
    )
    .forEach(button => {

        button.addEventListener(
            "click",
            () => {

                setHistoryRange(
                    button.dataset.range
                );

            }
        );
    });


/* Initial history load. */
loadSelectedHistory();

/* Refresh history every 30 seconds,
   while the main dashboard still refreshes
   every 5 seconds. */
setInterval(
    loadSelectedHistory,
    30000
);



refresh();

setInterval(
    async () => {

        await refresh();

        if (
            typeof renderInteractiveHistory ===
            "function"
        ) {
            renderInteractiveHistory();
        }

    },
    5000
);

</script>


<div
    id="userSettingsModal"
    style="
        display:none;
        position:fixed;
        inset:0;
        z-index:10000;
        background:rgba(0,0,0,.65);
        align-items:center;
        justify-content:center;
        padding:20px;
        box-sizing:border-box;
    "
>
    <div
        style="
            width:min(520px,100%);
            max-height:90vh;
            overflow:auto;
            background:#111827;
            color:#e5e7eb;
            border:1px solid rgba(148,163,184,.30);
            border-radius:14px;
            box-shadow:0 24px 70px rgba(0,0,0,.5);
            padding:20px;
            box-sizing:border-box;
        "
    >

        <div
            style="
                display:flex;
                justify-content:space-between;
                align-items:center;
                gap:12px;
                margin-bottom:18px;
            "
        >
            <div>
                <div
                    style="
                        font-size:18px;
                        font-weight:700;
                    "
                    id="userSettingsTitle"
                >
                    Настройки пользователя
                </div>

                <div
                    class="small muted"
                    id="userSettingsSubtitle"
                    style="margin-top:4px"
                >
                </div>
            </div>

            <button
                type="button"
                onclick="closeUserSettings()"
                style="
                    min-width:36px;
                    width:36px;
                    height:36px;
                    padding:0;
                    font-size:20px;
                "
            >
                ×
            </button>
        </div>


        <div
            style="
                display:grid;
                grid-template-columns:1fr;
                gap:12px;
            "
        >

            <label>
                <div
                    class="small muted"
                    style="margin-bottom:5px"
                >
                    Максимальное число соединений
                </div>

                <input
                    id="settingsMaxConns"
                    type="number"
                    min="1"
                    step="1"
                    placeholder="Не установлено"
                >
            </label>


            <label>
                <div
                    class="small muted"
                    style="margin-bottom:5px"
                >
                    Квота, GB
                </div>

                <input
                    id="settingsQuotaGb"
                    type="number"
                    min="0"
                    step="0.01"
                    placeholder="Не установлена"
                >
            </label>


            <label>
                <div
                    class="small muted"
                    style="margin-bottom:5px"
                >
                    Максимум уникальных IP
                </div>

                <input
                    id="settingsMaxIps"
                    type="number"
                    min="1"
                    step="1"
                    placeholder="Не установлено"
                >
            </label>


            <label>
                <div
                    class="small muted"
                    style="margin-bottom:5px"
                >
                    Срок действия
                </div>

                <input
                    id="settingsExpiration"
                    type="text"
                    maxlength="10"
                    inputmode="numeric"
                    autocomplete="off"
                    placeholder="ДД.ММ.ГГГГ"
                    oninput="formatExpirationInput(this)"
                >

                <div
                    class="small muted"
                    style="margin-top:4px"
                >
                    Формат: ДД.ММ.ГГГГ
                </div>
            </label>

        </div>


        <div
            class="small muted"
            style="
                margin-top:14px;
                line-height:1.45;
            "
        >
            Изменяются только заполненные поля.
            Пустое поле оставляет текущее значение без изменений.
        </div>


        <div
            style="
                display:flex;
                justify-content:flex-end;
                gap:8px;
                margin-top:20px;
            "
        >

            <button
                type="button"
                class="danger"
                onclick="clearUserLimits()"
                style="margin-right:auto"
            >
                Сбросить ограничения
            </button>

            <button
                type="button"
                onclick="closeUserSettings()"
            >
                Отмена
            </button>

            <button
                type="button"
                class="good"
                onclick="saveUserSettings()"
            >
                Сохранить
            </button>

        </div>

    </div>
</div>


<div
    id="telegramQrModal"
    style="
        display:none;
        position:fixed;
        inset:0;
        z-index:11000;
        background:rgba(0,0,0,.70);
        align-items:center;
        justify-content:center;
        padding:20px;
        box-sizing:border-box;
    "
    onclick="if(event.target===this) closeTelegramQr()"
>
    <div
        style="
            width:min(420px,100%);
            background:#111827;
            color:#e5e7eb;
            border:1px solid rgba(148,163,184,.30);
            border-radius:14px;
            box-shadow:0 24px 70px rgba(0,0,0,.55);
            padding:20px;
            box-sizing:border-box;
            text-align:center;
        "
    >

        <div
            style="
                font-size:18px;
                font-weight:700;
                margin-bottom:14px;
            "
        >
            Telegram
        </div>

        <div
            style="
                background:#ffffff;
                border-radius:10px;
                padding:14px;
                display:inline-block;
            "
        >
            <div
                id="telegramQrContainer"
                style="
                    width:260px;
                    height:260px;
                    max-width:70vw;
                    max-height:70vw;
                    display:flex;
                    align-items:center;
                    justify-content:center;
                    overflow:hidden;
                "
            ></div>
        </div>

        <div
            id="telegramQrLink"
            style="
                margin-top:14px;
                font-size:12px;
                line-height:1.4;
                color:#94a3b8;
                word-break:break-all;
                text-align:left;
            "
        ></div>

        <div
            style="
                display:flex;
                justify-content:center;
                gap:8px;
                margin-top:16px;
            "
        >
            <button
                type="button"
                class="good"
                onclick="closeTelegramQr()"
            >
                Закрыть
            </button>
        </div>

    </div>
</div>


<script>
function hideTelegramExtraRows() {

    const ids = [
        "tlsDomain",
        "modes",
        "readonly",
        "ready"
    ];

    ids.forEach(function(id) {

        const el = document.getElementById(id);

        if (!el) {
            return;
        }

        let node = el.parentElement;

        for (let i = 0; i < 4 && node; i++) {

            const text =
                (node.innerText || "")
                .replace(/\s+/g, " ")
                .trim();

            /*
             * Ищем именно небольшую строку,
             * а не всю карточку.
             */
            if (
                text.length > 0 &&
                text.length < 100 &&
                node.children.length >= 2
            ) {
                node.style.display = "none";
                return;
            }

            node = node.parentElement;
        }
    });
}

document.addEventListener(
    "DOMContentLoaded",
    hideTelegramExtraRows
);
</script>

</body>
</html>
"""


# ============================================================
# HTTP SERVER
# ============================================================

class Handler(BaseHTTPRequestHandler):

    server_version = "Telemt443Web/1.0"

    def log_message(self, fmt, *args):
        print(
            "%s - %s"
            % (
                self.address_string(),
                fmt % args,
            )
        )

    def is_authenticated(self):

        if not PANEL_PASSWORD:
            return True

        header = self.headers.get("Authorization", "")

        if not header.startswith("Basic "):
            return False

        try:
            raw = base64.b64decode(
                header[6:]
            ).decode(
                "utf-8",
                errors="strict"
            )

            username, password = raw.split(
                ":",
                1
            )

        except Exception:
            return False

        return (
            username == PANEL_USER
            and secrets_equal(
                password,
                PANEL_PASSWORD
            )
        )

    def require_auth(self):

        if self.is_authenticated():
            return True

        self.send_response(
            HTTPStatus.UNAUTHORIZED
        )

        self.send_header(
            "WWW-Authenticate",
            'Basic realm="Telemt 443 Control"'
        )

        self.send_header(
            "Content-Type",
            "text/plain; charset=utf-8"
        )

        self.end_headers()

        self.wfile.write(
            b"Authentication required\n"
        )

        return False

    def send_json(self, status, payload):

        raw = json.dumps(
            payload,
            ensure_ascii=False
        ).encode("utf-8")

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )

        self.send_header(
            "Cache-Control",
            "no-store"
        )

        self.send_header(
            "Content-Length",
            str(len(raw))
        )

        self.end_headers()

        self.wfile.write(raw)

    def read_body(self):

        length = int(
            self.headers.get(
                "Content-Length",
                "0"
            )
        )

        if length > 1024 * 1024:
            raise ValueError(
                "Request body too large"
            )

        if length <= 0:
            return {}

        raw = self.rfile.read(length)

        return json.loads(
            raw.decode("utf-8")
        )

    def do_GET(self):

        if not self.require_auth():
            return

        parsed = urllib.parse.urlparse(
            self.path
        )

        path = parsed.path

        if path == "/api/public-host":
            try:
                self.send_json(200, {"ok": True, "host": read_public_host()})
            except Exception as e:
                self.send_json(500, {"ok": False, "error": str(e)})
            return


        if path == "/xray":

            raw = xray_page_html().encode(
                "utf-8"
            )

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8"
            )
            self.send_header(
                "Cache-Control",
                "no-store"
            )
            self.send_header(
                "Content-Length",
                str(len(raw))
            )
            self.end_headers()
            self.wfile.write(raw)
            return


        if path == "/xray/qrcode.js":

            raw = xray_qrcode_js().encode(
                "utf-8"
            )

            if not raw:
                self.send_error(
                    404,
                    "QR library not found"
                )
                return

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/javascript; charset=utf-8"
            )
            self.send_header(
                "Cache-Control",
                "no-store"
            )
            self.send_header(
                "Content-Length",
                str(len(raw))
            )
            self.end_headers()
            self.wfile.write(raw)
            return


        if path == "/api/xray/dashboard":

            self.send_json(
                200,
                xray_dashboard()
            )
            return


        if path == "/api/xray/history":

            query = urllib.parse.parse_qs(
                parsed.query
            )

            period = query.get(
                "range",
                ["24h"]
            )[0]

            self.send_json(
                200,
                {
                    "ok": True,
                    "range": period,
                    "data":
                        xray_load_history(
                            period
                        ),
                }
            )
            return


        if path == "/":

            raw = HTML.encode("utf-8")

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8"
            )

            self.send_header(
                "Cache-Control",
                "no-store"
            )

            self.send_header(
                "Content-Length",
                str(len(raw))
            )

            self.end_headers()

            self.wfile.write(raw)

            return

        if path == "/api/dashboard":

            try:

                tel = telemt_snapshot()
                system = system_metrics()
                service = container_status()

                conns = total_connections(tel)
                users = tel.get("users", [])
                stats = tel.get("stats") or {}

                if not isinstance(stats, dict):
                    stats = {}

                connections_total = int(
                    stats.get("connections_total") or 0
                )

                connections_bad_total = int(
                    stats.get("connections_bad_total") or 0
                )

                handshake_failures = 0

                for item in (
                    stats.get("handshake_failures_by_class") or []
                ):
                    if isinstance(item, dict):
                        try:
                            handshake_failures += int(
                                item.get("total") or 0
                            )
                        except Exception:
                            pass

                active_ips = 0

                for user in users:
                    try:
                        active_ips += int(
                            user.get("active_unique_ips") or 0
                        )
                    except Exception:
                        pass

                service["connections"] = conns
                service["connections_total"] = connections_total
                service["connections_bad_total"] = connections_bad_total
                service["handshake_failures_total"] = handshake_failures
                service["active_ips"] = active_ips
                service["traffic_bytes"] = total_traffic(tel)
                service["user_count"] = len(users)

                config = {
                    "tls_domain": "google.com",
                    "mode": "TLS / FakeTLS",
                }

                try:
                    import tomllib

                    cfg_path = Path(
                        "/opt/telemt-443/config/config.toml"
                    )

                    if cfg_path.exists():
                        with cfg_path.open("rb") as f:
                            cfg = tomllib.load(f)

                        config["tls_domain"] = (
                            cfg.get("censorship", {})
                            .get(
                                "tls_domain",
                                "google.com"
                            )
                        )

                        modes = (
                            cfg.get("general", {})
                            .get("modes", {})
                        )

                        if modes.get("tls"):
                            config["mode"] = "TLS / FakeTLS"

                except Exception:
                    pass

                self.send_json(
                    200,
                    {
                        "ok": True,
                        "service": service,
                        "telemt": tel,
                        "system": system,
                        "config": config,
                        "history": load_history(),
                        "logs": docker_logs(80),
                    }
                )

            except Exception as e:

                self.send_json(
                    500,
                    {
                        "ok": False,
                        "error": str(e),
                    }
                )

            return

        if path == "/api/history":

            try:
                query = urllib.parse.parse_qs(
                    parsed.query
                )

                period = query.get(
                    "range",
                    ["24h"]
                )[0]

                if period not in HISTORY_RANGES:
                    period = "24h"

                rows = load_history_range(
                    period
                )

                self.send_json(
                    200,
                    {
                        "ok": True,
                        "range": period,
                        "points": len(rows),
                        "data": rows,
                    }
                )

            except Exception as e:

                self.send_json(
                    500,
                    {
                        "ok": False,
                        "error": str(e),
                    }
                )

            return

        self.send_json(
            404,
            {
                "ok": False,
                "error": "not_found",
            }
        )

    def do_POST(self):

        if not self.require_auth():
            return

        parsed = urllib.parse.urlparse(
            self.path
        )

        path = parsed.path

        try:

            if path == "/api/public-host":
                body = self.read_body()
                host = validate_public_host(body.get("host"))

                # Снимок текущих файлов для отката при ошибке.
                config_old = PUBLIC_HOST_CONFIG.read_text(encoding="utf-8")
                telemt_env_old = PUBLIC_HOST_ENV.read_text(encoding="utf-8")
                panel_env_old = PANEL_ENV.read_text(encoding="utf-8")

                config_new = replace_public_host_config(config_old, host)
                telemt_env_new = replace_env_value(telemt_env_old, "PUBLIC_HOST", host)
                panel_env_new = replace_env_value(panel_env_old, "XRAY_PUBLIC_HOST", host)

                # Резервная копия перед каждым применением из веб-интерфейса.
                apply_dir = APP / "backups" / (
                    "apply-" + datetime.now().strftime("%Y%m%d-%H%M%S")
                )
                apply_dir.mkdir(parents=True, exist_ok=False)
                os.chmod(apply_dir, 0o700)
                for path_to_save in (PUBLIC_HOST_CONFIG, PUBLIC_HOST_ENV, PANEL_ENV):
                    backup_name = {
                        PUBLIC_HOST_CONFIG: "telemt-config.toml",
                        PUBLIC_HOST_ENV: "telemt.env",
                        PANEL_ENV: "panel.env",
                    }[path_to_save]
                    shutil.copy2(path_to_save, apply_dir / backup_name)

                try:
                    atomic_write(PUBLIC_HOST_CONFIG, config_new)
                    atomic_write(PUBLIC_HOST_ENV, telemt_env_new)
                    atomic_write(PANEL_ENV, panel_env_new)

                    code, output = run_command(
                        ["docker", "restart", CONTAINER], timeout=40
                    )
                    if code != 0:
                        raise RuntimeError("Ошибка перезапуска Telemt: " + output[-1000:])

                    code, state = run_command(
                        ["docker", "inspect", "--format", "{{.State.Running}}", CONTAINER],
                        timeout=10
                    )
                    if code != 0 or state.strip() != "true":
                        raise RuntimeError("Контейнер Telemt не перешёл в состояние running")

                    # Ссылка Xray строится этим модулем в текущем процессе.
                    xray_panel.XRAY_PUBLIC_HOST = host

                except Exception:
                    atomic_write(PUBLIC_HOST_CONFIG, config_old)
                    atomic_write(PUBLIC_HOST_ENV, telemt_env_old)
                    atomic_write(PANEL_ENV, panel_env_old)
                    run_command(["docker", "restart", CONTAINER], timeout=40)
                    raise

                self.send_json(200, {
                    "ok": True,
                    "host": host,
                    "message": "Адрес применён; Telemt перезапущен",
                })
                return

            if path == "/api/xray/users/create":

                body = self.read_body()

                result = xray_create_user(
                    body.get("username")
                )

                self.send_json(
                    200,
                    {
                        "ok": True,
                        "message":
                            "Пользователь создан",
                        "link":
                            result.get("link")
                        if isinstance(result, dict)
                        else None,
                        "user": result,
                    }
                )

                return


            if path.startswith(
                "/api/xray/users/"
            ):

                suffix = path[
                    len("/api/xray/users/"):
                ]

                if suffix.endswith(
                    "/enable"
                ):

                    username = urllib.parse.unquote(
                        suffix[
                            :-len("/enable")
                        ].rstrip("/")
                    )

                    result = xray_set_user_enabled(
                            username,
                            True
                        )

                    self.send_json(
                        200,
                        result
                    )

                    return


                if suffix.endswith(
                    "/disable"
                ):

                    username = urllib.parse.unquote(
                        suffix[
                            :-len("/disable")
                        ].rstrip("/")
                    )

                    result = xray_set_user_enabled(
                            username,
                            False
                        )

                    self.send_json(
                        200,
                        result
                    )

                    return


                if suffix.endswith(
                    "/delete"
                ):

                    username = urllib.parse.unquote(
                        suffix[
                            :-len("/delete")
                        ].rstrip("/")
                    )

                    result = xray_delete_user(
                            username
                        )

                    self.send_json(
                        200,
                        result
                    )

                    return


            if path == "/api/service/start":

                code, output = run_command(
                    ["docker", "start", CONTAINER]
                )

                if code != 0:
                    self.send_json(
                        500,
                        {
                            "ok": False,
                            "error": output,
                        }
                    )
                    return

                self.send_json(
                    200,
                    {
                        "ok": True,
                        "message": "Telemt запущен",
                    }
                )
                return

            if path == "/api/service/stop":

                code, output = run_command(
                    ["docker", "stop", CONTAINER]
                )

                if code != 0:
                    self.send_json(
                        500,
                        {
                            "ok": False,
                            "error": output,
                        }
                    )
                    return

                self.send_json(
                    200,
                    {
                        "ok": True,
                        "message": "Telemt остановлен",
                    }
                )
                return

            if path == "/api/service/restart":

                code, output = run_command(
                    ["docker", "restart", CONTAINER],
                    timeout=30
                )

                if code != 0:
                    self.send_json(
                        500,
                        {
                            "ok": False,
                            "error": output,
                        }
                    )
                    return

                self.send_json(
                    200,
                    {
                        "ok": True,
                        "message": "Telemt перезапущен",
                    }
                )
                return

            if path == "/api/users/create":

                body = self.read_body()

                username = str(
                    body.get("username", "")
                ).strip()

                if not username:
                    raise ValueError(
                        "username is required"
                    )

                payload = {
                    "username": username
                }

                if body.get("max_tcp_conns"):
                    payload["max_tcp_conns"] = int(
                        body["max_tcp_conns"]
                    )

                if body.get("data_quota_bytes"):
                    payload["data_quota_bytes"] = int(
                        body["data_quota_bytes"]
                    )

                if body.get("expiration_rfc3339"):
                    payload[
                        "expiration_rfc3339"
                    ] = str(
                        body["expiration_rfc3339"]
                    )

                status, result = api_request(
                    "POST",
                    "/v1/users",
                    payload
                )

                self.send_json(
                    status or 500,
                    result
                )

                return

            if path.startswith(
                "/api/users/"
            ):

                suffix = path[len(
                    "/api/users/"
                ):]

                if suffix.endswith("/enable"):

                    username = urllib.parse.unquote(
                        suffix[:-len("/enable")].rstrip("/")
                    )

                    status, result = api_request(
                        "POST",
                        "/v1/users/" +
                        urllib.parse.quote(
                            username,
                            safe=""
                        ) +
                        "/enable"
                    )

                    self.send_json(
                        status or 500,
                        result
                    )

                    return

                if suffix.endswith("/disable"):

                    username = urllib.parse.unquote(
                        suffix[:-len("/disable")].rstrip("/")
                    )

                    status, result = api_request(
                        "POST",
                        "/v1/users/" +
                        urllib.parse.quote(
                            username,
                            safe=""
                        ) +
                        "/disable"
                    )

                    self.send_json(
                        status or 500,
                        result
                    )

                    return

                if suffix.endswith("/rotate-secret"):

                    username = urllib.parse.unquote(
                        suffix[:-len("/rotate-secret")].rstrip("/")
                    )

                    status, result = api_request(
                        "POST",
                        "/v1/users/" +
                        urllib.parse.quote(
                            username,
                            safe=""
                        ) +
                        "/rotate-secret"
                    )

                    self.send_json(
                        status or 500,
                        result
                    )

                    return

                if suffix.endswith("/reset-quota"):

                    username = urllib.parse.unquote(
                        suffix[:-len("/reset-quota")].rstrip("/")
                    )

                    status, result = api_request(
                        "POST",
                        "/v1/users/" +
                        urllib.parse.quote(
                            username,
                            safe=""
                        ) +
                        "/reset-quota"
                    )

                    self.send_json(
                        status or 500,
                        result
                    )

                    return

                if suffix.endswith("/patch"):

                    username = urllib.parse.unquote(
                        suffix[:-len("/patch")].rstrip("/")
                    )

                    body = self.read_body()

                    status, result = api_request(
                        "PATCH",
                        "/v1/users/" +
                        urllib.parse.quote(
                            username,
                            safe=""
                        ),
                        body
                    )

                    self.send_json(
                        status or 500,
                        result
                    )

                    return

        except Exception as e:

            self.send_json(
                400,
                {
                    "ok": False,
                    "error": str(e),
                }
            )

            return

        self.send_json(
            404,
            {
                "ok": False,
                "error": "not_found",
            }
        )

    def do_DELETE(self):

        if not self.require_auth():
            return

        parsed = urllib.parse.urlparse(
            self.path
        )

        path = parsed.path

        if path.startswith(
            "/api/users/"
        ):

            username = urllib.parse.unquote(
                path[len("/api/users/"):]
            ).strip("/")

            if not username:
                self.send_json(
                    400,
                    {
                        "ok": False,
                        "error": "username required",
                    }
                )
                return

            status, result = api_request(
                "DELETE",
                "/v1/users/" +
                urllib.parse.quote(
                    username,
                    safe=""
                )
            )

            self.send_json(
                status or 500,
                result
            )

            return

        self.send_json(
            404,
            {
                "ok": False,
                "error": "not_found",
            }
        )


def secrets_equal(a, b):
    return hashlib.sha256(
        a.encode()
    ).digest() == hashlib.sha256(
        b.encode()
    ).digest()


def main():

    DATA.mkdir(
        parents=True,
        exist_ok=True
    )

    threading.Thread(
        target=sampler,
        daemon=True
    ).start()

    server = ThreadingHTTPServer(
        ("0.0.0.0", PORT),
        Handler
    )

    print(
        f"Telemt 443 web monitor listening on 0.0.0.0:{PORT}"
    )

    server.serve_forever()


if __name__ == "__main__":
    main()
