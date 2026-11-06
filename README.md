# vless-proxy-vps

Self-hosted VPN-прокси для организации защищённого удалённого доступа к
интернет-ресурсам и домашней сети. Технический образовательный проект:
xray (VLESS Reality), telemt (прокси для мессенджеров) и веб-панель
управления. Ставится одним интерактивным скриптом на чистый Ubuntu/Debian.

## Документация

- [Руководство пользователя (PDF)](docs/user-guide-ru.pdf) — использование и
  администрирование сервера: веб-панель, подключение клиентов, telemt,
  смена адреса и пароля, мониторинг, квоты и пользователи.

## Установка

На чистый Ubuntu (нужен root и интернет):

```bash
git clone https://github.com/asedavnykh/vless-proxy-vps.git
cd vless-proxy-vps
sudo ./install.sh
```

Скрипт спросит:

- публичный адрес сервера (IP/домен, определяется автоматически);
- порт VPN (VLESS Reality) и домен-маскировку (SNI);
- порт telemt и домен FakeTLS;
- порт, логин и пароль веб-панели;
- имена VPN-клиентов.

Далее он сам: ставит xray и Docker, генерирует ключи и конфиги, поднимает
два сервиса — **VPN** (systemd `xray@main`) и **Telemt** (docker compose) —
и запускает веб-панель (systemd `telemt-web`). На выходе печатает готовые
ссылки `vless://` для клиентов и адрес панели.

Проверка генерации конфигов без установки (на любой машине):

```bash
./install.sh --gen-test    # файлы в ./gen-test, система не меняется
```

## Веб-панель

`http://<СЕРВЕР>:4443/` — управление и мониторинг:

- VPN: пользователи (создание, включение/отключение, удаление), ссылки/QR
  для клиентов, статистика трафика;
- Telemt: статус, активные клиенты, история;
- система: нагрузка, диск, история.

Панель работает поверх HTTP с авторизацией (логин/пароль задаются при
установке, файл `/opt/telemt-web/.env`, chmod 600). Ограничьте доступ к порту
панели файрволом или открывайте только через VPN.

## VLESS+TLS для клиентов sing-box (второй вход)

REALITY-вход (порт 8443) с Xray-core v26.9.8+ не принимает клиентов на
sing-box: сервер требует в ClientHello постквантовый ключ X25519MLKEM768,
а клиент sing-box его вырезает (sing-box issue #4520, на ноябрь 2026 не
исправлен). Клиенты получают `reality verification failed`, хотя
Shadowrocket/v2rayNG/Xray-клиенты подключаются нормально.

Решение — второй вход VLESS+TLS с обычным сертификатом Let's Encrypt
(домен `<IP-ЧЕРЕЗ-ДЕФИС>.sslip.io` — DNS-имя из IP, отдельная покупка
домена не нужна). REALITY-вход при этом продолжает работать для остальных
клиентов.

1. Выпуск сертификата (порт 80 должен быть свободен):

   ```sh
   apt-get install -y certbot
   certbot certonly --standalone -d <IP-ЧЕРЕЗ-ДЕФИС>.sslip.io \
     --noninteractive --agree-tos --register-unsafely-without-email
   mkdir -p /usr/local/etc/xray/tls
   cp /etc/letsencrypt/live/<IP-ЧЕРЕЗ-ДЕФИС>.sslip.io/{fullchain,privkey}.pem /usr/local/etc/xray/tls/
   chown xray:xray /usr/local/etc/xray/tls/*.pem && chmod 640 /usr/local/etc/xray/tls/privkey.pem
   ```

2. Hook автопродления `/etc/letsencrypt/renewal-hooks/deploy/xray-tls-reload.sh`
   (chmod +x):

   ```sh
   #!/bin/sh
   cp /etc/letsencrypt/live/<IP-ЧЕРЕЗ-ДЕФИС>.sslip.io/{fullchain,privkey}.pem /usr/local/etc/xray/tls/
   chown xray:xray /usr/local/etc/xray/tls/*.pem
   chmod 640 /usr/local/etc/xray/tls/privkey.pem
   systemctl restart xray.service
   ```

3. Конфиг `/usr/local/etc/xray/config.json` — см. `xray/vless-tls.example.json`
   (порт 2053, `flow: xtls-rprx-vision`). Пустой `config.json` обслуживается
   сервисом `xray.service` и не пересекается с `xray@main` (REALITY + панель).

   ```sh
   systemctl restart xray.service && ss -lntp | grep 2053
   ```

Ссылка для клиента:

```
vless://<UUID>@<IP-СЕРВЕРА>:2053?type=tcp&security=tls&sni=<IP-ЧЕРЕЗ-ДЕФИС>.sslip.io&flow=xtls-rprx-vision&encryption=none#имя
```

## Состав

```
install.sh                # интерактивный установщик (см. выше)
xray/
  config.example.json     # шаблон конфигурации xray (VLESS Reality + API/статистика)
  vless-tls.example.json  # второй вход VLESS+TLS (совместимость с sing-box, см. README)
  xray@.service           # systemd-шаблон: xray@<имя> для инстансов
telemt/
  docker-compose.yml      # telemt (шаблон: __TELEMT_PORT__)
  config.toml.example     # шаблон конфигурации telemt
  telemt-clients.sh       # список клиентов telemt
  telemt-monitor.sh       # мониторинг клиентов/сессий
web/
  server.py               # веб-панель (HTTP + авторизация)
  xray_panel.py           # модуль управления xray для панели
  .env.example            # шаблон настроек панели
  telemt-web.service      # systemd-юнит панели (шаблон: __PANEL_HOME__)
```

## Расположение на сервере

| Компонент  | Путь                       | Сервис                    |
|------------|----------------------------|---------------------------|
| xray       | `/usr/local/etc/xray/main.json` | `xray@main`          |
| telemt     | `/opt/telemt/`             | docker compose (`telemt`)  |
| веб-панель | `/opt/telemt-web/`         | `telemt-web`               |

## Ответственность

Проект носит технический образовательный характер, не является коммерческим
сервисом и не предоставляет услуг доступа. Пользователь самостоятельно несёт
ответственность за соблюдение законодательства своей страны при установке,
использовании и распространении данного программного обеспечения.

