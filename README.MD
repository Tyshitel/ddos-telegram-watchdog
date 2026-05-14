# DDoS Telegram Watchdog

Telegram-бот для мониторинга DDoS-активности на нескольких VDS.

---

# Возможности

- мониторинг нескольких VDS
- алерт при DDoS
- сообщение о нормализации атаки
- inline-кнопки статуса VDS
- кнопка возврата в меню
- кнопки блокировки IP
- блокировка через ipset + iptables
- список заблокированных IP
- whitelist hits
- имена портов

---

# Структура

```text
ddos_alert.py — основной Telegram-бот, запускается на VDS1
agent.py — агент метрик, запускается на каждой VDS
servers.json — конфиг
```

Пример структуры:

```text
VDS1 (основной):
├── servers.json
├── agent.py
└── ddos_alert.py

VDS2:
└── agent.py
```

---

# Этапы установки

## Установка зависимостей

```bash
sudo apt update
sudo apt install -y python3 python3-requests ipset iptables
```

---

# Скачивание файлов

Скачанные файлы можно положить в:

```text
/home/user/ddos_alert
```

или сразу в:

```text
/opt/ddos_alert
```

---

# Создание папок

## VDS1

Здесь должны находиться:

```text
servers.json
agent.py
ddos_alert.py
```

Создаем папку:

```bash
mkdir /opt/ddos_alert
cd /opt/ddos_alert
```

Перемещаем файлы:

```bash
mv /home/user/ddo_alert/* /opt/ddos_alert
```

Даем права:

```bash
chmod +x /opt/ddos_alert/*.py
```

---

## VDS2

Здесь должен находиться:

```text
agent.py
```

Создаем папку:

```bash
mkdir /opt/ddos_alert
cd /opt/ddos_alert
```

Перемещаем файлы:

```bash
mv /home/user/ddo_alert/* /opt/ddos_alert
```

Даем права:

```bash
chmod +x /opt/ddos_alert/*.py
```

---

# Правило для iptables

Обязательно, если нужен ban.

```bash
ipset create proxy_blacklist hash:ip timeout 9000 -exist
iptables -I INPUT -m set --match-set proxy_blacklist src -j DROP
```

---

# Открытие порта на VDS2

Порт `9000` должен быть открыт только для VDS1.

```bash
sudo ufw allow from VDS1_IP to any port 9000 proto tcp
```

---

# Создание systemd

## agent.py

```bash
sudo nano /etc/systemd/system/ddos-agent.service
```

```ini
[Unit]
Description=DDoS Metrics Agent
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/ddos_alert/agent.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

---

## ddos_alert.py

```bash
sudo nano /etc/systemd/system/ddos-alert.service
```

```ini
[Unit]
Description=DDoS Telegram Alert Bot
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/ddos_alert/ddos_alert.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

---

# Запуск

## На каждой VDS

```bash
sudo systemctl daemon-reload
sudo systemctl start ddos-agent
sudo systemctl enable --now ddos-agent
sudo systemctl status ddos-agent
```

---

## На VDS1

```bash
sudo systemctl start ddos-alert
sudo systemctl enable --now ddos-alert
sudo systemctl status ddos-alert
```

---

# Настройка servers.json

```json
{
  "telegram": {
    "bot_token": "PASTE_BOT_TOKEN",
    "chat_id": "PASTE_CHAT_ID"
  },
  "servers": [
    {
      "name": "VDS1",
      "url": "http://127.0.0.1:9000/metrics"
    },
    {
      "name": "VDS2",
      "url": "http://VDS2_IP:9000/metrics"
    }
  ]
}
```

---

## Описание

```text
PASTE_BOT_TOKEN = токен от @BotFather
PASTE_CHAT_ID = ID чата для отправки алертов
```

Добавление новых VDS:

```json
{
  "name": "VDS3",
  "url": "http://VDS3_IP:9000/metrics"
}
```

Inline-кнопки и Telegram-команды создаются автоматически.

---

# Настройка ddos_alert.py

Настраиваются пороги детекта.

```python
MAX_TOTAL_CONNECTIONS = 2000
MAX_SYN_RECV = 300
MAX_RX_MBPS = 45.0
MAX_CONN_PER_IP = 300
ALERT_COOLDOWN_SECONDS = 2000
```

---

## MAX_TOTAL_CONNECTIONS

Если соединений больше `2000` → тревога.

Для proxy/VPN лучше повышать:

```python
10000
15000
```

---

## MAX_SYN_RECV

Количество полуоткрытых TCP-соединений.

Ловит:

- SYN flood
- exhaustion attack
- handshake flood

Норма:

```text
SYN_RECV: 2
```

Подозрительно:

```text
SYN_RECV: 500
```

Рекомендуемо:

```python
300-500
```

---

## MAX_RX_MBPS

Порог входящего трафика.

Если RX выше:

```python
45 Mbps
```

будет алерт.

Ловит:

- volumetric DDoS
- UDP flood
- packet flood

Рекомендуемые значения:

```text
100 Mbps канал → 45
1 Gbit канал → 200-500
```

---

## MAX_CONN_PER_IP

Максимум соединений от одного IP.

Ловит:

- одного атакующего
- агрессивных ботов
- сканеры

Для proxy/VPN лучше:

```python
1000-1500
```

---

## ALERT_COOLDOWN_SECONDS

Антиспам между повторными алертами.

```python
2000 секунд ≈ 33 минуты
```

Логика:

```text
атака началась → алерт
атака продолжается → молчит
прошло 33 минуты → повторный алерт
```

---

# Рекомендуемые значения для Proxy/VPN

```python
MAX_TOTAL_CONNECTIONS = 10000
MAX_SYN_RECV = 300
MAX_RX_MBPS = 80
MAX_CONN_PER_IP = 1500
ALERT_COOLDOWN_SECONDS = 600
```

---

# Логика срабатывания

Алерт отправляется если выполняется любое условие:

```text
Connections > MAX_TOTAL_CONNECTIONS
или
SYN_RECV > MAX_SYN_RECV
или
RX > MAX_RX_MBPS
или
Single IP > MAX_CONN_PER_IP
```

---

# Настройка agent.py

## Сетевой интерфейс

```python
NET_IFACE = "eth0"
```

---

## Какие порты отслеживать

```python
WATCH_PORTS = [
    443,
    80
]
```

---

## Имена портов

```python
PORT_NAMES = {
    443: "HTTPS",
    80: "HTTP"
}
```

---

# Whitelist

IP и сети, которые игнорируются ботом.

```python
WHITELIST_IPS = {
    "127.0.0.1",
    "::1"
}

WHITELIST_NETWORKS = [
    "149.154.160.0/20",
    "91.108.4.0/22"
]
```

---

# Проверка бана

```bash
sudo ipset list proxy_blacklist
sudo ipset test proxy_blacklist IP
sudo iptables -L INPUT -n -v | grep proxy_blacklist
```
