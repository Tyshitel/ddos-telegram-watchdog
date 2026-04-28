# DDoS Telegram Watchdog

Telegram-бот для мониторинга DDoS-активности на нескольких VDS.

## Возможности

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

## Структура

- `ddos_alert.py` — основной Telegram-бот, запускается на VDS1
- `agent.py` — агент метрик, запускается на каждой VDS
- `servers.json` — пример конфига
  
Пример:
VDS1(основной):    |    VDS2:
servers.json       |    agent.py
agent.py           |
ddos_alert.py      |

# Этапы:
### Установка
```bash
sudo apt update
sudo apt install -y python3 python3-requests ipset iptables
```
### Скачиваем файлы
Скаченые файлы можно положить в папку /home/user/ddos_alert или сразу в /opt/ddos_alert

### Создаем папки на VDS, если не были созданы
VDS1
```bash
mkdir /opt/ddos_alert 
cd /opt/ddos_alert
# Здесь мы оставляем из архива такие файлы как:
# servers.json
# agent.py
# ddos_alert.py

# и даем им разрешение:
chmod +7 *.py
```
VDS2
```bash
mkdir /opt/ddos_alert
cd /opt/ddos_alert
# Здесь мы оставляем из архива такие файлы как:
# agent.py

# и даем разрешение:
chmod +7 *.py
```

### Правило для iptables 
```bash
# Обязательно, если хотим чтобы бан работал
ipset create proxy_blacklist hash:ip timeout 9000 -exist
iptables -I INPUT -m set --match-set proxy_blacklist src -j DROP
```

### Открыть порт в firewall на VDS2
```bash
# Порт 9000 должен быть открыт только для VDS1
sudo ufw allow from VDS1_IP to any port 9000 proto tcp
```
### Создаем systemd 
Под agent.py
```bash
sudo nano /etc/systemd/system/ddos-agent.service
```
```bash
[Unit]
Description=DDoS Metrics Agent
After=network-online.target

[Service]
ExecStart=/usr/bin/python /opt/ddos_alert/agent.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

Под ddos_alert.py
```bash
sudo nano /etc/systemd/system/ddos-alert.service
```
```bash
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
На каждой VDS
```bash
sudo systemctl daemon-reload
sudo systemctl start ddos-agent
sudo systemctl enable --now ddos-agent
sudo systemctl status ddos-agent # Проверка статуса
```
На VDS1
```
sudo systemctl start  ddos-alert
sudo systemctl enable --now ddos-alert
sudo systemctl status ddos-alert  # Проверка статуса
```

# Структура файлов

### servers.json настройка
- PASTE_BOT_TOKEN = нужен токен из @botfather
- PASTE_CHAT_ID = нужен ваш ChatID, то есть в какой чат будет отсылаться
- VDS1, VDS2 и тд. = Добавляем новые сервера с IP. inline кнопки будут появляться автоматически

```bash
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

### ddos_alert.py настройка
Настраиваются пороги при котором будет срабатывать алерт
```bash
MAX_TOTAL_CONNECTIONS = 2000 
MAX_SYN_RECV = 300
MAX_RX_MBPS = 45.0
MAX_CONN_PER_IP = 300
ALERT_COOLDOWN_SECONDS = 2000
```
```
MAX_TOTAL_CONNECTIONS
```
Если соединений больше 2000, будет тревога.
Для нагруженных proxy/VPN лучше повысить до максимум 15000
```
MAX_SYN_RECV
```
Максимальное количество полуоткрытых TCP-соединений.
Ловит:
- SYN flood
- exhaustion атаки
- handshake flood
Норма:
- SYN_RECV: 2
Подозрительно:
- SYN_RECV: 500
Рекомендуемые значения до 500

```
MAX_RX_MBPS
```
Порог входящего трафика (Mbps).
Если входящий поток выше 45 Mbp, будет алерт.
Обнаруживает:
- volumetric DDoS
- UDP flood
- packet flood
Для 100 Mbps канала:
45
Для 1 Gbit:
200
300
500
  
```
MAX_CONN_PER_IP
```
Максимум соединений от одного IP.
Ловит:
- один атакующий IP
- сканеры
- агрессивных ботов
Для proxy обычно лучше выше:
1000
1500
  
```
ALERT_COOLDOWN_SECONDS
```
Антиспам между повторными алертами. 2000 секунд ≈ 33 минуты
Логика:
атака началась → алерт
атака продолжается → молчит
прошло 33 минуты → повторный алерт

Рекомендуемые значения для Proxy/VPN
```bash
MAX_TOTAL_CONNECTIONS = 10000
MAX_SYN_RECV = 300
MAX_RX_MBPS = 80
MAX_CONN_PER_IP = 1500
ALERT_COOLDOWN_SECONDS = 600
```

### Логика срабатывания
Алерт отправляется если выполняется любое условие:
```bash
Connections > MAX_TOTAL_CONNECTIONS
или
SYN_RECV > MAX_SYN_RECV
или
RX > MAX_RX_MBPS
или
Single IP > MAX_CONN_PER_IP
```
# agent.py настройка
Здесь можно добавлять IP и подсети, которые будут игнорироваться ботом
```bash
WHITELIST_IPS = {
    "127.0.0.1",
    "::1"
}

WHITELIST_NETWORKS = [
    "149.154.160.0/20",
    "91.108.4.0/22"
]
```
# Проверка бана
Если необходимо проверить вручную проверку бана
```bash
sudo ipset list proxy_blacklist
sudo ipset test proxy_blacklist IP
sudo iptables -L INPUT -n -v | grep proxy_blacklist
```
