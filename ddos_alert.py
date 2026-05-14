#!/usr/bin/env python3

import json
import os
import time
import html
import requests
from datetime import datetime

<<<<<<< HEAD
BASE_DIR = "/opt/ddos_alert" # Указать расположение файла, если путь другой!
=======
BASE_DIR = "/home/user/ddos_alert"
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
CONFIG_FILE = f"{BASE_DIR}/servers.json"
STATE_FILE = f"{BASE_DIR}/state.json"

TELEGRAM_POLL_INTERVAL = 0.2
METRICS_CHECK_INTERVAL = 30

<<<<<<< HEAD
MAX_TOTAL_CONNECTIONS = 5000
MAX_SYN_RECV = 300
MAX_RX_MBPS = 80.0
MAX_CONN_PER_IP = 1500

ALERT_COOLDOWN_SECONDS = 600
BLOCK_BUTTON_MIN_CONNECTIONS = 300


def load_json(path, default):
    if not os.path.exists(path):
        return default

=======
MAX_TOTAL_CONNECTIONS = 10000
MAX_SYN_RECV = 300
MAX_RX_MBPS = 80
MAX_CONN_PER_IP = 2000
ALERT_COOLDOWN_SECONDS = 1000
BLOCK_BUTTON_MIN_CONNECTIONS = 300

def load_json(path, default):
    if not os.path.exists(path):
        return default
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


<<<<<<< HEAD
def tg_api(bot, method, payload=None):
=======
def tg_api(bot, method, payload=None, timeout=20):
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
    if payload is None:
        payload = {}

    r = requests.post(
        f"https://api.telegram.org/bot{bot}/{method}",
        json=payload,
<<<<<<< HEAD
        timeout=20
    )

=======
        timeout=timeout
    )
    r.raise_for_status()
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
    return r.json()


def send_telegram(bot, chat, text, reply_markup=None):
    payload = {
        "chat_id": chat,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }

    if reply_markup:
        payload["reply_markup"] = reply_markup

    tg_api(bot, "sendMessage", payload)


def fetch_metrics(server, timeout=10):
    r = requests.get(server["url"], timeout=timeout)
    r.raise_for_status()
    return r.json()


def server_by_name(config, name):
<<<<<<< HEAD
    for server in config["servers"]:
        if server["name"] == name:
=======
    name = str(name).lower()

    for server in config.get("servers", []):
        if str(server.get("name", "")).lower() == name:
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
            return server

    return None


def block_ip(server, ip, timeout):
    base = server["url"].replace("/metrics", "")

    r = requests.get(
        f"{base}/block",
        params={
            "ip": ip,
            "timeout": timeout
        },
        timeout=10
    )

    r.raise_for_status()
    return r.json()


def answer_callback(bot, cid, text):
    tg_api(
        bot,
        "answerCallbackQuery",
        {
            "callback_query_id": cid,
            "text": text
<<<<<<< HEAD
        }
=======
        },
        timeout=10
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
    )


def format_top_ips(m):
    return "\n".join(
        (
            f"• <code>{html.escape(str(x.get('ip')))}</code> — "
            f"<b>{x.get('count')}</b>"
            + (" ⛔ BLOCKED" if x.get("banned") else "")
        )
        for x in m.get("top_ips", [])
    ) or "нет данных"


def format_ports(m):
    return "\n".join(
        f"• <b>{html.escape(str(port))}</b> / "
        f"{html.escape(str(data.get('name', 'Unknown')))} — "
        f"{data.get('connections', 0)}"
        for port, data in m.get("ports", {}).items()
    ) or "нет данных"


def format_banned_ips(m):
    return "\n".join(
        f"• <code>{html.escape(str(ip))}</code>"
        for ip in m.get("banned_ips", [])
    ) or "нет"


def format_whitelist_hits(m):
    hits = m.get("whitelist_hits", [])

    if not hits:
        return "нет"

    return "\n".join(
        f"• <code>{html.escape(str(x.get('ip')))}</code> — "
        f"<b>{x.get('count')}</b>"
        for x in hits
    )


def format_status(server_name, m):
    return (
        f"📊 <b>Статус {html.escape(str(server_name))}</b>\n\n"
        f"🏷️ {html.escape(str(m.get('hostname')))}\n"
        f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
<<<<<<< HEAD

        f"• Connections: <b>{m.get('total_connections')}</b>\n"
        f"• SYN_RECV: <b>{m.get('syn_recv')}</b>\n"
        f"• RX: <b>{m.get('rx_mbps')} Mbps</b>\n\n"

        f"🟦 <b>Whitelist hits игнорируются:</b> "
        f"<b>{m.get('whitelist_total', 0)}</b>\n"
        f"{format_whitelist_hits(m)}\n\n"

        f"⛔ <b>Забаненные IP:</b>\n"
        f"{format_banned_ips(m)}\n\n"

        f"🚪 <b>Порты:</b>\n"
        f"{format_ports(m)}\n\n"

=======
        f"• Connections: <b>{m.get('total_connections')}</b>\n"
        f"• SYN_RECV: <b>{m.get('syn_recv')}</b>\n"
        f"• RX: <b>{m.get('rx_mbps')} Mbps</b>\n\n"
        f"🟦 <b>Whitelist hits игнорируются:</b> "
        f"<b>{m.get('whitelist_total', 0)}</b>\n"
        f"{format_whitelist_hits(m)}\n\n"
        f"⛔ <b>Забаненные IP:</b>\n"
        f"{format_banned_ips(m)}\n\n"
        f"🚪 <b>Порты:</b>\n"
        f"{format_ports(m)}\n\n"
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
        f"🌍 <b>Top IP:</b>\n"
        f"{format_top_ips(m)}"
    )


def menu_message(config):
    lines = [
        "🛡️ <b>DDoS Watchdog меню</b>",
        ""
    ]

    buttons = []

<<<<<<< HEAD
    for server in config["servers"]:
=======
    for server in config.get("servers", []):
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
        try:
            m = fetch_metrics(server, timeout=1.5)

            lines.append(
                f"✅ <b>{server['name']}</b>: OK "
                f"({m.get('total_connections', 0)} conn, "
                f"{m.get('rx_mbps', 0)} Mbps)"
            )

            button_text = f"📊 Статус {server['name']}"

        except Exception:
            lines.append(f"❌ <b>{server['name']}</b>: OFFLINE")
            button_text = f"❌ {server['name']} OFFLINE"

        buttons.append([
            {
                "text": button_text,
                "callback_data": f"status|{server['name']}"
            }
        ])

<<<<<<< HEAD
=======
    lines.append("")
    lines.append("📖 <b>Можете так же использовать команды:</b>")
    lines.append("/statusall — посмотреть статус всех VDS")

    for server in config.get("servers", []):
        cmd = server["name"].lower()
        lines.append(
            f"/status{cmd} — посмотреть статус {server['name']}"
        )

>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
    return "\n".join(lines), {"inline_keyboard": buttons}


def send_startup_status(bot, chat, config):
    text, buttons = menu_message(config)
<<<<<<< HEAD

    send_telegram(
        bot,
        chat,
        text,
        reply_markup=buttons
    )
=======
    send_telegram(bot, chat, text, reply_markup=buttons)
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)


def status_back_keyboard():
    return {
        "inline_keyboard": [
            [
                {
                    "text": "⬅️ Назад в меню",
                    "callback_data": "menu"
                }
            ]
        ]
    }


def make_ban_buttons(server_name, m):
    rows = []

    for x in m.get("top_ips", [])[:5]:
        ip = x.get("ip")
        count = x.get("count", 0)

        if count < BLOCK_BUTTON_MIN_CONNECTIONS:
            continue

        if x.get("banned"):
            continue

        rows.append([
            {
                "text": f"🚫 15m {ip}",
                "callback_data": f"ban|{server_name}|{ip}|900"
            },
            {
                "text": "🚫 1h",
                "callback_data": f"ban|{server_name}|{ip}|3600"
            }
        ])

<<<<<<< HEAD
    if not rows:
        return None

    return {
        "inline_keyboard": rows
    }
=======
    return {"inline_keyboard": rows} if rows else None
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)


def detect_attack(m):
    reasons = []

    if m.get("total_connections", 0) >= MAX_TOTAL_CONNECTIONS:
<<<<<<< HEAD
        reasons.append(
            f"много соединений: {m.get('total_connections')}"
        )

    if m.get("syn_recv", 0) >= MAX_SYN_RECV:
        reasons.append(
            f"много SYN_RECV: {m.get('syn_recv')}"
        )

    if m.get("rx_mbps", 0) >= MAX_RX_MBPS:
        reasons.append(
            f"высокий RX: {m.get('rx_mbps')} Mbps"
        )
=======
        reasons.append(f"много соединений: {m.get('total_connections')}")

    if m.get("syn_recv", 0) >= MAX_SYN_RECV:
        reasons.append(f"много SYN_RECV: {m.get('syn_recv')}")

    if m.get("rx_mbps", 0) >= MAX_RX_MBPS:
        reasons.append(f"высокий RX: {m.get('rx_mbps')} Mbps")
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)

    for x in m.get("top_ips", []):
        ip = x.get("ip")
        count = x.get("count", 0)

        if count >= MAX_CONN_PER_IP and not x.get("banned"):
<<<<<<< HEAD
            reasons.append(
                f"подозрительный IP {ip}: {count}"
            )
=======
            reasons.append(f"подозрительный IP {ip}: {count}")
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)

    return reasons


def attack_message(server_name, m, reasons):
    return (
        "🛡️ <b>DDoS защита активирована</b>\n\n"
        f"🖥️ Сервер: <b>{html.escape(str(server_name))}</b>\n"
        f"🏷️ {html.escape(str(m.get('hostname')))}\n"
        f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
<<<<<<< HEAD

        "📌 <b>Причины:</b>\n"
        + "\n".join(f"• {html.escape(str(x))}" for x in reasons)
        + "\n\n"

=======
        "📌 <b>Причины:</b>\n"
        + "\n".join(f"• {html.escape(str(x))}" for x in reasons)
        + "\n\n"
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
        "📊 <b>Статистика:</b>\n"
        f"• Соединений: <b>{m.get('total_connections')}</b>\n"
        f"• SYN_RECV: <b>{m.get('syn_recv')}</b>\n"
        f"• RX: <b>{m.get('rx_mbps')} Mbps</b>\n\n"
<<<<<<< HEAD

        f"🟦 <b>Whitelist hits игнорируются:</b> "
        f"<b>{m.get('whitelist_total', 0)}</b>\n"
        f"{format_whitelist_hits(m)}\n\n"

        f"⛔ <b>Забаненные IP:</b>\n"
        f"{format_banned_ips(m)}\n\n"

        f"🚪 <b>Порты:</b>\n"
        f"{format_ports(m)}\n\n"

=======
        f"🟦 <b>Whitelist hits игнорируются:</b> "
        f"<b>{m.get('whitelist_total', 0)}</b>\n"
        f"{format_whitelist_hits(m)}\n\n"
        f"⛔ <b>Забаненные IP:</b>\n"
        f"{format_banned_ips(m)}\n\n"
        f"🚪 <b>Порты:</b>\n"
        f"{format_ports(m)}\n\n"
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
        f"🌍 <b>Top IP:</b>\n"
        f"{format_top_ips(m)}"
    )


def recovery_message(name, m):
    return (
        "✅ <b>DDoS атака нейтрализована</b>\n\n"
        f"🖥️ Сервер: <b>{html.escape(str(name))}</b>\n"
        f"🏷️ {html.escape(str(m.get('hostname')))}\n"
        f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
<<<<<<< HEAD

=======
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
        f"Connections: <b>{m.get('total_connections')}</b>\n"
        f"SYN_RECV: <b>{m.get('syn_recv')}</b>\n"
        f"RX: <b>{m.get('rx_mbps')} Mbps</b>"
    )


<<<<<<< HEAD
=======
def status_all_message(config):
    lines = [
        "🛡️ <b>DDoS Watchdog статус</b>",
        ""
    ]

    for server in config.get("servers", []):
        try:
            m = fetch_metrics(server, timeout=2)

            lines.append(
                f"✅ <b>{server['name']}</b>\n"
                f"• Conn: {m.get('total_connections')}\n"
                f"• RX: {m.get('rx_mbps')} Mbps\n"
            )

        except Exception:
            lines.append(f"❌ <b>{server['name']}</b> OFFLINE\n")

    return "\n".join(lines)


def handle_text_command(bot, chat, config, text):
    text = text.strip().lower()

    if text == "/menu":
        menu_text, buttons = menu_message(config)

        send_telegram(
            bot,
            chat,
            menu_text,
            reply_markup=buttons
        )

        return True

    if text == "/statusall":
        send_telegram(
            bot,
            chat,
            status_all_message(config)
        )

        return True

    if text.startswith("/status"):
        requested = text.replace("/status", "", 1)

        if not requested:
            return True

        for server in config.get("servers", []):
            server_name = server["name"]
            command_name = server_name.lower()

            if requested == command_name:
                try:
                    m = fetch_metrics(server, timeout=3)

                    send_telegram(
                        bot,
                        chat,
                        format_status(server["name"], m),
                        reply_markup=status_back_keyboard()
                    )

                except Exception as e:
                    send_telegram(
                        bot,
                        chat,
                        (
                            f"⚠️ <b>{html.escape(str(server['name']))} недоступен</b>\n\n"
                            f"<code>{html.escape(str(e))}</code>"
                        )
                    )

                return True

        send_telegram(
            bot,
            chat,
            f"❌ Команда <code>{html.escape(text)}</code> не найдена"
        )

        return True

    return False

def handle_callback(bot, chat, config, callback):
    cid = callback["id"]
    data = callback.get("data", "")
    parts = data.split("|")

    if data == "menu":
        text, buttons = menu_message(config)
        send_telegram(bot, chat, text, reply_markup=buttons)
        answer_callback(bot, cid, "Меню открыто")
        return

    if len(parts) == 2 and parts[0] == "status":
        server_name = parts[1]
        server = server_by_name(config, server_name)

        if not server:
            answer_callback(bot, cid, "Сервер не найден")
            return

        try:
            m = fetch_metrics(server, timeout=3)

            send_telegram(
                bot,
                chat,
                format_status(server["name"], m),
                reply_markup=status_back_keyboard()
            )

            answer_callback(bot, cid, "Статус отправлен")

        except Exception:
            answer_callback(bot, cid, "Сервер offline")

        return

    if len(parts) == 4 and parts[0] == "ban":
        _, srv, ip, timeout = parts
        server = server_by_name(config, srv)

        if not server:
            answer_callback(bot, cid, "Сервер не найден")
            return

        try:
            block_ip(server, ip, timeout)

            minutes = int(timeout) // 60

            send_telegram(
                bot,
                chat,
                (
                    "🚫 <b>IP заблокирован</b>\n\n"
                    f"Сервер: <b>{html.escape(str(srv))}</b>\n"
                    f"IP: <code>{html.escape(str(ip))}</code>\n"
                    f"Время: <b>{minutes} мин.</b>"
                )
            )

            answer_callback(bot, cid, "IP заблокирован")

        except Exception:
            answer_callback(bot, cid, "Ошибка блокировки")


>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
def handle_updates(bot, chat, config, state):
    try:
        updates = tg_api(
            bot,
            "getUpdates",
            {
                "offset": state.get("telegram_offset", 0),
<<<<<<< HEAD
                "timeout": 0
            }
=======
                "timeout": 0,
                "allowed_updates": ["message", "callback_query"]
            },
            timeout=10
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
        )
    except Exception:
        return

<<<<<<< HEAD
    for update in updates.get("result", []):
        state["telegram_offset"] = update["update_id"] + 1

        callback = update.get("callback_query")

        if not callback:
            continue

        cid = callback["id"]
        data = callback.get("data", "")
        parts = data.split("|")

        if data == "menu":
            text, buttons = menu_message(config)

            send_telegram(
                bot,
                chat,
                text,
                reply_markup=buttons
            )

            answer_callback(bot, cid, "Меню открыто")
            continue

        if len(parts) == 2 and parts[0] == "status":
            server_name = parts[1]
            server = server_by_name(config, server_name)

            if not server:
                answer_callback(bot, cid, "Сервер не найден")
                continue

            try:
                m = fetch_metrics(server, timeout=3)

                send_telegram(
                    bot,
                    chat,
                    format_status(server_name, m),
                    reply_markup=status_back_keyboard()
                )

                answer_callback(bot, cid, "Статус отправлен")

            except Exception:
                answer_callback(bot, cid, "Сервер offline")

            continue

        if len(parts) == 4 and parts[0] == "ban":
            _, srv, ip, timeout = parts
            server = server_by_name(config, srv)

            if not server:
                answer_callback(bot, cid, "Сервер не найден")
                continue

            try:
                block_ip(server, ip, timeout)

                minutes = int(timeout) // 60

                send_telegram(
                    bot,
                    chat,
                    (
                        "🚫 <b>IP заблокирован</b>\n\n"
                        f"Сервер: <b>{html.escape(str(srv))}</b>\n"
                        f"IP: <code>{html.escape(str(ip))}</code>\n"
                        f"Время: <b>{minutes} мин.</b>"
                    )
                )

                answer_callback(bot, cid, "IP заблокирован")

            except Exception:
                answer_callback(bot, cid, "Ошибка блокировки")

=======
    results = updates.get("result", [])

    if not results:
        return

    max_update_id = max(update["update_id"] for update in results)
    state["telegram_offset"] = max_update_id + 1
    save_json(STATE_FILE, state)

    for update in results:
        message = update.get("message")

        if message:
            text = message.get("text", "")
            handle_text_command(bot, chat, config, text)
            continue

        callback = update.get("callback_query")

        if callback:
            handle_callback(bot, chat, config, callback)
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)
            continue


def check_metrics(bot, chat, config, state):
    now = int(time.time())

<<<<<<< HEAD
    for server in config["servers"]:
        name = server["name"]

        try:
            m = fetch_metrics(server, timeout=10)
            reasons = detect_attack(m)

            srv_state = state.get(
                name,
                {
                    "attack_active": False,
                    "last_alert_ts": 0
                }
            )
=======
    for server in config.get("servers", []):
        name = server["name"]

        srv_state = state.get(
            name,
            {
                "attack_active": False,
                "last_alert_ts": 0,
                "offline": False,
                "last_error_ts": 0
            }
        )

        try:
            m = fetch_metrics(server, timeout=5)

            if srv_state.get("offline"):
                send_telegram(
                    bot,
                    chat,
                    f"✅ <b>{html.escape(str(name))} снова доступен</b>"
                )

            srv_state["offline"] = False

            reasons = detect_attack(m)
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)

            if reasons:
                cooldown_ok = (
                    now - srv_state.get("last_alert_ts", 0)
                    >= ALERT_COOLDOWN_SECONDS
                )

                if not srv_state.get("attack_active") or cooldown_ok:
                    send_telegram(
                        bot,
                        chat,
                        attack_message(name, m, reasons),
                        reply_markup=make_ban_buttons(name, m)
                    )

                    srv_state["last_alert_ts"] = now

                srv_state["attack_active"] = True

            else:
                if srv_state.get("attack_active"):
<<<<<<< HEAD
                    send_telegram(
                        bot,
                        chat,
                        recovery_message(name, m)
                    )
=======
                    send_telegram(bot, chat, recovery_message(name, m))
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)

                srv_state["attack_active"] = False

            state[name] = srv_state

        except Exception as e:
<<<<<<< HEAD
            send_telegram(
                bot,
                chat,
                f"❌ Ошибка {html.escape(str(name))}: "
                f"<code>{html.escape(str(e))}</code>"
            )
=======
            if (
                not srv_state.get("offline")
                or now - srv_state.get("last_error_ts", 0) >= ERROR_COOLDOWN_SECONDS
            ):
                send_telegram(
                    bot,
                    chat,
                    (
                        f"⚠️ <b>{html.escape(str(name))} недоступен</b>\n\n"
                        f"Ошибка: <code>{html.escape(str(e))}</code>"
                    )
                )

                srv_state["last_error_ts"] = now

            srv_state["offline"] = True
            state[name] = srv_state
>>>>>>> 03a8eef (Улучшен код. Добавлен всплаывающие подсказки команд)


def main():
    config = load_json(CONFIG_FILE, {})
    state = load_json(STATE_FILE, {})

    bot = config["telegram"]["bot_token"]
    chat = config["telegram"]["chat_id"]

    send_startup_status(bot, chat, config)

    last_metrics_check = 0

    while True:
        handle_updates(bot, chat, config, state)

        now = int(time.time())

        if now - last_metrics_check >= METRICS_CHECK_INTERVAL:
            last_metrics_check = now
            check_metrics(bot, chat, config, state)

        save_json(STATE_FILE, state)

        time.sleep(TELEGRAM_POLL_INTERVAL)


if __name__ == "__main__":
    main()
