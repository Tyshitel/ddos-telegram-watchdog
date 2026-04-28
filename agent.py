#!/usr/bin/env python3

import json
import time
import socket
import subprocess
import urllib.parse
import ipaddress
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "0.0.0.0"
PORT = 9000

NET_IFACE = "сетефой интерфейс"

WATCH_PORTS = [
    Указанть порт,
    Указать порт,
    
]

PORT_NAMES = {
    Порт: "Имя",
    Порт: "Имя",
    
}

WHITELIST_IPS = {
    "127.0.0.1",
    "::1"    
}

WHITELIST_NETWORKS = [
    "подсеть",
    "подсеть"
]

IPSET_NAME = "proxy_blacklist"
RX_STATE_FILE = "/tmp/ddos-agent-rx-state.json"


def run_cmd(cmd):
    try:
        return subprocess.check_output(
            cmd,
            shell=True,
            text=True,
            stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return ""


def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def is_whitelisted(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False

    if ip in WHITELIST_IPS:
        return True

    for net in WHITELIST_NETWORKS:
        try:
            if ip_obj in ipaddress.ip_network(net):
                return True
        except Exception:
            pass

    return False


def ip_is_banned(ip):
    try:
        r = subprocess.run(
            ["ipset", "test", IPSET_NAME, ip],
            capture_output=True,
            text=True
        )
        return r.returncode == 0
    except Exception:
        return False


def list_banned_ips():
    out = run_cmd(f"ipset list {IPSET_NAME}")

    banned = []
    in_members = False

    for line in out.splitlines():
        line = line.strip()

        if line == "Members:":
            in_members = True
            continue

        if in_members and line:
            ip = line.split()[0]
            banned.append(ip)

    return banned


def block_ip(ip, timeout):
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return False, "invalid ip"

    if is_whitelisted(ip):
        return False, "ip is whitelisted"

    run_cmd(f"ipset create {IPSET_NAME} hash:ip timeout 0 -exist")

    run_cmd(
        f"iptables -C INPUT -m set --match-set {IPSET_NAME} src -j DROP "
        f"|| iptables -I INPUT -m set --match-set {IPSET_NAME} src -j DROP"
    )

    timeout = int(timeout)

    if timeout <= 0:
        run_cmd(f"ipset add {IPSET_NAME} {ip} -exist")
    else:
        run_cmd(f"ipset add {IPSET_NAME} {ip} timeout {timeout} -exist")

    return True, "blocked"


def read_rx_bytes():
    try:
        with open("/proc/net/dev", "r") as f:
            for line in f:
                if line.strip().startswith(NET_IFACE + ":"):
                    return int(line.split(":")[1].split()[0])
    except Exception:
        pass

    return 0


def read_rx_mbps():
    now = time.time()
    current = read_rx_bytes()

    try:
        with open(RX_STATE_FILE, "r") as f:
            old = json.load(f)

        old_time = old.get("time", now)
        old_bytes = old.get("bytes", current)

        delta_time = max(now - old_time, 0.001)
        delta_bytes = max(current - old_bytes, 0)

        mbps = round((delta_bytes * 8) / 1024 / 1024 / delta_time, 2)

    except Exception:
        mbps = 0.0

    try:
        with open(RX_STATE_FILE, "w") as f:
            json.dump(
                {
                    "time": now,
                    "bytes": current
                },
                f
            )
    except Exception:
        pass

    return mbps


def parse_connections():
    out = run_cmd("ss -nt")

    ips = []
    whitelist_ips = []

    ports = defaultdict(int)
    whitelist_ports = defaultdict(int)

    syn_recv = 0

    for line in out.splitlines()[1:]:
        parts = line.split()

        if len(parts) < 5:
            continue

        state = parts[0]
        local = parts[3]
        peer = parts[4]

        if state == "SYN-RECV":
            syn_recv += 1

        try:
            local_port = int(local.rsplit(":", 1)[1])

            peer_ip = peer.rsplit(":", 1)[0]
            peer_ip = peer_ip.replace("[", "").replace("]", "")
            peer_ip = peer_ip.replace("::ffff:", "")

        except Exception:
            continue

        if WATCH_PORTS and local_port not in WATCH_PORTS:
            continue

        if not valid_ip(peer_ip):
            continue

        if is_whitelisted(peer_ip):
            whitelist_ips.append(peer_ip)
            whitelist_ports[str(local_port)] += 1
            continue

        ips.append(peer_ip)
        ports[str(local_port)] += 1

    return ips, ports, whitelist_ips, whitelist_ports, syn_recv


def build_metrics():
    ips, ports, whitelist_ips, whitelist_ports, syn_recv = parse_connections()

    counter = Counter(ips)
    whitelist_counter = Counter(whitelist_ips)

    return {
        "hostname": socket.gethostname(),
        "total_connections": len(ips),
        "syn_recv": syn_recv,
        "rx_mbps": read_rx_mbps(),

        "top_ips": [
            {
                "ip": ip,
                "count": count,
                "banned": ip_is_banned(ip)
            }
            for ip, count in counter.most_common(10)
        ],

        "whitelist_total": len(whitelist_ips),

        "whitelist_hits": [
            {
                "ip": ip,
                "count": count
            }
            for ip, count in whitelist_counter.most_common(10)
        ],

        "banned_ips": list_banned_ips(),

        "ports": {
            port: {
                "name": PORT_NAMES.get(int(port), "Unknown"),
                "connections": count
            }
            for port, count in ports.items()
        },

        "whitelist_ports": {
            port: {
                "name": PORT_NAMES.get(int(port), "Unknown"),
                "connections": count
            }
            for port, count in whitelist_ports.items()
        },

        "timestamp": int(time.time())
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            body = json.dumps(
                build_metrics(),
                ensure_ascii=False
            ).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/block"):
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)

            ip = qs.get("ip", [""])[0]
            timeout = qs.get("timeout", ["900"])[0]

            ok, msg = block_ip(ip, timeout)

            body = json.dumps(
                {
                    "ok": ok,
                    "message": msg,
                    "ip": ip,
                    "timeout": timeout,
                    "banned_ips": list_banned_ips()
                },
                ensure_ascii=False
            ).encode("utf-8")

            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        return


def main():
    server = HTTPServer((HOST, PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
