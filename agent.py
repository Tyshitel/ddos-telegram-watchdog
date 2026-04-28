#!/usr/bin/env python3
                "banned":ip_is_banned(ip)
            }
            for ip,cnt in c.most_common(10)
        ],
        "whitelist_total":len(whitelist),
        "whitelist_hits":[
            {"ip":ip,"count":cnt}
            for ip,cnt in wc.most_common(10)
        ],
        "banned_ips":list_banned_ips(),
        "ports":{
            p:{
                "name":PORT_NAMES.get(int(p),"Unknown"),
                "connections":cnt
            }
            for p,cnt in ports.items()
        },
        "timestamp":int(time.time())
    }


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path=="/metrics":
            body=json.dumps(
                build_metrics(),
                ensure_ascii=False
            ).encode()

            self.send_response(200)
            self.send_header(
                'Content-Type',
                'application/json'
            )
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith('/block'):
            q=urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query
            )
            ip=q.get('ip',[''])[0]
            timeout=q.get('timeout',['900'])[0]
            ok,msg=block_ip(ip,timeout)

            body=json.dumps({
                "ok":ok,
                "message":msg
            }).encode()

            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self,*args):
        return


def main():
    HTTPServer((HOST,PORT),Handler).serve_forever()


if __name__=='__main__':
    main()
