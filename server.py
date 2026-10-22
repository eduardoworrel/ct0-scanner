import http.server, socketserver, urllib.request, urllib.parse, sys
PORT=int(__import__("os").environ.get("PORT","8008"))
class H(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/proxy?"):
            q=urllib.parse.parse_qs(self.path.split("?",1)[1])
            url=(q.get("url") or [""])[0]
            if not url.startswith(("http://","https://")):
                self.send_error(400,"bad url"); return
            try:
                req=urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0 CT0Scanner"})
                with urllib.request.urlopen(req, timeout=20) as r:
                    body=r.read()
                    ctype=r.headers.get("Content-Type","text/html")
                # injeta <base> (resolve recursos relativos no destino real) + repassa o CSP real como meta (check fiel)
                if "text/html" in ctype:
                    import re
                    inject=f'<base href="{url}">'.encode()
                    realcsp=r.headers.get("Content-Security-Policy")
                    if realcsp:
                        inject+=f'<meta http-equiv="Content-Security-Policy" content="{realcsp}">'.encode()
                    if b"<head" in body: body=re.sub(rb"(<head[^>]*>)", rb"\1"+inject, body, count=1)
                    else: body=inject+body
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
            except Exception as e:
                self.send_error(502, f"proxy: {e}")
            return
        return super().do_GET()
socketserver.ThreadingTCPServer.allow_reuse_address=True
with socketserver.ThreadingTCPServer(("0.0.0.0",PORT), H) as httpd:
    print("serving :%d (+ /proxy)"%PORT); httpd.serve_forever()
