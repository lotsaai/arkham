#!/usr/bin/env python3
"""Tutorial upstream: records the Authorization header it receives to SEEN_PATH
and echoes it in the body. Binds UPSTREAM_HOST (default 127.0.0.1). Serves TLS
when CERT and KEY are set."""
import os
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

seen_path = os.environ["SEEN_PATH"]
port = int(os.environ["UPSTREAM_PORT"])


class Handler(BaseHTTPRequestHandler):
  def do_GET(self):
    seen = self.headers.get("Authorization", "<none>")
    with open(seen_path, "w", encoding="utf-8") as f:
      f.write(seen)
    body = ("upstream saw: " + seen).encode()
    self.send_response(200)
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)

  def log_message(self, *_args):
    pass


server = HTTPServer((os.environ.get("UPSTREAM_HOST", "127.0.0.1"), port), Handler)
if os.environ.get("CERT"):
  ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  ctx.load_cert_chain(os.environ["CERT"], os.environ["KEY"])
  server.socket = ctx.wrap_socket(server.socket, server_side=True)
print("upstream ready", flush=True)
server.serve_forever()
