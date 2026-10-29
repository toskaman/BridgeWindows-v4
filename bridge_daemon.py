#!/usr/bin/env python3
"""
BridgeWindows Background Daemon
Maintains persistent reverse TCP connection with PC2 agent on port 9876,
and provides a fast local REST API on 127.0.0.1:9877 for CLI queries and subagents.
"""

import sys
import os
import json
import time
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# Import BridgeWindows engine
import bridge_mcp

HOST = "0.0.0.0"
AGENT_PORT = 9876
TOKEN = os.environ.get("OPENBRIDGE_PSK")
DAEMON_PORT = 9877
BRIDGE_VERSION = "4.0.0"
MAX_TOOL_BODY = 1024 * 1024  # 1 MB cap on /tool requests (memory-DoS guard)

class DaemonHandler(BaseHTTPRequestHandler):
    # Enable HTTP/1.1 persistent connections (Keep-Alive)
    protocol_version = "HTTP/1.1"
    timeout = 60  # Close idle persistent sockets after 60s of inactivity

    def log_message(self, format, *args):
        # Suppress noisy HTTP access logs
        pass

    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {
                "status": "ok",
                "connected": bridge_mcp.bridge.is_connected,
                "agents": bridge_mcp.bridge.list_agents(),
                "version": BRIDGE_VERSION
            })
        elif self.path == "/status":
            res = bridge_mcp.handle_tool_call("remote_status", {})
            self._send_json(200, {"result": res, "connected": bridge_mcp.bridge.is_connected})
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        if self.path == "/tool":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                self._send_json(400, {"success": False, "error": "Bad Content-Length"})
                return
            if content_length < 0 or content_length > MAX_TOOL_BODY:
                self._send_json(413, {"success": False, "error": f"Body over {MAX_TOOL_BODY} bytes"})
                return
            post_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
            try:
                payload = json.loads(post_data)
                if not isinstance(payload, dict):
                    raise ValueError("tool payload must be an object")
                tool_name = payload.get("tool", "")
                tool_args = payload.get("args", {})
                if not isinstance(tool_args, dict):
                    raise ValueError("tool args must be an object")
                agent_id = payload.get("agent")
                res = bridge_mcp.handle_tool_call(tool_name, tool_args, agent_id=agent_id)
                self._send_json(200, {"success": True, "result": res})
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})
        else:
            self._send_json(404, {"error": "Not Found"})

def main():
    if not TOKEN:
        print("OPENBRIDGE_PSK is not set. Refusing to listen unauthenticated.", file=sys.stderr)
        sys.exit(2)
    print(f"Starting BridgeWindows Agent listener on {HOST}:{AGENT_PORT}...")
    bridge_mcp.bridge.host = HOST
    bridge_mcp.bridge.port = AGENT_PORT
    bridge_mcp.bridge.token = TOKEN
    bridge_mcp.bridge.start_server()

    server = ThreadingHTTPServer(("127.0.0.1", DAEMON_PORT), DaemonHandler)
    server.daemon_threads = True
    print(f"BridgeDaemon HTTP/1.1 API listening on http://127.0.0.1:{DAEMON_PORT}")
    print("Keep-Alive connection pooling enabled. Ready for high-throughput RPC.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        bridge_mcp.bridge.running = False
        server.server_close()

if __name__ == "__main__":
    main()
