"""Minimal MCP server for testing — runs over stdio.

Speaks the JSON-RPC wire protocol directly (see `_mcp_fixture`) so the same
fixture works against any `mcp` SDK major. MCP's stdio transport is
newline-delimited JSON in both directions.
"""

import json
import sys

from _mcp_fixture import handle


def _write(message: dict) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def _roots_tool_response(request_id, roots: list[dict]) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": json.dumps(roots)}],
            "isError": False,
        },
    }


def main() -> None:
    roots_request_id = "test-server-roots"
    roots: list[dict] | None = []
    pending_roots_tool_id = None

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue

        if message.get("id") == roots_request_id and "result" in message:
            roots = (message.get("result") or {}).get("roots", [])
            if pending_roots_tool_id is not None:
                _write(_roots_tool_response(pending_roots_tool_id, roots))
                pending_roots_tool_id = None
            continue

        method = message.get("method")
        if method == "initialize":
            capabilities = (message.get("params") or {}).get("capabilities") or {}
            roots = None if "roots" in capabilities else []

        if method == "notifications/initialized" and roots is None:
            _write(
                {
                    "jsonrpc": "2.0",
                    "id": roots_request_id,
                    "method": "roots/list",
                    "params": {},
                }
            )
            continue

        params = message.get("params") or {}
        if method == "tools/call" and params.get("name") == "client_roots":
            if roots is None:
                pending_roots_tool_id = message["id"]
            else:
                _write(_roots_tool_response(message["id"], roots))
            continue

        response = handle(message)
        if response is not None:
            _write(response)


if __name__ == "__main__":
    main()
