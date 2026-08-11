"""MCP のプロトコル層（JSON-RPC / stdio / ライフサイクル）。"""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from securia.config import Config, ScanConfig
from securia.mcp.protocol import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    JsonRpcError,
    StdioTransport,
    make_error,
    make_response,
    parse_message,
)
from securia.mcp.server import LATEST_PROTOCOL_VERSION, McpServer
from securia.store import Store

INIT = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": LATEST_PROTOCOL_VERSION, "capabilities": {},
               "clientInfo": {"name": "test", "version": "1"}},
}


@pytest.fixture
def server(tmp_path: Path) -> McpServer:
    cfg = Config()
    cfg.scan = ScanConfig(allowed_roots=[str(tmp_path)])
    cfg.osv.enabled = False
    store = Store(tmp_path / "mcp.db")
    srv = McpServer(cfg, store)
    yield srv
    store.close()


@pytest.fixture
def ready(server: McpServer) -> McpServer:
    server.handle(INIT)
    server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return server


# ---------------- メッセージの解析 ----------------
def test_parse_valid_request() -> None:
    msg = parse_message({"jsonrpc": "2.0", "id": 7, "method": "ping", "params": {"a": 1}})
    assert (msg.id, msg.method, msg.params) == (7, "ping", {"a": 1})
    assert msg.is_notification is False


def test_parse_notification_has_no_id() -> None:
    assert parse_message({"jsonrpc": "2.0", "method": "notifications/initialized"}).is_notification


def test_parse_defaults_missing_params() -> None:
    assert parse_message({"jsonrpc": "2.0", "id": 1, "method": "ping"}).params == {}


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ("not an object", INVALID_REQUEST),
        ({"id": 1, "method": "ping"}, INVALID_REQUEST),                     # jsonrpc 欠落
        ({"jsonrpc": "1.0", "id": 1, "method": "ping"}, INVALID_REQUEST),   # 版違い
        ({"jsonrpc": "2.0", "id": 1}, INVALID_REQUEST),                     # method 欠落
        ({"jsonrpc": "2.0", "id": 1, "method": ""}, INVALID_REQUEST),
        ({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": [1, 2]}, INVALID_PARAMS),
    ],
)
def test_parse_rejects_malformed(payload, code: int) -> None:
    with pytest.raises(JsonRpcError) as exc:
        parse_message(payload)
    assert exc.value.code == code


def test_response_and_error_shape() -> None:
    assert make_response(3, {"ok": True}) == {"jsonrpc": "2.0", "id": 3, "result": {"ok": True}}
    err = make_error(3, -32601, "nope", {"detail": "x"})
    assert err["error"] == {"code": -32601, "message": "nope", "data": {"detail": "x"}}
    assert "data" not in make_error(3, -32601, "nope")["error"]


# ---------------- stdio トランスポート ----------------
def test_transport_reads_line_delimited_json() -> None:
    reader = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"ping"}\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n')
    transport = StdioTransport(reader, io.StringIO())
    assert transport.read()["id"] == 1
    assert transport.read()["id"] == 2
    assert transport.read() is None       # EOF


def test_transport_skips_blank_lines() -> None:
    transport = StdioTransport(io.StringIO('\n\n{"jsonrpc":"2.0","id":1,"method":"ping"}\n'), io.StringIO())
    assert transport.read()["id"] == 1


def test_transport_writes_single_line() -> None:
    writer = io.StringIO()
    StdioTransport(io.StringIO(), writer).write({"jsonrpc": "2.0", "id": 1, "result": {"text": "a\nb"}})
    out = writer.getvalue()
    assert out.endswith("\n")
    assert out.count("\n") == 1           # 埋め込み改行はエスケープされる
    assert json.loads(out)["result"]["text"] == "a\nb"


def test_transport_write_is_not_ascii_escaped() -> None:
    writer = io.StringIO()
    StdioTransport(io.StringIO(), writer).write({"jsonrpc": "2.0", "id": 1, "result": {"t": "日本語"}})
    assert "日本語" in writer.getvalue()


# ---------------- ライフサイクル ----------------
def test_initialize_response(server: McpServer) -> None:
    result = server.handle(INIT)["result"]
    assert result["protocolVersion"] == LATEST_PROTOCOL_VERSION
    assert result["serverInfo"]["name"] == "securia"
    assert result["capabilities"]["tools"] == {"listChanged": False}
    assert "resources" in result["capabilities"]
    assert "securia_scan" in result["instructions"]


def test_initialize_echoes_known_older_version(server: McpServer) -> None:
    payload = {**INIT, "params": {**INIT["params"], "protocolVersion": "2024-11-05"}}
    assert server.handle(payload)["result"]["protocolVersion"] == "2024-11-05"


def test_initialize_falls_back_for_unknown_version(server: McpServer) -> None:
    payload = {**INIT, "params": {**INIT["params"], "protocolVersion": "1999-01-01"}}
    assert server.handle(payload)["result"]["protocolVersion"] == LATEST_PROTOCOL_VERSION


def test_requests_before_initialize_are_rejected(server: McpServer) -> None:
    error = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["error"]
    assert error["code"] == INVALID_REQUEST


def test_ping_works_before_initialize(server: McpServer) -> None:
    assert server.handle({"jsonrpc": "2.0", "id": 2, "method": "ping"})["result"] == {}


def test_notifications_get_no_response(ready: McpServer) -> None:
    assert ready.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert ready.handle({"jsonrpc": "2.0", "method": "notifications/cancelled",
                         "params": {"requestId": 1}}) is None
    assert ready.handle({"jsonrpc": "2.0", "method": "notifications/unknown"}) is None


def test_unknown_method(ready: McpServer) -> None:
    assert ready.handle({"jsonrpc": "2.0", "id": 9, "method": "does/not/exist"})["error"]["code"] \
        == METHOD_NOT_FOUND


def test_malformed_message_keeps_request_id(server: McpServer) -> None:
    response = server.handle({"id": 42, "method": "ping"})
    assert response["id"] == 42
    assert response["error"]["code"] == INVALID_REQUEST


def test_prompts_list_is_empty(ready: McpServer) -> None:
    assert ready.handle({"jsonrpc": "2.0", "id": 3, "method": "prompts/list"})["result"] == {"prompts": []}


# ---------------- ループ全体 ----------------
def test_serve_loop_handles_stream(server: McpServer) -> None:
    lines = "\n".join(json.dumps(m) for m in [
        INIT,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]) + "\n"
    writer = io.StringIO()
    server.serve(StdioTransport(io.StringIO(lines), writer))

    responses = [json.loads(line) for line in writer.getvalue().splitlines()]
    assert [r["id"] for r in responses] == [1, 2]     # 通知には応答しない
    assert responses[1]["result"]["tools"]


def test_serve_loop_reports_parse_error_and_continues(server: McpServer) -> None:
    lines = "{ this is not json\n" + json.dumps(INIT) + "\n"
    writer = io.StringIO()
    server.serve(StdioTransport(io.StringIO(lines), writer))

    responses = [json.loads(line) for line in writer.getvalue().splitlines()]
    assert responses[0]["error"]["code"] == PARSE_ERROR
    assert responses[0]["id"] is None
    assert responses[1]["result"]["serverInfo"]["name"] == "securia"


def test_serve_loop_stops_at_eof(server: McpServer) -> None:
    writer = io.StringIO()
    server.serve(StdioTransport(io.StringIO(""), writer))
    assert writer.getvalue() == ""
