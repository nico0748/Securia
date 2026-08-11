"""MCP (Model Context Protocol) サーバー。

Claude などの MCP クライアントから Securia の脆弱性スキャンを実行できるようにする。
プロトコルは公式 SDK を使わず標準ライブラリだけで実装している。実行時依存ゼロを
崩さないため。
"""
from __future__ import annotations

from .server import LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, McpServer, serve_stdio

__all__ = [
    "LATEST_PROTOCOL_VERSION",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "McpServer",
    "serve_stdio",
]
