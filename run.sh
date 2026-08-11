#!/usr/bin/env bash
# Securify Local 起動スクリプト
cd "$(dirname "$0")"
exec python3 run.py "$@"
