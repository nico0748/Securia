#!/usr/bin/env bash
# Securia Local 起動スクリプト
cd "$(dirname "$0")"
exec python3 run.py "$@"
