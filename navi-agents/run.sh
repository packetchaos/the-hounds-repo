#!/usr/bin/env bash
cd "$(dirname "$0")"
exec "$(command -v python3 || command -v python)" run.py "$@"
