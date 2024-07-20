#!/usr/bin/env bash
set -eo pipefail

sleep 1000

exec python3 tools/ip_autoblock_job.py
