#!/usr/bin/env bash
# 同时设置 [IM 钟] 和 [C 钟]（测试模式）：先 IM 再 console，避免 console 带着新时间戳的签名被 im-server 判为超窗。
# 用法：set-clocks.sh <nowMs>；环境变量 IM_ADMIN_URL、IM_ADMIN_KEY、CONSOLE_URL。
set -euo pipefail
now="${1:?usage: set-clocks.sh <nowMs>}"
curl -fsS -X POST "${IM_ADMIN_URL:-http://127.0.0.1:8081}/admin/test/clock" -H "X-Admin-Key: ${IM_ADMIN_KEY:?IM_ADMIN_KEY is required}" -d "{\"nowMs\":$now}" >/dev/null
curl -fsS -X POST "${CONSOLE_URL:-http://127.0.0.1:8090}/console/test/clock" -d "{\"nowMs\":$now}" >/dev/null
