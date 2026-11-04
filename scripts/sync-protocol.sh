#!/usr/bin/env bash
# 把 tianting-server 的协议文件同步过来（错误码和签名向量的唯一真相源在那边）。默认源 ../im-mvp。
set -euo pipefail
cd "$(dirname "$0")/.."
src="${1:-../im-mvp}"
for f in errors.json vectors/admin-sign.json vectors/ops-sign.json; do
  mkdir -p "protocol/$(dirname "$f")"
  cp "$src/protocol/$f" "protocol/$f"
done
git -C "$src" rev-parse HEAD > protocol/SOURCE
echo "已同步到 tianting-server@$(cut -c1-7 protocol/SOURCE)"
