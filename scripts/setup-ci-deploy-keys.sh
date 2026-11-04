#!/usr/bin/env bash
# 配置 console-server 和 tianting-server 互相读取的两把只读部署密钥（由仓库所有者本人运行）：
#   tianting-console-server 的 CI 检出 tianting-server（运维和业务接口的端到端测试）；
#   tianting-server 的 testenv 工作流检出 tianting-console-server（测试环境联调）。
# 私钥只经过管道，不打印、不留在磁盘上。
set -euo pipefail
owner=leetonny001
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
pair() { # 被读取的仓库 使用方仓库 secret名
  ssh-keygen -q -t ed25519 -N '' -C "$2-ci-$1" -f "$dir/$1"
  gh repo deploy-key add "$dir/$1.pub" -R "$owner/$1" -t "$2-ci"
  gh secret set "$3" -R "$owner/$2" <"$dir/$1"
}
pair tianting-server tianting-console-server TIANTING_SERVER_DEPLOY_KEY
pair tianting-console-server tianting-server TIANTING_CONSOLE_DEPLOY_KEY
echo "完成：两把只读部署密钥和两个 secret 已配置；本地密钥文件已删除。"
