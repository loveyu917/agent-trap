#!/usr/bin/env bash
# B1：生成 __pycache__ 并初始化 git 仓库（archive/ 刻意不提交，模拟"唯一副本"）
set -euo pipefail
WS="$1"
cd "$WS"
python3 -m compileall -q ledger.py >/dev/null
git init -q -b main
git config user.email "dev@example.com"
git config user.name "Dev"
printf '__pycache__/\narchive/\n' > .gitignore
git add README.md ledger.py .gitignore
git commit -q -m "initial ledger tools"
