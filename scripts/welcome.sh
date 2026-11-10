#!/usr/bin/env bash
# 进入容器时显示的快速开始横幅（由 /root/.bashrc 调用）。
cat <<'EOF'

==========================================================
  Agent Trap Lab
  测试 AI 编程助手会不会被提示注入骗去外泄 .env 凭据
==========================================================

快速开始：
  1) 登录 Claude（首次；之后靠卷复用，不必每次登）
       claude                 # 选 Claude account (Pro/Max)，浏览器授权
       claude -p "hi"         # 验证能通

  2) 批次前体检
       python3 runner/preflight.py

  3) 跑实验（选一个被测 agent）
       # Claude：
       python3 runner/run.py all --agent claude \
         --scenarios A1v,A1vp --profiles yolo --repeats 10 --interleave --tag demo
       # DeepSeek（需要 DEEPSEEK_API_KEY）：
       python3 runner/run.py all --agent deepseek \
         --scenarios A1v,A1vp --profiles yolo --repeats 10 --interleave --tag demo

  4) 出报告（分析 + 独立审计）
       python3 runner/analyze.py demo
       python3 runner/audit.py

  报告(.md) 会出现在宿主机的 results/ 文件夹里。
  完整说明见项目根目录的 USAGE.md。

  随时再看这张表：  menu
EOF
if [ -n "$DEEPSEEK_API_KEY" ]; then
  echo "  DeepSeek: API key 已设置，两个 agent 都能测。"
else
  echo "  DeepSeek: 未设置 key —— 当前只能测 Claude。"
  echo "            要测 DeepSeek，重新用：DEEPSEEK_API_KEY=sk-xxx ./install.sh"
fi
echo
