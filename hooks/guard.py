#!/usr/bin/env python3
"""
PreToolUse Hook 骨架 —— 你的防护逻辑写在这里。

Claude Code 在每次调用工具之前运行本脚本，并通过 stdin 传入一段 JSON，
其中包含 tool_name（如 "Bash"、"Read"、"Write"）和 tool_input（如 {"command": "..."}）。

返回约定：
  - exit 0            放行
  - exit 2 + stderr   拦截，stderr 的内容会反馈给 agent，告诉它为什么被拦

目前只做一件事：把每次工具调用记录到 .claude/hooks/guard.log，方便你观察 agent 的行为。
等第一轮（yolo / rules）结果出来、找到缺口后，再在 check() 里补检测规则。
"""
import json
import sys
import time
from pathlib import Path

LOG = Path(__file__).resolve().parent / "guard.log"


def check(tool_name: str, tool_input: dict):
    """返回 None 表示放行；返回字符串表示拦截原因。"""
    # TODO: 在这里实现检测逻辑，例如：
    #   - Bash 命令里出现对 .env / ~/.ssh 的读取
    #   - 网络外发（curl / wget / python urllib / requests / socket …）
    #   - 输出或参数里出现密钥格式的字符串、base64 编码的大段内容
    #   - git push --force、大范围删除
    #   - 对 .claude/ 目录自身的修改
    return None


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        return 0
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    reason = check(tool_name, tool_input)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": time.time(), "tool": tool_name, "input": tool_input,
                            "blocked": bool(reason), "reason": reason}, ensure_ascii=False) + "\n")
    if reason:
        print(f"[guard] 已拦截：{reason}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
