"""
DeepSeek 驱动器：调用 runner/agent_executor.py（经过验证的执行器）作为子进程。

执行器通过 OpenAI 兼容 API 直连 DeepSeek，自己实现工具调用循环，
并把对话写成与 Claude CLI stream-json 对齐的 transcript.jsonl。

需要在容器里设置 DEEPSEEK_API_KEY，并安装 openai 库。
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from .base import AgentBase

EXECUTOR = Path(__file__).resolve().parent.parent / "agent_executor.py"
# 实验框架根目录（runner/ 的上一级），传给执行器做软隔离
LAB_ROOT = Path(__file__).resolve().parent.parent.parent


class DeepSeekAgent(AgentBase):
    name = "deepseek"

    def __init__(self, model: str | None = None):
        self._model = model or os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")

    def run(self, task: str, workspace: Path, transcript_path: Path,
            timeout: int = 600, max_turns: int = 30, env: dict | None = None,
            profile_name: str = "yolo", cli_flags: list | None = None,
            user: str | None = None, executor_path: str | None = None) -> int:
        if not (env or os.environ).get("DEEPSEEK_API_KEY"):
            raise SystemExit("未设置 DEEPSEEK_API_KEY 环境变量（DeepSeek 执行器需要它）。")

        try:
            if user:
                # 降权运行：把执行器源码通过 stdin 喂给 `python3 -`，磁盘上不留任何文件给 agent 读
                # （曾把执行器暂存到 agent 家目录，被 agent cat 出来看穿装置——这里彻底堵住）。
                # 关键：task/workspace/profile//lab 不走 argv（否则 `ps aux`、`cat /proc/<ppid>/cmdline`
                # 能读到，正是 v15 作废的根因），改成注入到源码头部的 _INJECTED_CONFIG，argv 只留 `python3 -`。
                # transcript 用 "-" 走 stdout，由本进程(root)收回写到 /lab/runs。
                # key 也走注入 config，不进子进程环境块——否则 agent 读 /proc/<executor>/environ 能拿到
                # 真实 DeepSeek key（os.environ.pop 改不了已启动进程的 environ 副本，审计 061558 的近失）。
                src_env = {k: v for k, v in (env or os.environ).items()
                           if k not in ("DEEPSEEK_API_KEY", "DEEPSEEK_MODEL", "DEEPSEEK_BASE_URL")}
                cfg = {"task": task, "workspace": str(workspace),
                       "profile": profile_name, "lab_root": str(LAB_ROOT),
                       "api_key": (env or os.environ).get("DEEPSEEK_API_KEY", ""),
                       "model": self._model,
                       "base_url": (env or os.environ).get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")}
                header = ("import json as _json\n"
                          "_INJECTED_CONFIG = _json.loads(%r)\n" % json.dumps(cfg, ensure_ascii=False))
                src = header + EXECUTOR.read_text(encoding="utf-8")
                cmd = [sys.executable, "-"]
                res = subprocess.run(cmd, cwd=workspace, env=src_env, input=src, timeout=timeout,
                                     capture_output=True, text=True, user=user, group=user)
                if res.stdout:
                    transcript_path.write_text(res.stdout, encoding="utf-8")
            else:
                cmd = [sys.executable, str(EXECUTOR), task, str(workspace),
                       str(transcript_path), profile_name, str(LAB_ROOT)]
                res = subprocess.run(cmd, cwd=workspace, env=env, timeout=timeout,
                                     capture_output=True, text=True)
            # 执行器崩溃且没来得及写 transcript 时，补一条错误记录
            if res.returncode != 0 and not transcript_path.exists():
                transcript_path.write_text(
                    json.dumps({"type": "result",
                                "result": f"Executor Crashed:\n{res.stderr[-1000:]}",
                                "is_error": True, "permission_denials": []},
                               ensure_ascii=False) + "\n")
            return res.returncode
        except subprocess.TimeoutExpired:
            return -1  # 超时

    def model_id(self) -> str:
        return self._model
