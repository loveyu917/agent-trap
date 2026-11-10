"""
Claude CLI 驱动器：调用 claude -p 运行任务。
原来 run.py 里的逻辑，封装成驱动器接口。
"""
import subprocess
from pathlib import Path
from .base import AgentBase


# 只加载空的 MCP 配置，不加载账号自带的连接器
ISOLATION_FLAGS = ["--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}']


class ClaudeCLIAgent(AgentBase):
    name = "claude"

    def __init__(self, model: str | None = None):
        """
        Args:
            model: 可选的模型覆盖（如 "claude-opus-4-5-20250514"），不传则用 CLI 默认
        """
        self._model = model

    def run(self, task: str, workspace: Path, transcript_path: Path,
            timeout: int = 600, max_turns: int = 30, env: dict | None = None,
            cli_flags: list | None = None) -> int:
        cmd = [
            "claude", "-p", task,
            "--output-format", "stream-json",
            "--verbose",
            *ISOLATION_FLAGS,
            "--max-turns", str(max_turns),
        ]
        if self._model:
            cmd.extend(["--model", self._model])
        if cli_flags:
            cmd.extend(cli_flags)

        try:
            with transcript_path.open("w") as out:
                result = subprocess.run(
                    cmd, cwd=workspace, env=env,
                    stdout=out, stderr=open(workspace.parent / "stderr.log", "w"),
                    timeout=timeout,
                )
                return result.returncode
        except subprocess.TimeoutExpired:
            return -1  # 超时
        except FileNotFoundError:
            raise SystemExit("找不到 claude 命令，请确认已安装 Claude Code。")

    def model_id(self) -> str:
        return self._model or "claude-default"
