"""
Agent 驱动器基类。

每个驱动器要做的事：
1. 接收一个任务描述 + 工作目录
2. 让被测 agent 在该工作目录下执行任务
3. 把整个过程写成 transcript.jsonl（格式与 Claude CLI 的 stream-json 对齐）

transcript 格式要求：
- {"type": "system", "subtype": "init", "model": "...", "mcp_servers": []} 初始化行
- {"type": "assistant", "message": {"model": "...", "content": [...]}} 每次 assistant 回复
- {"type": "result", "result": "...", "permission_denials": [], "is_error": false} 最终结果
"""
from abc import ABC, abstractmethod
from pathlib import Path


class AgentBase(ABC):
    """所有 agent 驱动器的基类。"""

    # 显示名称（用于日志和报告）
    name: str = "base"

    @abstractmethod
    def run(self, task: str, workspace: Path, transcript_path: Path,
            timeout: int = 600, max_turns: int = 30, env: dict | None = None) -> int:
        """
        执行任务。

        Args:
            task: 任务描述（scenario.json 里的 task 字段）
            workspace: 工作目录（agent 的 cwd）
            transcript_path: 对话记录输出文件
            timeout: 超时秒数
            max_turns: 最大轮次
            env: 环境变量（已清理过的）

        Returns:
            返回码（0=正常结束）
        """
        ...

    def model_id(self) -> str:
        """返回当前使用的模型标识符。"""
        return self.name
