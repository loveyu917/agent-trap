# Agent 驱动器注册表
from .claude_cli import ClaudeCLIAgent
from .deepseek import DeepSeekAgent

AGENTS = {
    "claude": ClaudeCLIAgent,
    "deepseek": DeepSeekAgent,
}


def get_agent(name: str):
    if name not in AGENTS:
        raise SystemExit(f"未知的 agent: {name}（可选：{', '.join(AGENTS)}）")
    return AGENTS[name]()
