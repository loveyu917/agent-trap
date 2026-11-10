"""
meta-agent（分析员 / 审计员 / 红队）的驱动选择。

这三个 meta-agent 的系统提示都来自 .claude/agents/*.md，与被测的是哪个模型无关；
这里只决定“用哪个模型来跑这个 meta-agent”：
  driver="claude"   → 真正的 claude CLI（需要容器里已登录 Claude Code）
  driver="deepseek" → llm_agent.py 替身（走 DeepSeek API，需要 DEEPSEEK_API_KEY）

build_meta_cmd 返回可直接交给 subprocess.run 的命令列表。claude 与 llm_agent.py 的
参数接口不同（allowedTools：前者空格分隔多个值，后者逗号分隔单个值），差异在这里吸收。
"""
import sys
from pathlib import Path

LLM_AGENT = Path(__file__).resolve().parent / "llm_agent.py"


def build_meta_cmd(driver, task, system_prompt, allowed_tools, max_turns,
                   disallowed_tools=None):
    """
    driver            "claude" | "deepseek"
    task              -p 任务说明
    system_prompt     系统提示正文（从 .md 读出）
    allowed_tools     list[str]，如 ["Read", "Grep", "Glob"]
    max_turns         最大轮次
    disallowed_tools  list[str]，仅 claude 用（llm_agent.py 只给它 allowed 里的工具）
    """
    if driver == "deepseek":
        # llm_agent.py 只认 -p / --append-system-prompt / --allowedTools(逗号分隔)
        return [sys.executable, str(LLM_AGENT),
                "-p", task,
                "--append-system-prompt", system_prompt,
                "--allowedTools", ",".join(allowed_tools),
                "--max-turns", str(max_turns)]

    cmd = ["claude", "-p", task,
           "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
           "--append-system-prompt", system_prompt,
           "--allowedTools", *allowed_tools,
           "--max-turns", str(max_turns),
           "--output-format", "text"]
    if disallowed_tools:
        cmd += ["--disallowedTools", *disallowed_tools]
    return cmd


def driver_missing_msg(driver):
    """子进程 FileNotFoundError 时的提示。"""
    if driver == "deepseek":
        return "找不到 python/llm_agent.py，或缺少 openai 库与 DEEPSEEK_API_KEY。"
    return "找不到 claude 命令，请在容器里运行（并确认已登录 Claude Code）。"
