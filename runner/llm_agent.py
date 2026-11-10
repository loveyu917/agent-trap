#!/usr/bin/env python3
"""
meta-agent 的 DeepSeek 替身：模拟 `claude -p` 的命令行接口，让分析员 / 审计员 / 红队
这三个 meta-agent 也能跑在 DeepSeek 上（当容器里没有 Claude 时）。

它只认 claude CLI 的这几个参数，其余参数（--max-turns、--output-format 等）忽略即可：
  -p <task>                    任务
  --append-system-prompt <s>   系统提示（从 .claude/agents/*.md 读出的正文）
  --allowedTools <csv>         允许的工具，逗号分隔，如 "Read,Grep,Glob,Write"

与被测靶机执行器（agent_executor.py）区别：
  - 这是只读为主的分析工具，不需要 Bash（meta-agent 不该执行命令）
  - 最终报告直接打印到 stdout（analyze.py/audit.py/redteam.py 读 stdout 存文件）

环境变量：
  DEEPSEEK_API_KEY  必须设置
  DEEPSEEK_MODEL    默认 deepseek-chat
  DEEPSEEK_BASE_URL 默认 https://api.deepseek.com
"""
import sys, os, json, re
from pathlib import Path
from openai import OpenAI

MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
client = OpenAI(api_key=os.environ.get("DEEPSEEK_API_KEY"), base_url=BASE_URL)

MAX_TURNS = 40  # meta-agent 需要多轮 Grep/Read 核实，给足轮数


def _arg(flag, default=""):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default


def build_tools(allowed):
    specs = {
        "Read":  {"name": "Read",  "description": "读取文件", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}},
        "Grep":  {"name": "Grep",  "description": "在文件里按正则搜索行", "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}, "path": {"type": "string"}}, "required": ["pattern", "path"]}},
        "Glob":  {"name": "Glob",  "description": "按通配符查找文件", "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}},
        "Write": {"name": "Write", "description": "写入文件", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}, "content": {"type": "string"}}, "required": ["file_path", "content"]}},
    }
    return [{"type": "function", "function": specs[t]} for t in allowed if t in specs]


def execute(name, args, cwd):
    try:
        if name == "Read":
            p = (cwd / args["file_path"]).resolve()
            return p.read_text(errors="ignore")[:30000]
        if name == "Grep":
            p = (cwd / args["path"]).resolve()
            if p.is_file():
                text = p.read_text(errors="ignore")
            elif p.is_dir():
                text = "\n".join(f.read_text(errors="ignore") for f in p.rglob("*") if f.is_file())
            else:
                text = ""
            return "\n".join(l for l in text.splitlines() if re.search(args["pattern"], l))[:30000] or "No matches"
        if name == "Glob":
            return "\n".join(str(x.relative_to(cwd)) for x in cwd.glob(args["pattern"]))
        if name == "Write":
            p = (cwd / args["file_path"]).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(args["content"])
            return "Success"
    except Exception as e:
        return f"Error: {e}"
    return f"Unknown tool: {name}"


def main():
    task = _arg("-p")
    system_prompt = _arg("--append-system-prompt")
    allowed = [t.strip() for t in _arg("--allowedTools").split(",") if t.strip()]
    tools = build_tools(allowed)
    cwd = Path.cwd()

    messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": task}]

    for i in range(MAX_TURNS):
        try:
            resp = client.chat.completions.create(
                model=MODEL, messages=messages,
                tools=tools or None, temperature=0.0)
            msg = resp.choices[0].message
        except Exception as e:
            print(f"API Error: {e}")
            return
        messages.append(msg.model_dump(exclude_none=True))

        if not msg.tool_calls:
            print(msg.content or "")
            return

        for call in msg.tool_calls:
            try:
                args = json.loads(call.function.arguments)
            except (json.JSONDecodeError, TypeError):
                args = {}
            result = execute(call.function.name, args, cwd)
            messages.append({"role": "tool", "tool_call_id": call.id, "content": str(result)})

        # 倒数第二轮强制收尾：要求直接产出最终报告，别再调工具
        if i == MAX_TURNS - 2:
            messages.append({"role": "user", "content":
                "已到工具调用上限。请立刻只基于现有信息，按系统提示要求的 Markdown 格式输出最终报告"
                "（末尾附 JSON 代码块），不要再调用任何工具。"})

    last = messages[-1]
    print(last.get("content", "") if isinstance(last, dict) else (last.content or ""))


if __name__ == "__main__":
    main()
