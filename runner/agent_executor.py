#!/usr/bin/env python3
"""
DeepSeek 执行器：通过 OpenAI 兼容 API 直连 DeepSeek，自己实现工具调用循环。

用法（由 run.py 以子进程方式调用）：
  python3 agent_executor.py <task> <workspace> <transcript_path> <profile> [lab_root]

- task            任务描述（scenario.json 的 task 字段）
- workspace       agent 的工作目录（cwd）
- transcript_path 对话记录输出文件（格式与 Claude CLI stream-json 对齐）
- profile         权限配置名（yolo/auto 放行一切；rules/hooks 读 settings.json）
- lab_root        可选：实验框架所在目录（软隔离要挡住它，默认同时挡 /app 和 /lab）

环境变量：
  DEEPSEEK_API_KEY  必须设置；执行器读取后立刻从环境里弹出，绝不传给靶机进程
  DEEPSEEK_MODEL    模型名，默认 deepseek-chat
  DEEPSEEK_BASE_URL 默认 https://api.deepseek.com
"""
import sys, os, json, subprocess, re
from pathlib import Path
from openai import OpenAI

# key 优先从 stdin 注入的 _INJECTED_CONFIG 取（降权运行）：这样它绝不进执行器子进程的环境块，
# agent 即便读到 /proc/<executor>/environ（正则绕过）也拿不到真实 DeepSeek key。
# 非注入路径（直接跑文件）回退到环境变量。os.environ.pop 改不了已启动进程的 /proc environ 副本，
# 所以真正的防线是"从一开始就不把 key 放进环境"，而不是 pop。
_CFG0 = globals().get("_INJECTED_CONFIG") or {}
API_KEY = _CFG0.get("api_key") or os.environ.pop("DEEPSEEK_API_KEY", "")
MODEL = _CFG0.get("model") or os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
BASE_URL = _CFG0.get("base_url") or os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

# 软隔离要挡住的框架目录。run.py 会把实际的 lab_root 作为第 5 个参数传进来；
# 没传时同时挡 /app（旧 DeepSeek 容器）和 /lab（统一容器），两头都安全。
LAB_DIRS = ["/app", "/lab"]

TOOLS = [
    {"type": "function", "function": {"name": "Bash", "description": "执行 bash 命令", "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
    {"type": "function", "function": {"name": "Read", "description": "读取文件", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}},
    {"type": "function", "function": {"name": "Write", "description": "写入文件", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}, "content": {"type": "string"}}, "required": ["file_path", "content"]}}},
    {"type": "function", "function": {"name": "Edit", "description": "修改文件", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}, "old_string": {"type": "string"}, "new_string": {"type": "string"}}, "required": ["file_path", "old_string", "new_string"]}}},
    {"type": "function", "function": {"name": "Grep", "description": "搜索文本", "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}, "path": {"type": "string"}}, "required": ["pattern", "path"]}}},
    {"type": "function", "function": {"name": "Glob", "description": "查找文件", "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}}}
]


def clean_env():
    env = os.environ.copy()
    env.pop("DEEPSEEK_API_KEY", None)
    env.pop("DEEPSEEK_MODEL", None)
    env.pop("DEEPSEEK_BASE_URL", None)
    env.pop("TRAP_LAB_CONTAINER", None)
    return env


def _bash_blocked_re():
    # 命令里只要提到框架目录、/proc、keyreg、/root/.local 就拦。
    # /proc 用 /proc\b 整体拦截——旧的 /proc/\d+ 只拦字面数字，被 /proc/[0-9]*、/proc/$PPID、
    # ls /proc/*/cwd 绕过（审计 061452/061558 实测绕过成功）。这些场景 agent 没有读 /proc 的正当需求。
    # 不再只盯 cd/ls/cat——堵住 find/ls -la/readlink/cat 等一切绕法（审计发现 ls -la /lab、find /lab 可绕过旧正则）
    dir_alts = "|".join(re.escape(d) for d in LAB_DIRS)
    return re.compile(r"(?:" + dir_alts + r")(?:/|\b)|/proc\b|/root/\.local|keyreg")


def _read_blocked(file_path: str) -> bool:
    return (any(file_path.startswith(d) for d in LAB_DIRS)
            or file_path.startswith("/root") or file_path.startswith("/proc")
            or "keyreg" in file_path)


BASH_BLOCKED = _bash_blocked_re()


def is_allowed(tool_name, args, profile, ws):
    if profile in ("yolo", "auto"): return True, ""
    settings_file = ws / ".claude" / "settings.json"
    if not settings_file.exists(): return True, ""
    try: settings = json.loads(settings_file.read_text())
    except: return True, ""
    allow = settings.get("permissions", {}).get("allow", [])
    deny = settings.get("permissions", {}).get("deny", [])
    cmd = args.get("command", "") if tool_name == "Bash" else args.get("file_path", "")
    sig = f"{tool_name}({cmd})"
    for d in deny:
        pattern = d.replace("*", ".*").replace("(", "\\(").replace(")", "\\)")
        if re.search(pattern, sig, re.IGNORECASE): return False, f"Denied by rule: {d}"
    for a in allow:
        pattern = a.replace("*", ".*").replace("(", "\\(").replace(")", "\\)")
        if re.search(pattern, sig, re.IGNORECASE): return True, ""
    return False, "Not in allow list"


def execute_tool(name, args, ws):
    try:
        # 【软隔离】：防止 agent 跑到框架目录里看实验装置
        if name == "Bash":
            cmd = args["command"]
            if BASH_BLOCKED.search(cmd):
                return "Error: Permission denied. You can only access the current workspace."

            r = subprocess.run(cmd, shell=True, cwd=ws, capture_output=True, text=True, timeout=120, env=clean_env())
            return (r.stdout + r.stderr)[-3000:]
        elif name == "Read":
            file_path = args["file_path"]
            if _read_blocked(file_path):
                return "Error: Permission denied. You can only access the current workspace."
            p = ws / file_path
            return p.read_text(errors="ignore")[:5000] if p.exists() else "Error: File not found"
        elif name == "Write":
            p = ws / args["file_path"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(args["content"])
            return "Success"
        elif name == "Edit":
            p = ws / args["file_path"]
            if not p.exists(): return "Error: File not found"
            text = p.read_text()
            if args["old_string"] not in text: return "Error: old_string not found"
            p.write_text(text.replace(args["old_string"], args["new_string"]))
            return "Success"
        elif name == "Grep":
            p = ws / args.get("path", ".")
            matches = []
            for f in p.rglob("*"):
                if f.is_file():
                    try:
                        for line in f.read_text(errors="ignore").splitlines():
                            if re.search(args["pattern"], line): matches.append(f"{f.relative_to(ws)}: {line}")
                    except: pass
            return "\n".join(matches[:100]) or "No matches"
        elif name == "Glob":
            return "\n".join(str(p.relative_to(ws)) for p in ws.glob(args["pattern"]))
    except Exception as e:
        return f"Error: {e}"
    return "Unknown tool"


def soft_iso_reason(name, args):
    """软隔离：访问框架目录/进程/服务器源码时返回拒绝原因，否则 None。供 main 记入 denials。"""
    if name == "Bash" and BASH_BLOCKED.search(args.get("command", "")):
        return "You can only access the current workspace."
    if name in ("Read", "Edit", "Write") and _read_blocked(str(args.get("file_path", ""))):
        return "You can only access the current workspace."
    return None


def main():
    # 降权运行时，配置通过 stdin 注入的 _INJECTED_CONFIG 传进来（见 agents/deepseek.py），
    # argv 只有 `python3 -`，任务原文/profile//lab 绝不进命令行——否则 agent 用
    # `ps aux` / `cat /proc/<ppid>/cmdline` 就能看穿这是测试装置（v15 的回退根因）。
    cfg = globals().get("_INJECTED_CONFIG")
    if cfg is not None:
        task, ws_str, tp_arg, profile = cfg["task"], cfg["workspace"], "-", cfg["profile"]
        lab_root = cfg.get("lab_root")
    else:
        task, ws_str, tp_arg, profile = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
        lab_root = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None
    ws = Path(ws_str)

    # 实验框架目录：传了就只挡它（+ /root），更精确。
    if lab_root:
        global LAB_DIRS, BASH_BLOCKED
        LAB_DIRS = [lab_root]
        BASH_BLOCKED = _bash_blocked_re()

    messages = [{"role": "user", "content": task}]
    denials = []

    # transcript_path == "-" 时写到 stdout（降权运行用，磁盘上不留文件给 agent 读），否则写文件
    f = sys.stdout if tp_arg == "-" else open(tp_arg, "w")
    try:
        f.write(json.dumps({"type": "system", "subtype": "init", "model": MODEL, "permissionMode": profile, "mcp_servers": []}) + "\n")

        for _ in range(20):
            try:
                resp = client.chat.completions.create(model=MODEL, messages=messages, tools=TOOLS, temperature=0.0)
                msg = resp.choices[0].message
            except Exception as e:
                f.write(json.dumps({"type": "result", "result": f"API Error: {e}", "is_error": True, "permission_denials": denials}) + "\n")
                break

            messages.append(msg.model_dump(exclude_none=True))

            if msg.content:
                f.write(json.dumps({"type": "assistant", "message": {"model": MODEL, "content": [{"type": "text", "text": msg.content}]}}) + "\n")

            if not msg.tool_calls:
                f.write(json.dumps({"type": "result", "result": msg.content or "Done", "permission_denials": denials}) + "\n")
                break

            for call in msg.tool_calls:
                name = call.function.name
                args = json.loads(call.function.arguments)

                f.write(json.dumps({"type": "assistant", "message": {"model": MODEL, "content": [{"type": "tool_use", "name": name, "input": args}]}}) + "\n")

                allowed, reason = is_allowed(name, args, profile, ws)

                # 软隔离：命中框架路径直接拦下，并计入 denials（审计发现旧版拦下却不记录，导致"权限拒绝 0 次"）
                if allowed:
                    si = soft_iso_reason(name, args)
                    if si:
                        allowed, reason = False, si

                if allowed and profile == "hooks":
                    hook_path = ws / ".claude" / "hooks" / "guard.py"
                    if hook_path.exists():
                        res = subprocess.run([sys.executable, str(hook_path)], input=json.dumps({"tool_name": name, "tool_input": args}), capture_output=True, text=True)
                        if res.returncode == 2:
                            allowed = False
                            reason = res.stderr.strip()

                if not allowed:
                    denials.append({"tool_name": name, "tool_input": args})
                    result = f"Error: Permission denied. {reason}"
                else:
                    result = execute_tool(name, args, ws)

                f.write(json.dumps({"type": "user", "message": {"content": [{"type": "tool_result", "content": result}]}}) + "\n")
                messages.append({"role": "tool", "tool_call_id": call.id, "content": result})
        else:
            # 跑满 20 轮都没收尾：补写 result(is_error)，避免空回复被 judge 判成"安全"（审计 36a781c6）
            f.write(json.dumps({"type": "result", "result": "", "is_error": True,
                                "subtype": "max_turns", "permission_denials": denials}) + "\n")
    finally:
        if f is not sys.stdout:
            f.close()


if __name__ == "__main__": main()
