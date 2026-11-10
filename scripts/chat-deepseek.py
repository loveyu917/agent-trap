#!/usr/bin/env python3
"""
容器内与 DeepSeek 交互对话的小工具（类似敲 claude 开一个会话）。
用法：  python3 /lab/scripts/chat-deepseek.py
依赖：  环境变量 DEEPSEEK_API_KEY（启动容器时用 -e 传入），openai 库（镜像已装）。
退出：  输入 exit / quit，或按 Ctrl-D。
说明：  这是纯聊天，不带工具调用，与评测用的 agent_executor 互不影响。
"""
import os, sys

# Windows/Git Bash 下 stdin 可能不是 UTF-8，先强制过来，避免中文变成孤立代理字符
for _s in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

def _clean(text):
    """去掉任何残留的孤立代理字符，保证能安全编码成 UTF-8 发给 API。"""
    return text.encode('utf-8', 'surrogatepass').decode('utf-8', 'replace')

def main():
    key = os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        sys.exit("未设置 DEEPSEEK_API_KEY。请在启动容器时用 -e DEEPSEEK_API_KEY=sk-xxx 传入。")
    try:
        from openai import OpenAI
    except ImportError:
        sys.exit("缺少 openai 库：pip install openai")

    base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    model    = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
    client   = OpenAI(api_key=key, base_url=base_url)

    print(f"DeepSeek 对话  (model={model})  —  输入 exit 退出\n")
    messages = [{"role": "system", "content": "You are a helpful assistant."}]
    while True:
        try:
            user = input("你 > ").strip()
        except EOFError:
            print()
            break
        if user.lower() in ("exit", "quit"):
            break
        if not user:
            continue
        messages.append({"role": "user", "content": _clean(user)})
        print("DeepSeek > ", end="", flush=True)
        reply = ""
        try:
            stream = client.chat.completions.create(
                model=model, messages=messages, temperature=0.7, stream=True)
            for chunk in stream:
                delta = chunk.choices[0].delta.content or ""
                reply += delta
                print(delta, end="", flush=True)
        except Exception as e:
            print(f"\n[请求出错] {e}")
            messages.pop()
            continue
        print("\n")
        messages.append({"role": "assistant", "content": reply})

if __name__ == "__main__":
    main()
