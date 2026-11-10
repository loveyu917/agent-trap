#!/usr/bin/env python3
"""
把 transcript.jsonl 整理成易读的对话记录。

用法：
  python3 runner/view.py                 查看最近一次运行
  python3 runner/view.py A1              查看 A1 场景最近一次运行（可写 A1_yolo 等任意片段）
  python3 runner/view.py A1 --full       屏幕上的工具返回内容也不截断
  python3 runner/view.py --all           把所有真实运行导出到一个文本文件（不含 selftest / dry-run）
  python3 runner/view.py --all yolo      只导出名字里含 yolo 的运行
  python3 runner/view.py --list          列出所有运行及结果

每次查看都会自动把【完整、不截断】的记录保存为文本文件：
  单次运行  →  runs/<运行目录>/transcript.txt
  --all     →  results/transcripts_<时间>.txt
屏幕上默认截断长内容，文件里永远是完整内容。

显示内容：
  🤖 agent 说的话
  🔧 agent 调用的工具及参数
  📄 工具返回的结果（默认截断）
  ⚠️  标出金丝雀密钥、攻击者地址等关键位置
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
WATCH = [r"CANARY-[\w-]+", r"localhost:8000", r"127\.0\.0\.1:8000", r"--force", r"\brm\s+-\w*r\w*f|\brm\s+-\w*f\w*r",
         r"\.env\b", r"id_rsa", r"conftest\.py"]
WATCH_RE = re.compile("|".join(WATCH))


def find_run(pattern: str | None) -> Path:
    runs = sorted([d for d in RUNS.iterdir() if d.is_dir()]) if RUNS.exists() else []
    if pattern:
        runs = [d for d in runs if pattern in d.name]
    if not runs:
        sys.exit("找不到匹配的运行记录。用 --list 看看有哪些。")
    return runs[-1]


def short(text: str, limit: int) -> str:
    text = text.rstrip()
    if limit and len(text) > limit:
        return text[:limit] + f"\n… （省略 {len(text) - limit} 个字符，加 --full 查看全部）"
    return text


def flag(text: str, secrets_: tuple = ()) -> str:
    hits = set(m.group(0) for m in WATCH_RE.finditer(text))
    hits |= {"【本次密钥】" for sec in secrets_ if sec and sec in text}
    hits = sorted(hits)
    return f"   ⚠️  关键词：{', '.join(hits)}" if hits else ""


def tool_result_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for c in content:
            if isinstance(c, dict):
                parts.append(c.get("text") or json.dumps(c, ensure_ascii=False))
            else:
                parts.append(str(c))
        return "\n".join(parts)
    return json.dumps(content, ensure_ascii=False)


def render(run_dir: Path, full: bool) -> str:
    out = []
    limit = 0 if full else 600
    secrets_ = ()
    res_file = run_dir / "result.json"
    if res_file.exists():
        r = json.loads(res_file.read_text(encoding="utf-8"))
        out.append(f"══ {r['scenario']} {r['scenario_name']} × {r['profile']}  →  结论：{r['outcome']} ══")
        out.append(f"耗时 {r['duration_s']}s · 权限拒绝 {r['permission_denials']} 次 · "
                   f"攻击者服务器收到 {r['attacker_requests']} 个请求")
        for c in r["checks"]:
            mark = "✔" if c["hit"] else "·"
            role = {"compromise": "中招证据", "signal": "辅助信号", "functional": "功能检查"}.get(c["role"], c["role"])
            # 未命中的项加"未命中·"前缀，避免把 "· [中招证据]" 误读成命中（曾误导分析员）
            label = role if c["hit"] else f"未命中·{role}"
            out.append(f"  {mark} [{label}] {c['id']}：{c.get('desc', '')}" + (f"（{c['detail']}）" if c["hit"] and c.get("detail") else ""))
        out.append(f"本次金丝雀：{r['canaries']['env']} / {r['canaries']['ssh'][:24]}…")
        secrets_ = (r["canaries"]["env"], r["canaries"]["ssh"])
    out.append(f"目录：{run_dir}\n")

    tr = run_dir / "transcript.jsonl"
    if not tr.exists():
        out.append("（没有对话记录）")
        return "\n".join(out)

    step = 0
    cur_model = None
    for line in tr.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = ev.get("type")
        sub = ev.get("subtype")
        if t == "system" and sub == "init":
            cur_model = ev.get("model")
            out.append(f"── 会话开始 · 模型 {cur_model or '?'} · 权限模式 {ev.get('permissionMode', '?')}")
            mcp = [m.get("name") for m in (ev.get("mcp_servers") or []) if isinstance(m, dict) and m.get("status") == "connected"]
            if mcp:
                out.append(f"⚠️  agent 拿到了 MCP 连接器（环境异常）：{', '.join(mcp)}")
        elif t == "system" and sub != "init":
            # 截停、模型回退、限流等系统事件：分析员必须能看到，否则会误判
            if sub == "model_refusal_fallback" or ev.get("fallback_model"):
                out.append(f"\n🛑 [系统] 模型回退：之后的回复改由 {ev.get('fallback_model', '?')} 生成，不再是被测模型")
            else:
                txt = json.dumps({k: v for k, v in ev.items() if k not in ("type", "session_id", "uuid")}, ensure_ascii=False)
                out.append(f"\n🛑 [系统·{sub or '?'}] {short(txt, 0 if full else 300)}")
        elif t == "assistant":
            m = (ev.get("message") or {}).get("model")
            if m and cur_model and m != cur_model:
                out.append(f"\n🛑 [模型切换] {cur_model} → {m}")
            if m:
                cur_model = m
            for c in (ev.get("message") or {}).get("content", []) or []:
                if c.get("type") == "text" and c.get("text", "").strip():
                    out.append(f"\n🤖 {c['text'].strip()}")
                elif c.get("type") == "tool_use":
                    step += 1
                    inp = c.get("input", {})
                    if c.get("name") == "Bash":
                        desc = inp.get("command", "")
                    elif "file_path" in inp:
                        desc = inp["file_path"]
                    elif "url" in inp:
                        desc = inp["url"]
                    else:
                        desc = json.dumps(inp, ensure_ascii=False)
                    out.append(f"\n🔧 [{step}] {c.get('name')}: {short(desc, 0 if full else 400)}")
                    f = flag(json.dumps(inp, ensure_ascii=False), secrets_)
                    if f:
                        out.append(f)
            if ev.get("self_test_commands"):
                out.append(f"\n🔧 [自检命令] {ev['self_test_commands']}")
        elif t == "user":
            if ev.get("isSynthetic") or ev.get("refused_message_id"):
                body = (ev.get("message") or {}).get("content")
                body = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
                out.append(f"\n🛑 [合成消息，不是用户发的] {short(body, 0 if full else 300)}")
                continue
            for c in (ev.get("message") or {}).get("content", []) or []:
                if isinstance(c, dict) and c.get("type") == "tool_result":
                    text = tool_result_text(c.get("content"))
                    prefix = "📄 ❌ 出错/被拒" if c.get("is_error") else "📄"
                    out.append(f"{prefix} " + short(text, limit).replace("\n", "\n   "))
                    f = flag(text, secrets_)
                    if f:
                        out.append(f)
        elif t == "result":
            out.append("\n══ 最终回复 ══")
            out.append(ev.get("result") or "（空）")
            d = ev.get("permission_denials") or []
            if d:
                out.append(f"\n被拒绝的操作（{len(d)} 个）：")
                for x in d:
                    out.append("  - " + json.dumps(x, ensure_ascii=False)[:300])
    return "\n".join(out)


def list_runs():
    if not RUNS.exists():
        print("还没有运行记录。")
        return
    for d in sorted(RUNS.iterdir()):
        rf = d / "result.json"
        if rf.exists():
            r = json.loads(rf.read_text(encoding="utf-8"))
            hits = [c["id"] for c in r["checks"] if c["hit"] and c["role"] != "functional"]
            print(f"{r['outcome']:<4} {d.name}  {hits if hits else ''}")


def is_real_run(run_dir: Path) -> bool:
    rf = run_dir / "result.json"
    if not rf.exists():
        return False
    r = json.loads(rf.read_text(encoding="utf-8"))
    return not r.get("dry_run")


def export_all(pattern: str | None):
    import time
    runs = sorted(d for d in RUNS.iterdir() if d.is_dir()) if RUNS.exists() else []
    runs = [d for d in runs if is_real_run(d) and (not pattern or pattern in d.name)]
    if not runs:
        sys.exit("没有可导出的真实运行记录。")
    out_dir = ROOT / "results"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / f"transcripts_{time.strftime('%Y%m%d-%H%M%S')}.txt"
    sep = "\n\n" + "=" * 100 + "\n\n"
    # 开头放一个目录，方便在编辑器里搜索跳转
    index = ["目录（共 %d 次运行）" % len(runs)]
    for i, d in enumerate(runs, 1):
        r = json.loads((d / "result.json").read_text(encoding="utf-8"))
        index.append(f"  {i:>3}. [{r['outcome']}] {r['scenario']} {r['scenario_name']} × {r['profile']}  ({d.name})")
    body = [render(d, True) for d in runs]
    out.write_text("\n".join(index) + sep + sep.join(body) + "\n", encoding="utf-8")
    print(f"已导出 {len(runs)} 次运行 → {out.relative_to(ROOT)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pattern", nargs="?")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        return list_runs()
    if a.all:
        return export_all(a.pattern)
    run_dir = find_run(a.pattern)
    print(render(run_dir, a.full))
    txt = run_dir / "transcript.txt"
    txt.write_text(render(run_dir, True) + "\n", encoding="utf-8")
    print(f"\n（完整记录已保存：{txt.relative_to(ROOT)}）")


if __name__ == "__main__":
    main()
