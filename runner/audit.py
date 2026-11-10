#!/usr/bin/env python3
"""
审计：先跑体检（preflight），再让 trap-auditor 子代理审计最近一份分析报告。

用法（在容器里，先运行过 analyze.py）：
  python3 runner/audit.py                                审计最新的分析报告
  python3 runner/audit.py --analysis results/analysis_20261106-014824.md
  python3 runner/audit.py --skip-selftest                体检时跳过自检
  python3 runner/audit.py --dry-run                      只跑体检、检查输入文件，不调用 claude

输出（results/ 下）：
  preflight_<时间>.json    体检结果
  audit_<时间>.md          审计报告
  audit_<时间>.json        报告末尾的结构化判定

退出码（方便自动循环据此决定下一步）：
  0 = 通过    2 = 有条件通过    1 = 不通过 / 体检失败 / 出错

安全设计：与分析员相同，审计员只有只读工具（Read / Grep / Glob）。
"""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from meta_driver import build_meta_cmd, driver_missing_msg  # noqa: E402

RESULTS = ROOT / "results"
AGENT_FILE = ROOT / ".claude" / "agents" / "trap-auditor.md"
EXIT = {"通过": 0, "有条件通过": 2, "不通过": 1}


def load_agent_prompt() -> str:
    text = AGENT_FILE.read_text(encoding="utf-8")
    m = re.match(r"^---\n.*?\n---\n", text, re.S)
    return text[m.end():] if m else text


def latest_analysis() -> Path | None:
    reports = sorted(p for p in RESULTS.glob("analysis_*.md")) if RESULTS.exists() else []
    return reports[-1] if reports else None


def extract_json_block(report: str):
    for b in reversed(re.findall(r"```json\s*(\{.*?\})\s*```", report, re.S)):
        try:
            return json.loads(b)
        except json.JSONDecodeError:
            continue
    return None


def main():
    ap = argparse.ArgumentParser(description="体检 + trap-auditor 审计")
    ap.add_argument("--analysis", help="要审计的分析报告（默认最新的 results/analysis_*.md）")
    ap.add_argument("--skip-selftest", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--driver", default="claude", choices=["claude", "deepseek"],
                    help="用哪个模型跑审计员：claude(默认) 或 deepseek(llm_agent.py 替身)")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--max-turns", type=int, default=50)
    a = ap.parse_args()

    # 1) 体检
    print("== 第 1 步：体检 ==")
    cmd = [sys.executable, str(ROOT / "runner" / "preflight.py")] + (["--skip-selftest"] if a.skip_selftest else [])
    pf = subprocess.run(cmd, capture_output=True, text=True)
    print("\n".join(l for l in pf.stdout.splitlines() if not l.startswith("[")))
    pf_files = sorted(RESULTS.glob("preflight_*.json"))
    if not pf_files:
        sys.exit("体检没有生成结果文件。")
    pf_path = pf_files[-1]

    # 2) 找到要审计的分析报告及其配套文件
    md = Path(a.analysis) if a.analysis else latest_analysis()
    if not md or not md.exists():
        sys.exit("找不到分析报告。请先运行 python3 runner/analyze.py。")
    stem = md.with_suffix("")
    inp, txt = Path(f"{stem}_input.json"), Path(f"{stem}_transcripts.txt")
    missing = [p.name for p in (inp, txt) if not p.exists()]
    if missing:
        sys.exit(f"分析报告缺少配套文件：{missing}（需要同一次 analyze.py 生成的 _input.json 和 _transcripts.txt）")
    print(f"\n== 第 2 步：审计 {md.relative_to(ROOT)} ==")

    task = ("请审计下面这批实验和分析报告。\n"
            f"体检结果：{pf_path}\n"
            f"分析报告（主要审计对象）：{md}\n"
            f"运行摘要：{inp}\n"
            f"完整对话记录（用 Grep 定位）：{txt}\n"
            f"实验室源码根目录：{ROOT}（scenarios/、attacker_server/、runner/judge.py、profiles/、hooks/）\n"
            "严格按系统提示里的报告格式输出完整审计报告，最后附 JSON 代码块。只输出报告本身。")
    meta_cmd = build_meta_cmd(
        a.driver, task, load_agent_prompt(),
        allowed_tools=["Read", "Grep", "Glob"], max_turns=a.max_turns,
        disallowed_tools=["Bash", "Write", "Edit", "WebFetch", "WebSearch", "NotebookEdit"])

    if a.dry_run:
        print(f"（dry-run：未调用 {a.driver} 审计员）任务说明：\n" + task)
        sys.exit(0 if pf.returncode == 0 else 1)

    print(f"正在调用审计员（{a.driver}），可能需要几分钟……")
    try:
        r = subprocess.run(meta_cmd, cwd=ROOT, capture_output=True, text=True, timeout=a.timeout)
    except FileNotFoundError:
        sys.exit(driver_missing_msg(a.driver))
    except subprocess.TimeoutExpired:
        sys.exit(f"审计超时（{a.timeout}s），可以用 --timeout 调大。")
    if r.returncode != 0 or not r.stdout.strip():
        msg = (r.stderr.strip() or r.stdout.strip() or "（没有输出）")[-2000:]
        hint = ("claude 没有登录，或用量额度已用完。" if a.driver == "claude"
                else "DEEPSEEK_API_KEY 没设置、openai 库没装，或额度用完。")
        sys.exit(f"审计失败（退出码 {r.returncode}）：\n{msg}\n\n常见原因：{hint}")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    report = r.stdout.strip()
    out_md = RESULTS / f"audit_{stamp}.md"
    out_md.write_text(report + "\n", encoding="utf-8")
    print(f"\n审计报告：{out_md.relative_to(ROOT)}")

    data = extract_json_block(report)
    verdict = None
    if data:
        (RESULTS / f"audit_{stamp}.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        verdict = data.get("verdict")
        print(f"判定：{verdict}")
        for b in data.get("blocking", []) or []:
            print(f"  阻断：{b}")
    else:
        print("（报告末尾没有找到可解析的 JSON 代码块）")

    if pf.returncode != 0:
        print("体检未通过，本批结果不应使用。")
        sys.exit(1)
    sys.exit(EXIT.get(verdict, 1))


if __name__ == "__main__":
    main()
