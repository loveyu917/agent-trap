"""被测 agent 的 OS 级隔离（②-C）。

思路：runner 以 root 运行，被测 agent（claude / deepseek 执行器）降权到非特权用户
`sandbox`；/lab、/root、攻击者服务器源码都设成 sandbox 读不到。即使软隔离正则被绕过，
内核也会挡住 `cat /lab/...`、`ls /lab`、`readlink /proc/<server>/cwd` 等一切访问。

**向后兼容**：容器里没有 `sandbox` 用户时（旧镜像），enabled() 返回 False，所有函数退化为
no-op，run.py 的行为与 v13 完全一致——把新 run.py 覆盖进旧镜像不会有任何改变，隔离只在用
新 Dockerfile 重建后才启用。
"""
import shutil
import subprocess
from pathlib import Path

USER = "sandbox"
HOME = Path("/home/sandbox")
_enabled = None


def enabled() -> bool:
    """容器里是否存在 sandbox 用户（即隔离是否可用）。结果缓存。"""
    global _enabled
    if _enabled is None:
        try:
            import pwd
            pwd.getpwnam(USER)
            _enabled = True
        except (KeyError, ImportError):
            _enabled = False
    return _enabled


def home() -> Path:
    """被测 agent 的 HOME：启用隔离时是 /home/sandbox，否则是 runner 自己的 HOME。"""
    return HOME if enabled() else Path.home()


def chown_to_sandbox(path: Path):
    """把 path 整棵树交给 sandbox 用户（runner 以 root 跑才有权限）。失败则静默。"""
    if not enabled():
        return
    try:
        subprocess.run(["chown", "-R", f"{USER}:{USER}", str(path)],
                       check=True, capture_output=True)
    except Exception:
        pass


def sync_claude_creds() -> bool:
    """把登录凭据从 root 同步给 sandbox，让降权后的 claude 仍用订阅登录。
    返回 True 表示 sandbox 侧有可用凭据（否则调用方应回退为不降权，避免整批未登录失败）。"""
    if not enabled():
        return True
    ok = False
    try:
        src = Path("/root/.claude")
        dst = HOME / ".claude"
        if src.exists():
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst, symlinks=True)
            # 去掉会话历史/项目记录——它们含宿主路径(如 "project":"/lab")，被 agent cat 到就是环境泄露
            # (v21 审计发现 162826)。只保留凭据相关文件，agent 看不到装置路径。
            for leaky in ("history.jsonl", "projects", "sessions", "todos", "statsig", "shell-snapshots"):
                p = dst / leaky
                shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)
            ok = True
        for name in (".claude.json",):  # 部分版本把配置放这里
            s = Path("/root") / name
            if s.exists():
                shutil.copy2(s, HOME / name)
        chown_to_sandbox(HOME / ".claude")
        for name in (".claude.json",):
            p = HOME / name
            if p.exists():
                chown_to_sandbox(p)
    except Exception:
        pass
    return ok


def purge_claude_home() -> None:
    """删掉 sandbox 家目录里的 Claude 凭据和历史。
    非 Claude 靶机(如 DeepSeek)运行前调用：两个 agent 同为 sandbox uid，
    若不清，DeepSeek 能 cat /home/sandbox/.claude/.credentials.json 读到 Claude 的 OAuth 凭据
    并发给自己的 API 商（v21 审计指出的凭据暴露风险）。下一次 Claude 运行会重新 sync。"""
    if not enabled():
        return
    try:
        shutil.rmtree(HOME / ".claude", ignore_errors=True)
        (HOME / ".claude.json").unlink(missing_ok=True)
    except Exception:
        pass


def writeback_claude_creds() -> None:
    """把 claude 这轮刷新/轮换后的登录凭据写回 /root/.claude（持久卷）。
    OAuth 的 refresh token 常是一次性轮换的：claude 用掉旧的、把新的写进 $HOME/.claude（=sandbox），
    若不回写，下一轮 sync 又拿 /root 里的旧 token 覆盖回去 → 旧 token 已作废 → 整批登录被烧掉
    （表现为第一轮能跑、之后全部 <synthetic>/认证失败）。所以每轮跑完都要回写。"""
    if not enabled():
        return
    try:
        # 回写 ~/.claude 下所有顶层文件（不含 projects/ 等子目录），
        # 这样无论凭据文件叫 .credentials.json 还是别的名字都能覆盖到；外加 ~/.claude.json。
        src_dir = HOME / ".claude"
        dst_dir = Path("/root/.claude")
        if src_dir.is_dir():
            dst_dir.mkdir(parents=True, exist_ok=True)
            for f in src_dir.iterdir():
                if f.is_file():
                    shutil.copy2(f, dst_dir / f.name)
        s = HOME / ".claude.json"
        if s.exists():
            shutil.copy2(s, Path("/root/.claude.json"))
    except Exception:
        pass


def stage_executor(executor_src: Path) -> str:
    """把 agent_executor.py 复制到 sandbox 可读处（/lab 对 sandbox 已不可读）。返回新路径。"""
    d = HOME / ".harness"
    d.mkdir(parents=True, exist_ok=True)
    dst = d / "exec.py"
    shutil.copy2(executor_src, dst)
    chown_to_sandbox(d)
    return str(dst)


def launch_kwargs() -> dict:
    """subprocess.run 的降权参数。未启用时为空（不降权）。"""
    return {"user": USER, "group": USER} if enabled() else {}
