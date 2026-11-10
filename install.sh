#!/usr/bin/env bash
#
# Agent Trap Lab —— 一条命令安装并进入
#
#   ./install.sh                           # 只用 Claude（订阅登录），不测 DeepSeek
#   DEEPSEEK_API_KEY=sk-xxx ./install.sh    # 同时能测 DeepSeek
#   ./install.sh --rebuild                  # 改过代码后强制重建镜像
#
# 可在 Mac / Linux / Windows(Git Bash 或 WSL) 下运行。Windows 原生 cmd 请改用 install.bat。

set -euo pipefail

IMAGE="trap-lab:v22"
AUTH_VOLUME="trap-claude-auth"

cd "$(dirname "$0")"
mkdir -p results

# Git Bash / MSYS 会把 -v "源:/lab/results" 当成冒号分隔的路径列表，两段都转成 Windows 路径
# 再用分号拼起来（于是宿主机冒出 results;C 这种坏目录、/lab/results 挂不上）。
# 对策：关掉参数转换(MSYS2_ARG_CONV_EXCL)，并用 cygpath -w 把宿主机 results 路径转成 Windows 形式。
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
    HOST_RESULTS="$(cygpath -w "$PWD/results" 2>/dev/null || echo "$(pwd -W)/results")"
    ;;
  *)
    HOST_RESULTS="$PWD/results"
    ;;
esac

# 1. 检查 Docker
if ! command -v docker >/dev/null 2>&1; then
  echo "未找到 docker。请先安装 Docker Desktop：https://www.docker.com/products/docker-desktop/"; exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "Docker 没在运行。请先启动 Docker Desktop，再重试。"; exit 1
fi

# 2. 构建镜像（没有该镜像、或带 --rebuild 时才构建）
if [ "${1:-}" = "--rebuild" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "==> 构建镜像 $IMAGE（首次约几分钟，之后有缓存很快）..."
  docker build -t "$IMAGE" .
else
  echo "==> 镜像 $IMAGE 已存在（改了代码想重建：./install.sh --rebuild）"
fi

# 3. 持久卷：存 Claude 登录凭据，只建一次，删容器不丢
docker volume inspect "$AUTH_VOLUME" >/dev/null 2>&1 || docker volume create "$AUTH_VOLUME" >/dev/null

# 4. 可选的 DeepSeek key（不设也能跑，只是测不了 DeepSeek）
KEY_ARGS=()
if [ -n "${DEEPSEEK_API_KEY:-}" ]; then
  KEY_ARGS=(-e "DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY")
fi

# 5. 进容器（--rm：退出即删；登录在卷里、结果在 results/，都保留）
echo "==> results 挂载到宿主机：$HOST_RESULTS"
echo "==> 进入容器。退出后容器自动删除，登录和结果都保留。"
echo
exec docker run -it --rm \
  "${KEY_ARGS[@]}" \
  -v "$HOST_RESULTS:/lab/results" \
  -v "$AUTH_VOLUME:/root/.claude" \
  "$IMAGE"
