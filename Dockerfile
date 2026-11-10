FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates nodejs npm iproute2 net-tools procps \
 && rm -rf /var/lib/apt/lists/*

# claude-code = Claude 靶机/meta-agent；openai = DeepSeek 靶机(agent_executor.py)与 meta 替身(llm_agent.py)
RUN npm install -g @anthropic-ai/claude-code \
 && pip install --no-cache-dir pytest openai setproctitle

# ②-C 隔离：runner 以 root 运行，被测 agent 降权到非特权用户 sandbox。
# /lab 设为 root 700——sandbox 从内核层就读不到场景定义、其他运行的记录、攻击者服务器源码，
# 即使软隔离正则被绕过也挡得住。被测 agent 只在自己家目录 /home/sandbox/work 下活动。
# 向后兼容：runner 检测到没有 sandbox 用户时会退化为旧行为，所以旧镜像不受影响。
RUN useradd -m -u 1001 sandbox \
 && mkdir -p /lab/runs /lab/results /lab/logs /root/.claude \
           /home/sandbox/.harness /home/sandbox/work /home/sandbox/.ssh \
 && chown -R sandbox:sandbox /home/sandbox \
 && chmod 750 /home/sandbox
ENV TRAP_LAB_CONTAINER=1

WORKDIR /lab
COPY . /lab
# /lab 归 root、700：sandbox（被测 agent）读不到；runner 以 root 跑，照常读写
RUN chown -R root:root /lab && chmod -R 700 /lab \
 && git config --global init.defaultBranch main \
 && git config --global user.email dev@example.com \
 && git config --global user.name dev \
 && su sandbox -c 'git config --global init.defaultBranch main \
    && git config --global user.email dev@example.com \
    && git config --global user.name dev'

# 进入容器的交互 shell 自动显示快速开始横幅；并加 menu/help 命令随时再调出
RUN printf '\nalias menu="bash /lab/scripts/welcome.sh"\nalias help="bash /lab/scripts/welcome.sh"\n[ -f /lab/scripts/welcome.sh ] && bash /lab/scripts/welcome.sh\n' >> /root/.bashrc

# 以 root 运行：runner 需要 root 才能把被测 agent 降权到 sandbox、并 chown 工作区。
# 被测 agent 永远以 sandbox（非 root）运行，不触犯 --dangerously-skip-permissions 的限制。
CMD ["bash"]
