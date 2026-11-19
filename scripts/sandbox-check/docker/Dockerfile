# The image of the Linux sandbox check (scripts/sandbox-check/linux.sh builds it). No token, no
# secret and no copy of the repository: the source is mounted at run time.
# Claude Code comes from the committed package-lock.json: one version, its bytes pinned by their
# sha512. npm ci --ignore-scripts runs none of the package's scripts; the native binary of this
# platform (an optional dependency, pinned in the lock) is linked as `claude`, as the skipped
# postinstall would copy it. The package's engines field asks for Node 22 or newer and Debian's
# Node is older, so npm runs in Node's official image, in a stage of its own: the check's image
# needs no Node (the binary is native).
# CLAUDE_VERSION (a build-arg) installs another version instead, unlocked: the report says so.
ARG CLAUDE_VERSION=
FROM node:22-trixie-slim AS claude
ARG CLAUDE_VERSION
COPY package.json package-lock.json /opt/claude/
RUN cd /opt/claude && if [ -z "$CLAUDE_VERSION" ]; then \
      npm ci --ignore-scripts --no-audit --no-fund && echo yes > locked; \
    else \
      npm install --ignore-scripts --no-audit --no-fund --no-package-lock \
        "@anthropic-ai/claude-code@$CLAUDE_VERSION" && echo no > locked; \
    fi

FROM python:3.12-slim
ARG CLAUDE_VERSION
RUN apt-get update -qq >/dev/null && \
    apt-get install -y -qq --no-install-recommends bubblewrap socat git bsdutils util-linux \
      ca-certificates >/dev/null 2>&1
COPY --from=claude /opt/claude /opt/claude
RUN case $(uname -m) in x86_64) a=x64 ;; aarch64) a=arm64 ;; *) echo "unknown arch" >&2; exit 1 ;; esac && \
    ln -s "/opt/claude/node_modules/@anthropic-ai/claude-code-linux-$a/claude" /usr/local/bin/claude && \
    want=${CLAUDE_VERSION:-$(sed -n 's/.*"@anthropic-ai\/claude-code": "\(.*\)".*/\1/p' /opt/claude/package.json)} && \
    got=$(claude --version | head -1) && echo "claude: $got" && \
    case $got in "$want "*|"$want") ;; *) echo "claude is $got, not $want" >&2; exit 1 ;; esac
RUN pip install -q uv==0.13.9
RUN useradd -m tester && mkdir /work /out && chown tester /work /out
USER tester
RUN uv python install -q 3.12
WORKDIR /work
