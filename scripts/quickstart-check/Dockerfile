# The quickstart's Linux prerequisites on a clean python:3.12-slim (check.sh builds it)
FROM python:3.12-slim
RUN apt-get update -qq >/dev/null && apt-get install -y -qq bubblewrap socat git sudo >/dev/null 2>&1
RUN pip install -q uv pipx
