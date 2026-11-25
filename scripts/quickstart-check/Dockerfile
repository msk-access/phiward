# The quickstart's Linux prerequisites on a clean python:3.12-slim (check.sh builds it)
FROM python:3.12-slim
RUN apt-get update -qq >/dev/null && apt-get install -y -qq bubblewrap socat git sudo >/dev/null 2>&1
RUN pip install -q uv pipx
# stand-ins for the @genomics programs setup lists by default, so doctor finds them on the PATH
RUN for p in samtools bedtools tabix bgzip mosdepth seqkit file; do \
      printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/$p && chmod 755 /usr/local/bin/$p; done
