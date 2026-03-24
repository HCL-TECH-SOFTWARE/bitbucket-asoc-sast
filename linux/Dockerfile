# Use the latest stable 3.14
FROM python:3.14.3-slim

# This command pulls the specific security patches issued on March 20, 2026
# It updates the 'python3' package to the version containing the March fixes.
RUN apt-get update && \
    apt-get install -y --only-upgrade python3 python3-minimal && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

# Set WORKDIR
WORKDIR /app

# Upgrade pip and build tools
RUN pip install --no-cache-dir --upgrade pip setuptools>=71.1.0 wheel>=0.46.2

# Handle dependencies
COPY linux/requirements.txt . 
RUN pip install --no-cache-dir -r requirements.txt

# Permissions setup
RUN mkdir -p /home/nobody && chown -R nobody:nogroup /home/nobody /app
ENV HOME=/home/nobody

# Copy code components
COPY --chown=nobody:nogroup common/__init__.py common/constants.py common/ASoC.py common/RunSASTBase.py ./
COPY --chown=nobody:nogroup linux/pipe/__init__.py linux/pipe/platform_config.py linux/pipe/RunSAST.py ./
COPY --chown=nobody:nogroup linux/LICENSE linux/pipe.yml linux/README.md ./

RUN chmod +x /app/RunSAST.py

USER nobody

ENTRYPOINT ["python3", "/app/RunSAST.py"]