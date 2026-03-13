FROM python:3.13-slim

# Build context must be the repository root:
#   docker build -f linux/Dockerfile .
COPY linux/requirements.txt /
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r /requirements.txt

# Set proper working directory with correct permissions
RUN mkdir -p /app && chown -R nobody:nogroup /app
WORKDIR /app

# Create a writable home directory for the nobody user
# (default HOME=/nonexistent which does not exist, causing AppScan to fail)
RUN mkdir -p /home/nobody && chown -R nobody:nogroup /home/nobody
ENV HOME=/home/nobody

# Shared modules from common/
COPY --chown=nobody:nogroup common/__init__.py common/constants.py common/ASoC.py common/RunSASTBase.py /app/
# Platform-specific thin subclass + config
COPY --chown=nobody:nogroup linux/pipe/__init__.py linux/pipe/platform_config.py linux/pipe/RunSAST.py /app/
COPY --chown=nobody:nogroup linux/LICENSE linux/pipe.yml linux/README.md /app/

# Ensure the script is executable
RUN chmod +x /app/RunSAST.py

# Use a built-in unprivileged user
USER nobody

ENTRYPOINT ["python3", "/app/RunSAST.py"]
