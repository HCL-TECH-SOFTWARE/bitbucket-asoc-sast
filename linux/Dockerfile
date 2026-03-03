FROM python:3.11-slim@sha256:c8271b1f627d0068857dce5b53e14a9558603b527e46f1f901722f935b786a39

COPY requirements.txt /
RUN pip install --no-cache-dir -r /requirements.txt

# Set proper working directory with correct permissions
RUN mkdir -p /app && chown -R nobody:nogroup /app
WORKDIR /app

# Create a writable home directory for the nobody user
# (default HOME=/nonexistent which does not exist, causing AppScan to fail)
RUN mkdir -p /home/nobody && chown -R nobody:nogroup /home/nobody
ENV HOME=/home/nobody

COPY --chown=nobody:nogroup pipe /app/
COPY --chown=nobody:nogroup LICENSE pipe.yml README.md /app/

# Ensure the script is executable
RUN chmod +x /app/RunSAST.py

# Use a built-in unprivileged user
USER nobody

ENTRYPOINT ["python3", "/app/RunSAST.py"]
