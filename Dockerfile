# ============================================================
# Stage 1: Build Python dependencies (includes build-essential)
# ============================================================
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r /tmp/requirements.txt

# ============================================================
# Stage 2: Runtime image (no compilers)
# ============================================================
FROM python:3.11-slim

LABEL org.opencontainers.image.title="MagikUp" \
      org.opencontainers.image.description="PostgreSQL Backup/Restore Web Application" \
      org.opencontainers.image.vendor="fpellizz"

# Install only runtime dependencies (no build-essential)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    groff \
    less \
    postgresql-client \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI v2
RUN curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip -q awscliv2.zip \
    && ./aws/install \
    && rm -rf aws awscliv2.zip

# Install AWS Session Manager Plugin
RUN curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o "session-manager-plugin.deb" \
    && dpkg -i session-manager-plugin.deb \
    && rm session-manager-plugin.deb

# Copy pre-built Python packages from builder stage
COPY --from=builder /install /usr/local

# Create non-root user and directories
RUN useradd -m -u 1000 -s /bin/bash appuser \
    && mkdir -p /app/config /app/logs /backups /tmp \
    && chown -R appuser:appuser /app /backups /tmp

WORKDIR /app

# Copy application files only
COPY --chown=appuser:appuser app/ ./app/
COPY --chown=appuser:appuser templates/ ./templates/
COPY --chown=appuser:appuser static/ ./static/
COPY --chown=appuser:appuser docs/MagikUp_User_Manual.html docs/MagikUp_User_Manual.pdf ./docs/
COPY --chown=appuser:appuser docs/screenshots/ ./docs/screenshots/
COPY --chown=appuser:appuser run.py ./

USER appuser

# Context path for reverse proxy deployment (e.g., /magikup)
ENV ROOT_PATH=""

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# --proxy-headers + --forwarded-allow-ips: trust the reverse proxy's X-Forwarded-*
# so rate limiting and audit logging see the real client IP, not the proxy IP.
# Ingress is restricted at the network layer (NetworkPolicy), so "*" is acceptable.
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info", "--proxy-headers", "--forwarded-allow-ips", "*"]
