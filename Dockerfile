# ==========================================
# Stage 1: Build Dependencies
# ==========================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies required for compiling C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ==========================================
# Stage 2: Minimal Distroless / Hardened Runtime
# ==========================================
FROM python:3.11-slim AS runner

WORKDIR /app

# Security: Create non-root system user and group
RUN groupadd -g 10001 gateway && \
    useradd -u 10001 -g gateway -s /bin/bash -m gateway

# Copy installed python wheels from builder stage
COPY --from=builder /root/.local /home/gateway/.local

# Copy application source code
COPY --chown=gateway:gateway gateway.py /app/gateway.py

# Set runtime paths and python buffer settings
ENV PATH=/home/gateway/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001:10001

EXPOSE 4000

# Healthcheck targeting internal endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:4000/health').read()" || exit 1

ENTRYPOINT ["uvicorn", "gateway:app", "--host", "0.0.0.0", "--port", "4000"]

