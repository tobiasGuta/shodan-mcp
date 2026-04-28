# ─────────────────────────────────────────────────────────────────
# Shodan MCP Server
# Lightweight Python image — no binary build stage needed
# since Shodan queries are API-based (no local binary required)
# ─────────────────────────────────────────────────────────────────
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py scope_validator.py shodan_client.py ./

# Shared volume with h1-scope-watcher — mounted at runtime
VOLUME ["/data/snapshots"]

# ── Environment variables ────────────────────────────────────────
# SHODAN_API_KEY  : Required — your Shodan API key
# SNAPSHOTS_DIR   : Path to H1 scope JSON files (default /data/snapshots)
ENV SNAPSHOTS_DIR=/data/snapshots
ENV SHODAN_API_KEY=""

CMD ["python", "main.py"]
