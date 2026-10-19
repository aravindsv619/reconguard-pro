# ReconGuard Pro — container image
# Subdomain Enumeration, Takeover Risk & Lookalike Domain Recon (keyless).
#
# Build:  docker build -t reconguard-pro .
# Run:    docker run --rm -p 8080:8080 reconguard-pro
# Then open http://localhost:8080
#
# Multi-stage build keeps the final image small: deps are installed into a
# virtualenv in the builder, then copied into a slim runtime that only carries
# what is needed at run time (plus `dig` for the DNS-records feature).

# ---------- builder ----------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Create an isolated venv so we can copy it cleanly into the runtime stage.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install runtime dependencies only (requirements.txt is the runtime set;
# dev/test tooling lives in requirements-dev.txt and is intentionally excluded).
COPY requirements.txt .
RUN pip install -r requirements.txt

# ---------- runtime ----------
FROM python:3.12-slim AS runtime

# `dig` (dnsutils / bind9-dnsutils) powers the authoritative DNS-records and
# CNAME lookups. Without it the app falls back to the stdlib resolver, but dig
# gives accurate per-type records, so we install it. Clean apt lists after.
RUN apt-get update \
    && apt-get install -y --no-install-recommends dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user (security hardening — no reason for root in a web app).
RUN useradd --create-home --uid 10001 appuser

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Bind to all interfaces INSIDE the container so the mapped port is
    # reachable from the host. The container boundary is the isolation here;
    # for public deployment put an authenticating reverse proxy in front
    # (the app itself has no authentication by design).
    SUBRECON_HOST=0.0.0.0 \
    # CORS is scoped to localhost by default; override for your own origin.
    SUBRECON_CORS_ORIGINS=http://localhost:8080,http://127.0.0.1:8080

WORKDIR /app

# Copy the prebuilt venv and the application code.
COPY --from=builder /opt/venv /opt/venv
COPY main.py ./
COPY static/ ./static/
COPY wordlists/ ./wordlists/

USER appuser

EXPOSE 8080

# Lightweight container healthcheck hitting the app's /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=4).status==200 else 1)" || exit 1

# `python main.py` reads SUBRECON_HOST (0.0.0.0 above) and serves on :8080.
CMD ["python", "main.py"]
