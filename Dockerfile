# CLOUDRANGE -- runs the attack chain + detector. Mock mode needs no AWS creds.
FROM python:3.11-slim

LABEL org.opencontainers.image.title="CLOUDRANGE"
LABEL org.opencontainers.image.description="Cloud attack-and-detect range (IAM privesc graph + SARIF auditor)."
LABEL org.opencontainers.image.authors="Vishnu Kosuri"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first for layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project (package, fixtures, schemas, tests, terraform).
COPY . .

# Install the CLI entry point as an *editable* install so the top-level
# fixtures/ and schemas/ directories (siblings of the package, per the spec's
# layout) stay resolvable at runtime. The source already lives at /app via COPY.
RUN pip install --no-cache-dir -e .

# Run as non-root.
RUN useradd --create-home cloudrange
USER cloudrange

# Default: show the offline detection report against the bundled fixture.
ENTRYPOINT ["cloudrange"]
CMD ["detect", "--mock"]
