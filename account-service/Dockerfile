# syntax=docker/dockerfile:1

###############################################################################
# Build stage: Install dependencies into a virtual environment
###############################################################################
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY account-service/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

###############################################################################
# Runtime stage: Minimal secure runtime with non-root user
###############################################################################
FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create non-root system user
RUN groupadd -r account && useradd -r -g account -u 1001 account

WORKDIR /app

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Copy application source & migrations
COPY account-service/migrations ./migrations
COPY account-service/src ./src
COPY common ./common
COPY account-service/entrypoint.sh ./entrypoint.sh

RUN chmod +x ./entrypoint.sh && chown -R account:account /app

USER account

EXPOSE 8082

ENTRYPOINT ["./entrypoint.sh"]
