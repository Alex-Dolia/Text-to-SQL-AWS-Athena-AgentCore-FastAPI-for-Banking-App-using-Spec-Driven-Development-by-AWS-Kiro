FROM python:3.11-slim AS base

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definition
COPY pyproject.toml ./

# Install Python dependencies
RUN pip install --no-cache-dir .

# Copy application code
COPY . .

# Run as non-root user
RUN useradd --create-home appuser
USER appuser

# Agent does not expose HTTP port directly — communicates via AgentCore Runtime
# Health monitored by AgentCore Runtime orchestration

CMD ["python", "-m", "chatbot.agent"]
