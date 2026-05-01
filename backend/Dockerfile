FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    git \
    netcat-openbsd \
    openssh-client \
    procps \
    gcc \
    g++ \
    make \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python tools
RUN pip install --no-cache-dir gunicorn

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create necessary directories
RUN mkdir -p reports sessions uploads logs

# Create non-root user
RUN useradd -m -s /bin/bash redteam && \
    chown -R redteam:redteam /app

USER redteam

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8888/api/health || exit 1

CMD ["gunicorn", "--worker-class", "eventlet", "-w", "2", "--bind", "0.0.0.0:8888", "app:app"]