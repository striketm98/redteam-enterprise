FROM python:3.11-slim

WORKDIR /app

# Install only available system packages
RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    dnsutils \
    curl \
    wget \
    netcat-openbsd \
    openssh-client \
    procps \
    less \
    && rm -rf /var/lib/apt/lists/*

# Install nikto from source (since it's not in repos)
RUN apt-get update && apt-get install -y git perl && \
    git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto && \
    apt-get remove -y git && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create necessary directories
RUN mkdir -p sessions generated_reports

EXPOSE 5000

CMD ["python", "app.py"]
