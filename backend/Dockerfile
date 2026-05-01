FROM python:3.11-slim

WORKDIR /app

# Update and install only available packages
RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    nikto \
    dnsutils \
    curl \
    wget \
    netcat-openbsd \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based tools (gobuster, ffuf, etc.) using go
RUN apt-get update && apt-get install -y golang-go && \
    go install github.com/OJ/gobuster/v3@latest && \
    cp /root/go/bin/gobuster /usr/local/bin/ && \
    apt-get remove -y golang-go && apt-get autoremove -y && \
    rm -rf /root/go /var/lib/apt/lists/*

# Install python tools
RUN pip install --no-cache-dir \
    impacket \
    crackmapexec

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p sessions generated_reports

EXPOSE 5000

CMD ["python", "app.py"]
