FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    gobuster \
    nikto \
    whatweb \
    enum4linux \
    smbclient \
    crackmapexec \
    sshpass \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create necessary directories
RUN mkdir -p sessions generated_reports

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]