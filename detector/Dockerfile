FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for iptables
RUN apt-get update && apt-get install -y --no-install-recommends     iptables     curl     && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all detector files
COPY . .

# Create log directory
RUN mkdir -p /var/log/detector

CMD ["python", "-u", "main.py"]
