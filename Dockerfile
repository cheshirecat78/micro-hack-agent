# micro-hack remote agent
# Minimal Python agent that connects to micro-hack server via WebSocket
# All security tools are installed on-demand via the UI

FROM python:3.11-slim

LABEL maintainer="micro-hack team"
LABEL description="micro-hack remote agent for distributed operations"
LABEL version="1.3.1"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Minimal base - only what's needed for the agent to run and install tools later
# Security tools (nmap, nikto, dirb, etc.) are installed on-demand via the UI
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy agent code
COPY agent.py .

# Run as root to enable:
# - Full nmap capabilities (SYN scans, OS detection)
# - On-demand tool installation (apt-get install)
# The agent is designed to be deployed in isolated containers

# Environment variables that must be set:
# - MICROHACK_SERVER_URL: WebSocket URL (e.g., wss://app.micro-hack.nl)
# - MICROHACK_API_KEY: Your agent API key

# Run the agent
CMD ["python", "-u", "agent.py"]
