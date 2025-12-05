# micro-hack Agent

A lightweight remote agent that connects to your [micro-hack](https://github.com/cheshirecat78/micro-hack) server via WebSocket and executes security scanning commands on demand.

## Features

- 🔌 **WebSocket Connection** - Persistent connection with auto-reconnect
- 🔍 **Network Scanning** - Built-in nmap support for network discovery
- 🛠️ **Tool Management** - Install additional security tools on-demand (nikto, dirb, gobuster, whatweb)
- 🔄 **Self-Update** - Update the agent remotely from the micro-hack UI
- 🌍 **Location Reporting** - Reports public IP and geolocation to server
- 🐳 **Docker Ready** - Multi-platform images for amd64 and arm64 (Raspberry Pi)

## Quick Start

### Option 1: Docker (Recommended)

The fastest way to deploy an agent:

```bash
docker run -d --name micro-hack-agent \
  -e MICROHACK_SERVER_URL=wss://app.micro-hack.nl \
  -e MICROHACK_API_KEY=your_api_key_here \
  --restart unless-stopped \
  cheshirecat78/micro-hack-agent:latest
```

### Option 2: Docker Compose

1. Download the compose file:
```bash
curl -O https://raw.githubusercontent.com/cheshirecat78/micro-hack-agent/main/docker-compose.yml
```

2. Set your environment variables:
```bash
export MICROHACK_SERVER_URL=wss://app.micro-hack.nl
export MICROHACK_API_KEY=your_api_key_here
```

3. Start the agent:
```bash
docker-compose up -d
```

### Option 3: Python (Direct)

For systems without Docker:

```bash
# Download the agent
curl -O https://raw.githubusercontent.com/cheshirecat78/micro-hack-agent/main/agent.py

# Install dependencies
pip install websockets

# Set environment variables
export MICROHACK_SERVER_URL=wss://app.micro-hack.nl
export MICROHACK_API_KEY=your_api_key_here

# Run the agent
python agent.py
```

Or as a one-liner:
```bash
curl -sL https://raw.githubusercontent.com/cheshirecat78/micro-hack-agent/main/agent.py | \
  MICROHACK_SERVER_URL=wss://app.micro-hack.nl \
  MICROHACK_API_KEY=your_api_key_here \
  python3 -
```

### Option 4: Systemd Service

For running as a system service on Linux:

1. Download the agent:
```bash
sudo mkdir -p /opt/micro-hack-agent
sudo curl -o /opt/micro-hack-agent/agent.py \
  https://raw.githubusercontent.com/cheshirecat78/micro-hack-agent/main/agent.py
sudo pip3 install websockets
```

2. Create the service file `/etc/systemd/system/micro-hack-agent.service`:
```ini
[Unit]
Description=micro-hack Remote Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/micro-hack-agent
Environment=MICROHACK_SERVER_URL=wss://app.micro-hack.nl
Environment=MICROHACK_API_KEY=your_api_key_here
ExecStart=/usr/bin/python3 /opt/micro-hack-agent/agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

3. Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable micro-hack-agent
sudo systemctl start micro-hack-agent
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `MICROHACK_SERVER_URL` | WebSocket URL of your micro-hack server | `ws://localhost:8000` |
| `MICROHACK_API_KEY` | Agent API key from micro-hack | (required) |
| `MICROHACK_AGENT_UPDATE_URL` | URL for agent self-updates | GitHub raw URL |

## Getting an API Key

1. Log in to your micro-hack instance
2. Go to **Settings** > **Agents**
3. Click **Create Agent Key**
4. Copy the generated key (starts with `mh_agent_`)

## Supported Commands

| Command | Description |
|---------|-------------|
| `ping` | Health check |
| `info` | Get agent system info |
| `nmap` | Run network scans |
| `check_tools` | Check installed security tools |
| `install_tool` | Install a security tool (nmap, nikto, dirb, gobuster, whatweb) |
| `update_agent` | Self-update to latest version |
| `capabilities` | List agent capabilities |

## Security Notes

- The agent runs as **root** by default to enable full nmap capabilities and on-demand tool installation
- Deploy agents in **isolated environments** (containers, VMs, or dedicated hosts)
- API keys should be kept **secret** - they allow full control of the agent
- The agent only accepts commands from the authenticated micro-hack server

## Building from Source

```bash
git clone https://github.com/cheshirecat78/micro-hack-agent.git
cd micro-hack-agent
docker build -t micro-hack-agent .
```

## Multi-Platform Support

Pre-built images are available for:
- `linux/amd64` - Standard x86_64 servers
- `linux/arm64` - Raspberry Pi 4/5, ARM servers

## Troubleshooting

### Agent won't connect
- Verify `MICROHACK_SERVER_URL` uses the correct protocol (`wss://` for HTTPS, `ws://` for HTTP)
- Check that the API key is valid and not disabled
- Ensure network connectivity to the server

### Tools won't install
- The agent must run as root for tool installation
- If using Docker, the container runs as root by default
- Check that the system has internet access for package downloads

### View logs
```bash
# Docker
docker logs -f micro-hack-agent

# Systemd
journalctl -u micro-hack-agent -f
```

## License

MIT License - see [micro-hack](https://github.com/cheshirecat78/micro-hack) for details.
