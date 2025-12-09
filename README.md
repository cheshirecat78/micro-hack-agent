# micro-hack remote agent

A lightweight Docker agent that connects to your micro-hack server via WebSocket and executes commands on demand.

## Overview

The micro-hack agent allows you to deploy lightweight agents across your infrastructure that maintain a persistent WebSocket connection to your micro-hack server. You can then send commands to these agents remotely.

## Quick Start

### 1. Create an Agent API Key

In micro-hack, go to **Settings → Agents** and create a new agent API key.

Save the API key - it's only shown once!

### 2. Deploy the Agent (One-Liner)

```bash
curl -sL https://raw.githubusercontent.com/cheshirecat78/micro-hack/main/agent/deploy.sh | bash -s -- --key YOUR_API_KEY
```

That's it! The script will:
- ✅ Detect if Docker is available
- ✅ If Docker: Deploy in a fully-capable container with network scanning permissions
- ✅ If no Docker: Create isolated Python environment and run natively
- ✅ Set up auto-restart on system boot

### Alternative: Manual Docker Deployment

If you prefer manual control:

```yaml
version: '3.8'

services:
  micro-hack-agent:
    image: cheshirecat78/micro-hack-agent:latest
    container_name: micro-hack-agent
    restart: unless-stopped
    privileged: true
    network_mode: host
    environment:
      - MICROHACK_SERVER_URL=wss://app.micro-hack.nl
      - MICROHACK_API_KEY=mh_agent_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

```bash
docker-compose up -d
```

### 3. Verify Connection

Check the agent logs:

```bash
# Docker deployment
docker logs -f micro-hack-agent

# Native deployment
~/.μhack-agent/logs/agent.log
# or
journalctl -u micro-hack-agent -f
```

You should see:
```
[2024-01-01 12:00:00] [INFO] micro-hack agent v1.0.0 starting...
[2024-01-01 12:00:00] [INFO] Connecting to wss://app.micro-hack.nl...
[2024-01-01 12:00:00] [INFO] Connected to server!
[2024-01-01 12:00:00] [INFO] Registered as hostname (Linux 5.15.0)
```

## Deploy Script Options

The `deploy.sh` script provides full lifecycle management:

```bash
# Deploy with Docker (auto-detected)
./deploy.sh --key mh_agent_xxxxxxxxxxxx

# Force native Python deployment (no Docker)
./deploy.sh --key mh_agent_xxxxxxxxxxxx --native

# Use custom server
./deploy.sh --key mh_agent_xxxxxxxxxxxx --server wss://my-server.com

# Check agent status
./deploy.sh --status

# View logs
./deploy.sh --logs

# Update to latest version
./deploy.sh --update

# Stop the agent
./deploy.sh --stop

# Completely uninstall
./deploy.sh --uninstall
```

## API Endpoints

### Agent Keys Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agents/keys` | Create a new agent API key |
| GET | `/api/agents/keys` | List all your agent keys |
| GET | `/api/agents/keys/{id}` | Get details of a specific key |
| PATCH | `/api/agents/keys/{id}` | Update key (name, permissions, status) |
| DELETE | `/api/agents/keys/{id}` | Delete an agent key |
| POST | `/api/agents/keys/{id}/regenerate` | Regenerate the API key |

### Agent Status & Commands

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/agents/connected` | List all connected agents |
| POST | `/api/agents/keys/{id}/ping` | Ping an agent |
| POST | `/api/agents/keys/{id}/command` | Send a command to an agent |

## Supported Commands

### ping
Check if the agent is alive and responsive.

```json
{
  "command": "ping"
}
```

### info
Get agent system information.

```json
{
  "command": "info"
}
```

Response:
```json
{
  "agent_id": "uuid",
  "hostname": "server1",
  "ip": "192.168.1.100",
  "os": "Linux 5.15.0",
  "version": "1.0.0",
  "python_version": "3.11.4"
}
```

### echo
Echo back a message (useful for testing).

```json
{
  "command": "echo",
  "data": {
    "message": "Hello, agent!"
  }
}
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MICROHACK_SERVER_URL` | Yes | WebSocket URL (ws:// or wss://) |
| `MICROHACK_API_KEY` | Yes | Your agent API key from MicroHack |
| `MICROHACK_SKIP_UPDATE` | No | Set to "1" or "true" to skip auto-update |
| `MICROHACK_SUPERVISED` | No | Set to "1" when running under supervisor |
| `MICROHACK_HTTP_FALLBACK` | No | Set to "1" to enable HTTP polling fallback |
| `MICROHACK_HTTP_POLL_INTERVAL` | No | HTTP poll interval in seconds (default: 5) |

## Supervisor Mode (Recommended)

For production deployments, use `supervisor.py` instead of running `agent.py` directly.
The supervisor provides:

- **Process Management**: Spawns and monitors agent.py as a subprocess
- **Graceful Restarts**: Handles restart/update signals via exit codes
- **Auto-Restart**: Restarts agent on crashes with exponential backoff
- **Update Support**: Downloads and applies updates, then restarts

### Using the Supervisor

```bash
# Run supervisor (it will spawn agent.py)
python supervisor.py

# Or with Docker (recommended)
docker run -d \
  -e MICROHACK_SERVER_URL=wss://app.micro-hack.nl \
  -e MICROHACK_API_KEY=mh_agent_xxx \
  cheshirecat78/micro-hack-agent:latest python supervisor.py
```

### Exit Codes

When running under supervisor, agent.py uses these exit codes:

| Code | Meaning |
|------|---------|
| 0 | Normal exit, don't restart |
| 42 | Restart requested |
| 43 | Update and restart |
| 44 | Redeploy (fresh download) |
| 99 | Fatal error, don't restart |

## HTTP Fallback (When WebSocket is Blocked)

If WebSocket connections are blocked by a firewall/proxy, you can enable HTTP polling:

```bash
MICROHACK_HTTP_FALLBACK=1 python supervisor.py
```

This polls the server every 5 seconds (configurable) for pending commands.
Less efficient than WebSocket but works through most corporate firewalls.

**Note**: The backend needs additional endpoints for HTTP fallback (see below).

## Building Locally

```bash
cd agent
docker build -t microhack-agent:local .
```

## Running Without Docker

```bash
pip install -r requirements.txt
export MICROHACK_SERVER_URL=ws://localhost:8000
export MICROHACK_API_KEY=mh_agent_your_key_here
python agent.py
```

## WebSocket Protocol

### Agent → Server Messages

**Register** (sent after connection):
```json
{
  "type": "register",
  "data": {
    "agent_id": "uuid",
    "hostname": "server1",
    "ip": "192.168.1.100",
    "version": "1.0.0",
    "os": "Linux 5.15.0",
    "capabilities": ["ping", "info", "execute"]
  }
}
```

## Versioning

The agent version is stored in `agent/agent.py` and optionally overridden by `agent/VERSION`.
Use the `scripts/bump_agent_version.py` utility to bump the semantic version (patch, minor, major) and it will update both files.

Example:

```bash
# Bump the patch version
python3 ../scripts/bump_agent_version.py --part patch

# Bump the minor version
python3 ../scripts/bump_agent_version.py --part minor
```

When building the Docker image, GitHub Actions will pass the version to the build and label the image accordingly.

**Heartbeat** (sent periodically):
```json
{
  "type": "heartbeat",
  "status": {
    "uptime": "running",
    "timestamp": "2024-01-01T12:00:00Z"
  }
}
```

**Response** (to server commands):
```json
{
  "type": "response",
  "command_id": "uuid",
  "success": true,
  "data": { ... }
}
```

### Server → Agent Messages

**Connected** (after successful auth):
```json
{
  "type": "connected",
  "message": "Agent connection established",
  "agent_key_id": "uuid",
  "permissions": ["ping", "info"],
  "timestamp": "2024-01-01T12:00:00Z"
}
```

**Command** (request from server):
```json
{
  "type": "command",
  "command_id": "uuid",
  "command": "ping",
  "data": {},
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## Features

- ✅ Automatic reconnection with exponential backoff
- ✅ Heartbeat to maintain connection
- ✅ Secure API key authentication
- ✅ Permission-based command filtering
- ✅ Lightweight Docker image
- ✅ Non-root container execution
- ✅ Cross-platform support (Linux, Windows, macOS)

## Security Considerations

1. **API Keys**: Store API keys securely. They can only be viewed once when created.
2. **TLS**: Always use `wss://` in production for encrypted connections.
3. **Permissions**: Limit agent permissions to only what's needed.
4. **Network**: Consider using `network_mode: host` only when network scanning is needed.

## Troubleshooting

### Agent won't connect

1. Check the API key is correct
2. Verify the server URL (ws:// vs wss://)
3. Check firewall allows outbound WebSocket connections
4. Look at agent logs: `docker-compose logs -f`

### Connection keeps dropping

1. Check network stability
2. The agent will automatically reconnect
3. Heartbeats are sent every 30 seconds

### Permission denied errors

1. Check the agent key's permissions list
2. Update permissions via the API if needed

## License

MIT License - See main MicroHack repository.
