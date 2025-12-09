#!/usr/bin/env python3
"""
micro-hack remote agent

A lightweight, self-bootstrapping agent that connects to the micro-hack server 
via WebSocket and executes commands on demand (including nmap scans).

Features:
- Auto-installs its own dependencies (websockets, psutil)
- Auto-updates to latest version on startup
- Zero external dependencies required (just Python 3.7+)

Usage:
    Set environment variables:
    - MICROHACK_SERVER_URL: WebSocket URL (e.g., ws://localhost:8000 or wss://app.micro-hack.nl)
    - MICROHACK_API_KEY: Your agent API key from micro-hack
    
    Run directly:
    curl -sL https://raw.githubusercontent.com/cheshirecat78/micro-hack-agent/main/agent.py | \
      MICROHACK_SERVER_URL=wss://app.micro-hack.nl MICROHACK_API_KEY=your-key python3 -
"""
import os
import sys
import json
import socket
import platform
import subprocess
from datetime import datetime

# =============================================================================
# SELF-BOOTSTRAPPING: Install dependencies if missing
# =============================================================================

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

try:
    import websockets
except ImportError:
    install("websockets")
    import websockets

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    try:
        install("psutil")
        import psutil
        PSUTIL_AVAILABLE = True
    except:
        PSUTIL_AVAILABLE = False

# =============================================================================
# IMPORTS (now safe after bootstrap)
# =============================================================================

import uuid
import asyncio
import signal
import shutil
from typing import Optional

# Import websocket exceptions
from websockets.exceptions import ConnectionClosed, InvalidStatusCode

# =============================================================================
# AGENT VERSION & AUTO-UPDATE
# =============================================================================

VERSION = "1.10.20"
try:
    # Look for an agent/VERSION file to override the baked-in version. This
    # allows us to bump the version file and let the code always read the
    # current value.
    import os as _os
    version_path = _os.path.join(_os.path.dirname(__file__), 'VERSION')
    if _os.path.exists(version_path):
        with open(version_path, 'r') as vf:
            v = vf.read().strip()
            if v:
                VERSION = v
except Exception:
    pass

# Agent update URL (raw Python file)
# Priority: 1) MICROHACK_AGENT_UPDATE_URL env, 2) derived from server URL, 3) hardcoded fallback
def _get_agent_update_url():
    """Determine the agent update URL"""
    # Explicit update URL takes priority
    if os.environ.get("MICROHACK_AGENT_UPDATE_URL"):
        return os.environ.get("MICROHACK_AGENT_UPDATE_URL")
    
    # Derive from server URL if available
    # Server URL is WebSocket URL like wss://host/ws/agent or ws://host:port/ws/agent
    server_url = os.environ.get("MICROHACK_SERVER_URL", "")
    if server_url:
        # Convert wss:// to https:// or ws:// to http://
        if server_url.startswith("wss://"):
            base = "https://" + server_url[6:]
        elif server_url.startswith("ws://"):
            base = "http://" + server_url[5:]
        else:
            base = server_url
        
        # Remove /ws/agent or any path suffix to get the API base
        # e.g. wss://host.com/ws/agent -> https://host.com
        if "/ws/agent" in base:
            base = base.split("/ws/agent")[0]
        elif "/ws" in base:
            base = base.split("/ws")[0]
        
        base = base.rstrip('/')
        # The backend endpoint is at /api/agents/agent.py
        return f"{base}/api/agents/agent.py"
    
    # Fallback to GitHub (may not have latest)
    return "https://raw.githubusercontent.com/cheshirecat78/micro-hack/main/agent/agent.py"

AGENT_UPDATE_URL = _get_agent_update_url()

# Skip auto-update flag (for development)
SKIP_AUTO_UPDATE = os.environ.get("MICROHACK_SKIP_UPDATE", "").lower() in ("1", "true", "yes")


def auto_update_on_startup():
    """
    Check for updates and restart with new version if available.
    This runs BEFORE the agent starts, ensuring we always run the latest version.
    """
    if SKIP_AUTO_UPDATE:
        print("[UPDATE] Skipping auto-update (MICROHACK_SKIP_UPDATE is set)", flush=True)
        return
    
    # Don't update if running from stdin (piped execution)
    if not os.path.isfile(__file__) or __file__ == '<stdin>':
        print("[UPDATE] Running from stdin/pipe, skipping auto-update", flush=True)
        return
    
    print(f"[UPDATE] Checking for updates (current: v{VERSION})...", flush=True)
    print(f"[UPDATE] Update URL: {AGENT_UPDATE_URL}", flush=True)
    
    try:
        import urllib.request
        import tempfile
        
        # Download latest version
        with urllib.request.urlopen(AGENT_UPDATE_URL, timeout=15) as resp:
            new_code = resp.read().decode('utf-8')
        
        # Validate that we got actual Python code, not an error page
        if not new_code.strip().startswith(('#', 'import', 'from', '"""', "'''")):
            # Check for common error responses
            if '404' in new_code.lower() or 'not found' in new_code.lower():
                print(f"[UPDATE] Remote URL returned 404, skipping update", flush=True)
                return
            if '<html' in new_code.lower() or '<!doctype' in new_code.lower():
                print(f"[UPDATE] Remote URL returned HTML instead of Python, skipping update", flush=True)
                return
        
        # Extract version from new code
        new_version = None
        for line in new_code.split('\n'):
            if line.strip().startswith('VERSION = '):
                # Handle both double and single quoted version strings
                try:
                    new_version = line.split('"')[1]
                except IndexError:
                    new_version = line.split("'")[1]
                break
        
        if not new_version:
            print("[UPDATE] Could not parse version from remote, skipping update", flush=True)
            return
        
        # Compare versions (simple string comparison works for semantic versioning)
        if new_version == VERSION:
            print(f"[UPDATE] Already running latest version (v{VERSION})", flush=True)
            return
        
        # Check if newer (compare version tuples)
        def version_tuple(v):
            return tuple(map(int, v.split('.')))
        
        try:
            if version_tuple(new_version) <= version_tuple(VERSION):
                print(f"[UPDATE] Local version (v{VERSION}) is same or newer than remote (v{new_version})", flush=True)
                return
        except ValueError:
            # If version parsing fails, do string comparison
            pass
        
        print(f"[UPDATE] New version available: v{VERSION} → v{new_version}", flush=True)
        
        # Get current script path
        current_script = os.path.abspath(__file__)
        
        # Backup current script
        backup_path = current_script + ".backup"
        shutil.copy2(current_script, backup_path)
        print(f"[UPDATE] Backed up to {backup_path}", flush=True)
        
        # Write new code
        with open(current_script, 'w') as f:
            f.write(new_code)
        
        print(f"[UPDATE] Updated to v{new_version}, restarting...", flush=True)
        
        # Restart the agent with the new code
        # os.execv replaces the current process entirely - most reliable method
        os.execv(sys.executable, [sys.executable, current_script] + sys.argv[1:])
        
    except Exception as e:
        print(f"[UPDATE] Update check failed: {e} (continuing with current version)", flush=True)


# Run auto-update before anything else
auto_update_on_startup()

# =============================================================================
# TOOL DEFINITIONS
# =============================================================================

# Supported tools and their install commands (Debian/Ubuntu based)
# Note: Some tools require additional setup or alternative installation methods
TOOL_INSTALL_COMMANDS = {
    "iputils-ping": {
        "check": "ping",
        "install": ["apt-get", "install", "-y", "iputils-ping"],
        "uninstall": ["apt-get", "remove", "-y", "iputils-ping"],
        "description": "ICMP ping utility",
        "size": "0.1 MB",
        "pre_install": None
    },
    "nmap": {
        "check": "nmap",
        "install": ["apt-get", "install", "-y", "nmap"],
        "uninstall": ["apt-get", "remove", "-y", "nmap"],
        "description": "Network scanner",
        "size": "5.2 MB",
        "pre_install": None
    },
    "nikto": {
        "check": "nikto",
        # nikto is in Debian, but might need to enable non-free or use git
        "install": ["apt-get", "install", "-y", "nikto"],
        "uninstall": ["apt-get", "remove", "-y", "nikto"],
        "install_alt": ["git", "clone", "https://github.com/sullo/nikto.git", "/opt/nikto"],
        "post_install_alt": ["ln", "-sf", "/opt/nikto/program/nikto.pl", "/usr/local/bin/nikto"],
        "description": "Web server scanner",
        "size": "2.1 MB",
        "pre_install": None
    },
    "dirb": {
        "check": "dirb",
        "install": ["apt-get", "install", "-y", "dirb"],
        "uninstall": ["apt-get", "remove", "-y", "dirb"],
        "description": "Web content scanner",
        "size": "1.8 MB",
        "pre_install": None
    },
    "gobuster": {
        "check": "gobuster",
        "install": ["apt-get", "install", "-y", "gobuster"],
        "uninstall": ["apt-get", "remove", "-y", "gobuster"],
        "description": "Directory/file brute-forcer",
        "size": "7.5 MB",
        "pre_install": None
    },
    "whatweb": {
        "check": "whatweb",
        "install": ["apt-get", "install", "-y", "whatweb"],
        "uninstall": ["apt-get", "remove", "-y", "whatweb"],
        "description": "Web technology scanner",
        "size": "12 MB",
        "pre_install": None
    },
    "enum4linux": {
        "check": "enum4linux",
        "install": ["apt-get", "install", "-y", "enum4linux"],
        "uninstall": ["apt-get", "remove", "-y", "enum4linux"],
        "install_alt": ["git", "clone", "https://github.com/CiscoCXSecurity/enum4linux.git", "/opt/enum4linux"],
        "post_install_alt": ["ln", "-sf", "/opt/enum4linux/enum4linux.pl", "/usr/local/bin/enum4linux"],
        "description": "SMB/Samba enumeration tool",
        "size": "0.5 MB",
        "pre_install": ["apt-get", "install", "-y", "smbclient", "ldap-utils", "perl"]
    },
    "smbclient": {
        "check": "smbclient",
        "install": ["apt-get", "install", "-y", "smbclient"],
        "uninstall": ["apt-get", "remove", "-y", "smbclient"],
        "description": "SMB protocol client",
        "size": "8.4 MB",
        "pre_install": None
    },
    "testssl": {
        "check": "testssl",
        "install": ["apt-get", "install", "-y", "testssl.sh"],
        "uninstall": ["apt-get", "remove", "-y", "testssl.sh"],
        "install_alt": ["git", "clone", "--depth", "1", "https://github.com/drwetter/testssl.sh.git", "/opt/testssl"],
        "post_install_alt": ["ln", "-sf", "/opt/testssl/testssl.sh", "/usr/local/bin/testssl"],
        "description": "TLS/SSL encryption testing",
        "size": "4.2 MB",
        "pre_install": None
    },
    "hydra": {
        "check": "hydra",
        "install": ["apt-get", "install", "-y", "hydra"],
        "uninstall": ["apt-get", "remove", "-y", "hydra"],
        "description": "Network login brute-forcer",
        "size": "3.1 MB",
        "pre_install": None
    },
    "sqlmap": {
        "check": "sqlmap",
        "install": ["apt-get", "install", "-y", "sqlmap"],
        "uninstall": ["apt-get", "remove", "-y", "sqlmap"],
        "description": "SQL injection detection",
        "size": "15 MB",
        "pre_install": None
    },
    "wpscan": {
        "check": "wpscan",
        "install": ["gem", "install", "wpscan"],
        "uninstall": ["gem", "uninstall", "-x", "wpscan"],
        "description": "WordPress vulnerability scanner",
        "size": "25 MB",
        "pre_install": ["apt-get", "install", "-y", "ruby", "ruby-dev", "build-essential", "libcurl4-openssl-dev", "zlib1g-dev"]
    },
    "ffuf": {
        "check": "ffuf",
        "install": ["apt-get", "install", "-y", "ffuf"],
        "uninstall": ["apt-get", "remove", "-y", "ffuf"],
        "install_alt": ["go", "install", "github.com/ffuf/ffuf/v2@latest"],
        "description": "Fast web fuzzer",
        "size": "8.3 MB",
        "pre_install": None
    },
    "masscan": {
        "check": "masscan",
        "install": ["apt-get", "install", "-y", "masscan"],
        "uninstall": ["apt-get", "remove", "-y", "masscan"],
        "description": "High-speed port scanner",
        "size": "1.2 MB",
        "pre_install": None
    },
    "tcpdump": {
        "check": "tcpdump",
        "install": ["apt-get", "install", "-y", "tcpdump"],
        "uninstall": ["apt-get", "remove", "-y", "tcpdump"],
        "description": "Packet analyzer",
        "size": "1.5 MB",
        "pre_install": None
    },
    "whois": {
        "check": "whois",
        "install": ["apt-get", "install", "-y", "whois"],
        "uninstall": ["apt-get", "remove", "-y", "whois"],
        "description": "Domain registration lookup",
        "size": "0.3 MB",
        "pre_install": None
    },
    "dig": {
        "check": "dig",
        "install": ["apt-get", "install", "-y", "dnsutils"],
        "uninstall": ["apt-get", "remove", "-y", "dnsutils"],
        "description": "DNS lookup utility",
        "size": "2.8 MB",
        "pre_install": None
    },
    "curl": {
        "check": "curl",
        "install": ["apt-get", "install", "-y", "curl"],
        "uninstall": ["apt-get", "remove", "-y", "curl"],
        "description": "HTTP client and transfer tool",
        "size": "0.8 MB",
        "pre_install": None
    },
    "wget": {
        "check": "wget",
        "install": ["apt-get", "install", "-y", "wget"],
        "uninstall": ["apt-get", "remove", "-y", "wget"],
        "description": "Network file downloader",
        "size": "3.2 MB",
        "pre_install": None
    },
    "netcat": {
        "check": "nc",
        "install": ["apt-get", "install", "-y", "netcat-openbsd"],
        "uninstall": ["apt-get", "remove", "-y", "netcat-openbsd"],
        "description": "Network connection utility",
        "size": "0.1 MB",
        "pre_install": None
    },
    "traceroute": {
        "check": "traceroute",
        "install": ["apt-get", "install", "-y", "traceroute"],
        "uninstall": ["apt-get", "remove", "-y", "traceroute"],
        "description": "Network path tracer",
        "size": "0.2 MB",
        "pre_install": None
    },
    "openssl": {
        "check": "openssl",
        "install": ["apt-get", "install", "-y", "openssl"],
        "uninstall": ["apt-get", "remove", "-y", "openssl"],
        "description": "SSL/TLS toolkit",
        "size": "1.4 MB",
        "pre_install": None
    },
    "sslscan": {
        "check": "sslscan",
        "install": ["apt-get", "install", "-y", "sslscan"],
        "uninstall": ["apt-get", "remove", "-y", "sslscan"],
        "description": "SSL/TLS vulnerability scanner",
        "size": "0.6 MB",
        "pre_install": None
    },
    "ssh-audit": {
        "check": "ssh-audit",
        "install": ["pip3", "install", "ssh-audit"],
        "uninstall": ["pip3", "uninstall", "-y", "ssh-audit"],
        "description": "SSH server security auditing",
        "size": "0.5 MB",
        "pre_install": ["apt-get", "install", "-y", "python3-pip"]
    },
    "holehe": {
        "check": "holehe",
        "install": ["pip3", "install", "holehe"],
        "uninstall": ["pip3", "uninstall", "-y", "holehe"],
        "description": "Email OSINT - check email registrations",
        "size": "2 MB",
        "pre_install": ["apt-get", "install", "-y", "python3-pip"]
    },
    "phoneinfoga": {
        "check": "phoneinfoga",
        "install": ["bash", "-c", "wget -qO /tmp/phoneinfoga.tar.gz https://github.com/sundowndev/phoneinfoga/releases/latest/download/phoneinfoga_Linux_x86_64.tar.gz && tar -xzf /tmp/phoneinfoga.tar.gz -C /usr/local/bin phoneinfoga && chmod +x /usr/local/bin/phoneinfoga && rm /tmp/phoneinfoga.tar.gz"],
        "uninstall": ["rm", "-f", "/usr/local/bin/phoneinfoga"],
        "description": "Phone number OSINT tool",
        "size": "15 MB",
        "pre_install": ["apt-get", "install", "-y", "wget"]
    },
    "maigret": {
        "check": "maigret",
        "install": ["pip3", "install", "maigret"],
        "uninstall": ["pip3", "uninstall", "-y", "maigret"],
        "description": "Username OSINT - check social networks",
        "size": "10 MB",
        "pre_install": ["apt-get", "install", "-y", "python3-pip"]
    },
    "shell_pty": {
        "check": "tmux",
        "install": ["apt-get", "install", "-y", "tmux"],
        "uninstall": ["apt-get", "remove", "-y", "tmux"],
        "description": "Full PTY shell session support (tmux)",
        "size": "0.2 MB",
        "pre_install": None
    },
    "chromium": {
        "check": "chromium",
        "install": ["apt-get", "install", "-y", "chromium"],
        "uninstall": ["apt-get", "remove", "-y", "chromium"],
        "install_alt": ["apt-get", "install", "-y", "chromium-browser"],
        "description": "Headless browser for screenshots",
        "size": "150 MB",
        "pre_install": None
    }
}

# Configuration from environment
SERVER_URL = os.environ.get("MICROHACK_SERVER_URL", "ws://localhost:8000")
API_KEY = os.environ.get("MICROHACK_API_KEY", "")

# Reconnection settings
RECONNECT_DELAY = 5  # seconds
MAX_RECONNECT_DELAY = 60  # max backoff
HEARTBEAT_INTERVAL = 30  # seconds
PING_INTERVAL = 25  # seconds for WebSocket ping


# =============================================================================
# LOCAL WEBSERVER FOR AGENT CONTROL
# =============================================================================

class AgentLocalWebServer:
    """
    Local web server for agent control and monitoring.
    Provides a micro-hack styled web UI to control the agent locally.
    """
    
    HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>μ micro-hack agent</title>
    <style>
        :root {
            --bg-dark: #0a0a0f;
            --bg-card: #12121a;
            --border: #1e1e2d;
            --cyan: #00d4ff;
            --purple: #a855f7;
            --green: #22c55e;
            --red: #ef4444;
            --text: #e5e7eb;
            --text-muted: #6b7280;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            min-height: 100vh;
        }
        .container { max-width: 800px; margin: 0 auto; padding: 2rem; }
        .header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
        }
        .logo {
            font-size: 2rem;
            font-weight: bold;
            background: linear-gradient(135deg, var(--cyan), var(--purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .status-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .status-connected { background: rgba(34, 197, 94, 0.2); color: var(--green); border: 1px solid var(--green); }
        .status-disconnected { background: rgba(239, 68, 68, 0.2); color: var(--red); border: 1px solid var(--red); }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        .card h2 {
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--cyan);
        }
        .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; }
        .stat {
            background: rgba(255,255,255,0.02);
            padding: 1rem;
            border-radius: 0.5rem;
        }
        .stat-label { font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.25rem; }
        .stat-value { font-size: 1.125rem; font-weight: 600; font-family: monospace; }
        .btn {
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            border: none;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary { background: var(--cyan); color: #000; }
        .btn-primary:hover { filter: brightness(1.1); }
        .btn-danger { background: var(--red); color: #fff; }
        .btn-secondary { background: var(--border); color: var(--text); }
        .actions { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 1rem; }
        .log-box {
            background: #000;
            border-radius: 0.5rem;
            padding: 1rem;
            font-family: monospace;
            font-size: 0.8rem;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            color: var(--green);
        }
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.75rem;
        }
        .progress-bar {
            height: 4px;
            background: var(--border);
            border-radius: 2px;
            overflow: hidden;
            margin-top: 0.5rem;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--cyan), var(--purple));
            transition: width 0.3s;
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .pulse { animation: pulse 2s infinite; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">μ</div>
            <div>
                <h1 style="font-size: 1.25rem;">micro-hack agent</h1>
                <div style="font-size: 0.75rem; color: var(--text-muted);">{hostname}</div>
            </div>
            <div style="margin-left: auto;">
                <span class="status-badge {status_class}">{status}</span>
            </div>
        </div>

        <div class="card">
            <h2>System Information</h2>
            <div class="grid">
                <div class="stat">
                    <div class="stat-label">Hostname</div>
                    <div class="stat-value">{hostname}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Local IP</div>
                    <div class="stat-value">{local_ip}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">OS</div>
                    <div class="stat-value">{os_info}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Agent Version</div>
                    <div class="stat-value">v{version}</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Resource Usage</h2>
            <div class="grid">
                <div class="stat">
                    <div class="stat-label">CPU Usage</div>
                    <div class="stat-value">{cpu_percent}%</div>
                    <div class="progress-bar"><div class="progress-fill" style="width: {cpu_percent}%"></div></div>
                </div>
                <div class="stat">
                    <div class="stat-label">Memory Usage</div>
                    <div class="stat-value">{memory_percent}%</div>
                    <div class="progress-bar"><div class="progress-fill" style="width: {memory_percent}%"></div></div>
                </div>
                <div class="stat">
                    <div class="stat-label">Disk Usage</div>
                    <div class="stat-value">{disk_percent}%</div>
                    <div class="progress-bar"><div class="progress-fill" style="width: {disk_percent}%"></div></div>
                </div>
                <div class="stat">
                    <div class="stat-label">Uptime</div>
                    <div class="stat-value">{uptime}</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Server Connection</h2>
            <div class="grid">
                <div class="stat">
                    <div class="stat-label">Server URL</div>
                    <div class="stat-value" style="font-size: 0.8rem; word-break: break-all;">{server_url}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Remote IP</div>
                    <div class="stat-value">{remote_ip}</div>
                </div>
            </div>
            <div class="actions">
                <button class="btn btn-primary" onclick="location.reload()">Refresh</button>
                <button class="btn btn-secondary" onclick="fetch('/api/ping')">Ping Server</button>
            </div>
        </div>

        <div class="card">
            <h2>Recent Logs</h2>
            <div class="log-box" id="logs">{logs}</div>
        </div>

        <div class="footer">
            micro-hack agent v{version} • Local Web UI<br>
            <span style="color: var(--cyan);">https://micro-hack.nl</span>
        </div>
    </div>
    <script>
        // Auto-refresh every 5 seconds
        setTimeout(() => location.reload(), 5000);
    </script>
</body>
</html>'''

    def __init__(self, agent, port: int = 8888, token: str = None):
        self.agent = agent
        self.port = port
        self.token = token
        self.server = None
        self.running = False
        self._log_buffer = []
        self._max_logs = 50
    
    def add_log(self, message: str):
        """Add a log message to the buffer"""
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        self._log_buffer.append(f"[{timestamp}] {message}")
        if len(self._log_buffer) > self._max_logs:
            self._log_buffer = self._log_buffer[-self._max_logs:]
    
    def _get_system_metrics(self) -> dict:
        """Get current system metrics"""
        metrics = {
            "cpu_percent": 0,
            "memory_percent": 0,
            "disk_percent": 0,
            "uptime": "N/A"
        }
        
        if PSUTIL_AVAILABLE:
            try:
                metrics["cpu_percent"] = round(psutil.cpu_percent(interval=0.1), 1)
                metrics["memory_percent"] = round(psutil.virtual_memory().percent, 1)
                metrics["disk_percent"] = round(psutil.disk_usage('/').percent, 1)
                
                # Calculate uptime
                boot_time = psutil.boot_time()
                uptime_seconds = int(datetime.now().timestamp() - boot_time)
                days, remainder = divmod(uptime_seconds, 86400)
                hours, remainder = divmod(remainder, 3600)
                minutes, _ = divmod(remainder, 60)
                if days > 0:
                    metrics["uptime"] = f"{days}d {hours}h {minutes}m"
                elif hours > 0:
                    metrics["uptime"] = f"{hours}h {minutes}m"
                else:
                    metrics["uptime"] = f"{minutes}m"
            except:
                pass
        
        return metrics
    
    def _render_page(self) -> str:
        """Render the main HTML page"""
        metrics = self._get_system_metrics()
        
        status = "Connected" if self.agent.connected else "Disconnected"
        status_class = "status-connected" if self.agent.connected else "status-disconnected"
        
        return self.HTML_TEMPLATE.format(
            hostname=self.agent.hostname,
            local_ip=self.agent.local_ip,
            remote_ip=self.agent.remote_ip or "N/A",
            os_info=self.agent.os_info,
            version=VERSION,
            status=status,
            status_class=status_class,
            server_url=self.agent.server_url,
            cpu_percent=metrics["cpu_percent"],
            memory_percent=metrics["memory_percent"],
            disk_percent=metrics["disk_percent"],
            uptime=metrics["uptime"],
            logs="\\n".join(self._log_buffer[-20:]) or "No recent logs"
        )
    
    async def _handle_request(self, reader, writer):
        """Handle incoming HTTP request"""
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
            if not request_line:
                writer.close()
                return
            
            request = request_line.decode('utf-8', errors='ignore').strip()
            
            # Read headers
            headers = {}
            while True:
                header_line = await asyncio.wait_for(reader.readline(), timeout=5)
                if header_line == b'\\r\\n' or header_line == b'\\n' or not header_line:
                    break
                try:
                    key, value = header_line.decode('utf-8', errors='ignore').strip().split(':', 1)
                    headers[key.lower()] = value.strip()
                except:
                    pass
            
            # Parse request
            parts = request.split()
            if len(parts) < 2:
                writer.close()
                return
            
            method, path = parts[0], parts[1]
            
            # Token authentication if enabled
            if self.token:
                auth_header = headers.get('authorization', '')
                query_token = None
                if '?' in path:
                    path_parts = path.split('?')
                    path = path_parts[0]
                    for param in path_parts[1].split('&'):
                        if param.startswith('token='):
                            query_token = param[6:]
                            break
                
                if not (auth_header == f'Bearer {self.token}' or query_token == self.token):
                    # Send 401 Unauthorized
                    response = "HTTP/1.1 401 Unauthorized\\r\\n"
                    response += "Content-Type: text/plain\\r\\n"
                    response += "\\r\\n"
                    response += "Unauthorized - Token required"
                    writer.write(response.encode())
                    await writer.drain()
                    writer.close()
                    return
            
            # Route requests
            if path == '/' or path == '/index.html':
                content = self._render_page()
                response = "HTTP/1.1 200 OK\\r\\n"
                response += "Content-Type: text/html; charset=utf-8\\r\\n"
                response += f"Content-Length: {len(content.encode())}\\r\\n"
                response += "\\r\\n"
                writer.write(response.encode() + content.encode())
            
            elif path == '/api/status':
                data = {
                    "connected": self.agent.connected,
                    "hostname": self.agent.hostname,
                    "version": VERSION,
                    "metrics": self._get_system_metrics()
                }
                content = json.dumps(data)
                response = "HTTP/1.1 200 OK\\r\\n"
                response += "Content-Type: application/json\\r\\n"
                response += f"Content-Length: {len(content)}\\r\\n"
                response += "\\r\\n"
                writer.write(response.encode() + content.encode())
            
            elif path == '/api/ping':
                content = json.dumps({"pong": True, "timestamp": datetime.utcnow().isoformat()})
                response = "HTTP/1.1 200 OK\\r\\n"
                response += "Content-Type: application/json\\r\\n"
                response += f"Content-Length: {len(content)}\\r\\n"
                response += "\\r\\n"
                writer.write(response.encode() + content.encode())
            
            elif path == '/favicon.ico':
                response = "HTTP/1.1 204 No Content\\r\\n\\r\\n"
                writer.write(response.encode())
            
            else:
                response = "HTTP/1.1 404 Not Found\\r\\n"
                response += "Content-Type: text/plain\\r\\n"
                response += "\\r\\n"
                response += "Not Found"
                writer.write(response.encode())
            
            await writer.drain()
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            print(f"[WEBSERVER] Error handling request: {e}", flush=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def start(self):
        """Start the local web server"""
        if self.running:
            return
        
        try:
            self.server = await asyncio.start_server(
                self._handle_request,
                '0.0.0.0',
                self.port
            )
            self.running = True
            self.add_log(f"Local web server started on port {self.port}")
            print(f"[WEBSERVER] Started on http://0.0.0.0:{self.port}", flush=True)
            
            async with self.server:
                await self.server.serve_forever()
        except Exception as e:
            print(f"[WEBSERVER] Failed to start: {e}", flush=True)
            self.running = False
    
    async def stop(self):
        """Stop the local web server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.running = False
            self.add_log("Local web server stopped")
            print("[WEBSERVER] Stopped", flush=True)


class MicroHackAgent:
    """Remote agent that connects to micro-hack server via WebSocket"""
    
    def __init__(self, server_url: str, api_key: str):
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = str(uuid.uuid4())
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.running = False
        self.connected = False
        self.reconnect_delay = RECONNECT_DELAY
        self.key_invalidated = False  # Set when key is deleted/revoked - stops reconnection
        
        # Command queue for concurrent processing
        self._command_queue: asyncio.Queue = None  # Created in run()
        self._priority_queue: asyncio.Queue = None  # High-priority commands (info, ping, shell)
        self._num_workers = 4  # Number of concurrent command workers
        self._worker_tasks: list = []
        
        # Installation lock - only one tool can be installed at a time
        self._install_lock: asyncio.Lock = None  # Created in run()
        self._installing_tool: str = None  # Currently installing tool name
        
        # Spam prevention: 3-second cooldown between SCAN commands only
        self._last_scan_time: float = 0.0
        self._scan_cooldown: float = 3.0  # seconds
        
        # Commands exempt from cooldown (lightweight/interactive)
        self._fast_commands = {
            "ping", "info", "echo", "check_tools", "shell_start", "shell_stop",
            "shell_input", "shell_resize", "terminal", "get_shell_data"
        }
        
        # Gather system info
        # Shell sessions map: session_id -> { "master_fd": int, "process": subprocess.Popen }
        self.shell_sessions = {}
        self.hostname = socket.gethostname()
        self.os_info = f"{platform.system()} {platform.release()}"
        
        self.local_ip = self._get_local_ip()
        self.remote_ip = None
        self.location = None
        self.network_interfaces = []
        # Session reader tasks: session_id -> asyncio.Task
        self._session_tasks = {}
        
        # Local webserver for agent control
        self._local_webserver: Optional[AgentLocalWebServer] = None
        self._webserver_task: Optional[asyncio.Task] = None
        self._webserver_enabled = False
        self._webserver_port = 8888
        self._webserver_token = None
        
        # Collected host info (from self-scan)
        self.host_info = {}
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "unknown"
    
    def collect_host_info(self) -> dict:
        """
        Collect comprehensive host information for the overview panel.
        This runs on startup to provide detailed system info.
        """
        info = {
            "collected_at": datetime.utcnow().isoformat(),
            "os": {},
            "hardware": {},
            "network": {},
            "software": {},
            "security": {},
            "users": []
        }
        
        # === OS Information ===
        try:
            info["os"] = {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "architecture": platform.architecture()[0],
                "hostname": socket.gethostname(),
                "fqdn": socket.getfqdn(),
            }
            
            # Linux-specific: get distro info
            if platform.system() == "Linux":
                try:
                    # Try /etc/os-release first (modern Linux)
                    if os.path.exists("/etc/os-release"):
                        with open("/etc/os-release") as f:
                            for line in f:
                                if line.startswith("NAME="):
                                    info["os"]["distro_name"] = line.split("=")[1].strip().strip('"')
                                elif line.startswith("VERSION="):
                                    info["os"]["distro_version"] = line.split("=")[1].strip().strip('"')
                                elif line.startswith("ID="):
                                    info["os"]["distro_id"] = line.split("=")[1].strip().strip('"')
                                elif line.startswith("PRETTY_NAME="):
                                    info["os"]["distro_pretty"] = line.split("=", 1)[1].strip().strip('"')
                except Exception:
                    pass
                
                # Get kernel version
                try:
                    result = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        info["os"]["kernel"] = result.stdout.strip()
                except Exception:
                    pass
            
            # Windows-specific
            elif platform.system() == "Windows":
                try:
                    info["os"]["win_edition"] = platform.win32_edition() if hasattr(platform, 'win32_edition') else None
                    info["os"]["win_version"] = platform.win32_ver()
                except Exception:
                    pass
        except Exception as e:
            self.log(f"Error collecting OS info: {e}", "DEBUG")
        
        # === Hardware Information ===
        try:
            if PSUTIL_AVAILABLE:
                # CPU
                info["hardware"]["cpu_count_physical"] = psutil.cpu_count(logical=False)
                info["hardware"]["cpu_count_logical"] = psutil.cpu_count(logical=True)
                try:
                    info["hardware"]["cpu_freq_mhz"] = round(psutil.cpu_freq().current, 0) if psutil.cpu_freq() else None
                except Exception:
                    pass
                
                # Memory
                mem = psutil.virtual_memory()
                info["hardware"]["ram_total_gb"] = round(mem.total / (1024 ** 3), 2)
                info["hardware"]["ram_available_gb"] = round(mem.available / (1024 ** 3), 2)
                
                # Swap
                swap = psutil.swap_memory()
                info["hardware"]["swap_total_gb"] = round(swap.total / (1024 ** 3), 2)
                
                # Disks
                disks = []
                for partition in psutil.disk_partitions(all=False):
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        disks.append({
                            "device": partition.device,
                            "mountpoint": partition.mountpoint,
                            "fstype": partition.fstype,
                            "total_gb": round(usage.total / (1024 ** 3), 2),
                            "used_gb": round(usage.used / (1024 ** 3), 2),
                            "free_gb": round(usage.free / (1024 ** 3), 2),
                            "percent": usage.percent
                        })
                    except (PermissionError, OSError):
                        pass
                info["hardware"]["disks"] = disks
                
                # Boot time
                info["hardware"]["boot_time"] = datetime.fromtimestamp(psutil.boot_time()).isoformat()
                info["hardware"]["uptime_seconds"] = int(datetime.now().timestamp() - psutil.boot_time())
        except Exception as e:
            self.log(f"Error collecting hardware info: {e}", "DEBUG")
        
        # === Network Information ===
        try:
            interfaces = []
            
            if PSUTIL_AVAILABLE:
                # Get all network interfaces with addresses
                addrs = psutil.net_if_addrs()
                stats = psutil.net_if_stats()
                
                for iface_name, iface_addrs in addrs.items():
                    iface_info = {
                        "name": iface_name,
                        "ipv4": None,
                        "ipv6": None,
                        "mac": None,
                        "mac_vendor": None,
                        "is_up": False,
                        "speed_mbps": None,
                        "mtu": None
                    }
                    
                    for addr in iface_addrs:
                        if addr.family == socket.AF_INET:
                            iface_info["ipv4"] = addr.address
                            iface_info["netmask"] = addr.netmask
                        elif addr.family == socket.AF_INET6:
                            if not addr.address.startswith("fe80"):  # Skip link-local
                                iface_info["ipv6"] = addr.address
                        elif hasattr(socket, 'AF_PACKET') and addr.family == socket.AF_PACKET:
                            iface_info["mac"] = addr.address
                        elif hasattr(psutil, '_common') and addr.family == psutil.AF_LINK:
                            iface_info["mac"] = addr.address
                    
                    # Get interface stats
                    if iface_name in stats:
                        stat = stats[iface_name]
                        iface_info["is_up"] = stat.isup
                        iface_info["speed_mbps"] = stat.speed if stat.speed > 0 else None
                        iface_info["mtu"] = stat.mtu
                    
                    # Look up MAC vendor (first 3 octets = OUI)
                    if iface_info["mac"] and iface_info["mac"] != "00:00:00:00:00:00":
                        mac_vendor = self._lookup_mac_vendor(iface_info["mac"])
                        if mac_vendor:
                            iface_info["mac_vendor"] = mac_vendor
                    
                    # Classify interface type
                    name_lower = iface_name.lower()
                    if "docker" in name_lower or "br-" in name_lower or "veth" in name_lower:
                        iface_info["type"] = "docker"
                    elif "wlan" in name_lower or "wifi" in name_lower or "wl" in name_lower:
                        iface_info["type"] = "wifi"
                    elif "wg" in name_lower or "tun" in name_lower or "tap" in name_lower:
                        iface_info["type"] = "vpn"
                    elif "lo" == name_lower or "loopback" in name_lower:
                        iface_info["type"] = "loopback"
                    elif "eth" in name_lower or "en" in name_lower or "ens" in name_lower:
                        iface_info["type"] = "ethernet"
                    else:
                        iface_info["type"] = "other"
                    
                    interfaces.append(iface_info)
            
            info["network"]["interfaces"] = interfaces
            info["network"]["default_gateway"] = self._get_default_gateway()
            info["network"]["dns_servers"] = self._get_dns_servers()
            
        except Exception as e:
            self.log(f"Error collecting network info: {e}", "DEBUG")
        
        # === Software Information ===
        try:
            # Check for common security tools
            tools = {}
            tool_list = ["nmap", "nikto", "dirb", "gobuster", "sslscan", "whatweb", "ssh-audit", 
                        "masscan", "hydra", "john", "hashcat", "sqlmap", "wpscan", "nuclei",
                        "ffuf", "feroxbuster", "amass", "subfinder", "httpx", "curl", "wget"]
            for tool in tool_list:
                tools[tool] = shutil.which(tool) is not None
            info["software"]["security_tools"] = tools
            
            # Check for package managers
            pkg_managers = {}
            for pm in ["apt", "apt-get", "yum", "dnf", "pacman", "brew", "choco", "pip", "pip3"]:
                pkg_managers[pm] = shutil.which(pm) is not None
            info["software"]["package_managers"] = pkg_managers
            
            # Check Python packages
            try:
                import pkg_resources
                installed_packages = [{"name": p.key, "version": p.version} for p in pkg_resources.working_set]
                info["software"]["python_packages"] = installed_packages[:50]  # Limit to 50
            except Exception:
                pass
            
            # Count running processes
            if PSUTIL_AVAILABLE:
                try:
                    info["software"]["process_count"] = len(psutil.pids())
                except Exception:
                    pass
                
        except Exception as e:
            self.log(f"Error collecting software info: {e}", "DEBUG")
        
        # === Security Information ===
        try:
            # Check listening ports
            listening_ports = []
            if PSUTIL_AVAILABLE:
                try:
                    for conn in psutil.net_connections(kind='inet'):
                        if conn.status == 'LISTEN':
                            listening_ports.append({
                                "port": conn.laddr.port,
                                "ip": conn.laddr.ip,
                                "pid": conn.pid
                            })
                except (psutil.AccessDenied, PermissionError):
                    pass
            info["security"]["listening_ports"] = listening_ports[:50]  # Limit
            
            # Check firewall status (Linux)
            if platform.system() == "Linux":
                # Check iptables
                try:
                    result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=5)
                    info["security"]["iptables_rules"] = len(result.stdout.split('\n')) if result.returncode == 0 else 0
                except Exception:
                    pass
                
                # Check ufw
                try:
                    result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        info["security"]["ufw_status"] = "active" if "active" in result.stdout.lower() else "inactive"
                except Exception:
                    pass
            
            # Check SELinux (if on Linux)
            if platform.system() == "Linux":
                try:
                    if os.path.exists("/etc/selinux/config"):
                        result = subprocess.run(["getenforce"], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            info["security"]["selinux"] = result.stdout.strip()
                except Exception:
                    pass
                    
        except Exception as e:
            self.log(f"Error collecting security info: {e}", "DEBUG")
        
        # === Users Information ===
        try:
            if PSUTIL_AVAILABLE:
                # Current logged-in users
                logged_in = []
                for user in psutil.users():
                    logged_in.append({
                        "name": user.name,
                        "terminal": user.terminal,
                        "host": user.host,
                        "started": datetime.fromtimestamp(user.started).isoformat()
                    })
                info["users"] = logged_in
            
            # Current user
            try:
                import getpass
                info["security"]["current_user"] = getpass.getuser()
            except Exception:
                pass
                
        except Exception as e:
            self.log(f"Error collecting user info: {e}", "DEBUG")
        
        self.host_info = info
        return info
    
    def _lookup_mac_vendor(self, mac: str) -> Optional[str]:
        """Look up MAC address vendor from OUI prefix"""
        # Common OUI prefixes (first 3 octets) -> Vendor name
        # This is a small subset; a full lookup would use an OUI database
        OUI_DATABASE = {
            "00:0c:29": "VMware",
            "00:50:56": "VMware",
            "00:1c:42": "Parallels",
            "08:00:27": "VirtualBox",
            "52:54:00": "QEMU/KVM",
            "00:15:5d": "Hyper-V",
            "02:42:": "Docker",
            "00:1a:4a": "Qumranet/KVM",
            "b8:27:eb": "Raspberry Pi",
            "dc:a6:32": "Raspberry Pi",
            "e4:5f:01": "Raspberry Pi",
            "28:cd:c1": "Raspberry Pi",
            "d8:3a:dd": "Raspberry Pi",
            "00:00:5e": "IANA",
            "00:1b:21": "Intel",
            "00:1e:67": "Intel",
            "00:1f:3c": "Intel",
            "3c:97:0e": "Intel",
            "a4:4c:c8": "Intel",
            "f8:b1:56": "Dell",
            "14:fe:b5": "Dell",
            "00:14:22": "Dell",
            "00:1e:c9": "Dell",
            "d4:be:d9": "Dell",
            "00:25:64": "Dell",
            "18:66:da": "Dell",
            "00:50:8b": "HP",
            "00:1e:0b": "HP",
            "3c:d9:2b": "HP",
            "94:57:a5": "HP",
            "08:00:20": "Sun/Oracle",
            "00:03:ba": "Sun/Oracle",
            "00:0d:3a": "Microsoft Azure",
            "00:17:fa": "Microsoft Hyper-V",
            "00:1d:d8": "Microsoft",
            "28:18:78": "Microsoft",
            "7c:1e:52": "Microsoft",
            "00:16:3e": "Xen",
            "00:25:90": "Supermicro",
            "00:e0:81": "Tyan",
            "ac:1f:6b": "Supermicro",
        }
        
        if not mac:
            return None
            
        mac_lower = mac.lower().replace("-", ":")
        prefix = mac_lower[:8]  # First 3 octets (xx:xx:xx)
        
        # Direct match
        if prefix in OUI_DATABASE:
            return OUI_DATABASE[prefix]
        
        # Partial match (for Docker which uses 02:42:)
        for oui, vendor in OUI_DATABASE.items():
            if mac_lower.startswith(oui):
                return vendor
        
        return None
    
    def _get_default_gateway(self) -> Optional[str]:
        """Get default gateway IP"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and "via" in result.stdout:
                    parts = result.stdout.split()
                    idx = parts.index("via")
                    return parts[idx + 1]
            elif platform.system() == "Darwin":  # macOS
                result = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if "gateway:" in line:
                            return line.split(":")[1].strip()
            elif platform.system() == "Windows":
                result = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if "Default Gateway" in line and ":" in line:
                            gw = line.split(":")[-1].strip()
                            if gw:
                                return gw
        except Exception:
            pass
        return None
    
    def _get_dns_servers(self) -> list:
        """Get configured DNS servers"""
        dns_servers = []
        try:
            if platform.system() == "Linux":
                # Try /etc/resolv.conf
                if os.path.exists("/etc/resolv.conf"):
                    with open("/etc/resolv.conf") as f:
                        for line in f:
                            if line.strip().startswith("nameserver"):
                                dns = line.split()[1]
                                dns_servers.append(dns)
            elif platform.system() == "Windows":
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if "DNS Servers" in line and ":" in line:
                            dns = line.split(":")[-1].strip()
                            if dns:
                                dns_servers.append(dns)
        except Exception:
            pass
        return dns_servers[:5]  # Limit to 5
    
    def _is_root(self) -> bool:
        """Check if running as root/administrator"""
        # Method 1: os.geteuid (Unix/Linux) - most reliable
        if hasattr(os, 'geteuid'):
            euid = os.geteuid()
            if euid == 0:
                return True
            # If not root by euid, still check other methods
        
        # Method 2: Check if we can write to /root (Linux)
        try:
            if os.access('/root', os.W_OK):
                return True
        except:
            pass
        
        # Method 3: Check if we're in Docker (usually run as root)
        try:
            if os.path.exists('/.dockerenv'):
                return True
        except:
            pass
        
        # Method 4: Try to actually run apt-get (the real test)
        try:
            result = subprocess.run(
                ['apt-get', '--version'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                # apt-get works, assume we can install
                return True
        except:
            pass
        
        return False
    
    def _is_running_in_docker(self) -> bool:
        """Check if running inside a Docker container"""
        # Check for .dockerenv file
        if os.path.exists('/.dockerenv'):
            return True
        # Check cgroup for docker/containerd
        try:
            with open('/proc/1/cgroup', 'r') as f:
                return 'docker' in f.read() or 'containerd' in f.read()
        except:
            pass
        return False
    
    def _get_docker_host_ip(self) -> str:
        """Get the Docker host's actual LAN IP address from inside a container"""
        # Try multiple methods to get the host's real LAN IP
        
        # Method 1: Check HOST_IP environment variable (most reliable - user-provided)
        host_ip = os.environ.get('HOST_IP') or os.environ.get('DOCKER_HOST_IP')
        if host_ip:
            return host_ip
        
        # Method 2: Use 'ip route' command to get default gateway (very reliable on Linux)
        try:
            result = subprocess.check_output("ip route | awk '/default/ {print $3}'", shell=True, timeout=5)
            gateway = result.decode().strip()
            if gateway and not gateway.startswith('127.'):
                return gateway
        except:
            pass
        
        # Method 3: Use host.docker.internal (works on Docker Desktop for Mac/Windows)
        try:
            host_ip = socket.gethostbyname('host.docker.internal')
            if host_ip and not host_ip.startswith('127.') and not host_ip.startswith('172.17.'):
                return host_ip
        except:
            pass
        
        # Method 4: Get default gateway from /proc/net/route (fallback for Linux)
        gateway_ip = None
        try:
            with open('/proc/net/route', 'r') as f:
                for line in f:
                    fields = line.strip().split()
                    if fields[1] == '00000000':  # Default route
                        # Gateway is in hex, little-endian
                        gateway_hex = fields[2]
                        # Convert from hex to IP
                        gateway_bytes = bytes.fromhex(gateway_hex)
                        gateway_ip = '.'.join(str(b) for b in reversed(gateway_bytes))
                        break
        except:
            pass
        
        # If gateway is a docker bridge (172.17.0.1), try to get actual host LAN
        if gateway_ip and gateway_ip.startswith('172.17.'):
            # Method 5: Try to infer from WAN lookup - if we can reach the internet,
            # the route likely goes through the host's actual interface
            # We return the gateway as fallback - frontend will show this as docker-host
            return gateway_ip
        
        if gateway_ip and not gateway_ip.startswith('127.'):
            return gateway_ip
        
        return None
    
    def _get_network_interfaces(self) -> list:
        """Detect network interfaces and their types (lan, wifi, docker, vpn, etc.)"""
        interfaces = []
        
        if not PSUTIL_AVAILABLE:
            return interfaces
        
        try:
            # Get all network interfaces with addresses
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for iface_name, addr_list in addrs.items():
                # Skip loopback
                if iface_name.lower() in ['lo', 'loopback', 'lo0']:
                    continue
                    
                # Check if interface is up
                if iface_name in stats and not stats[iface_name].isup:
                    continue
                
                # Get IPv4 address
                ipv4 = None
                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        ipv4 = addr.address
                        break
                
                if not ipv4 or ipv4.startswith('127.'):
                    continue
                
                # Determine interface type
                iface_lower = iface_name.lower()
                iface_type = 'lan'  # default
                
                # Check if this is a Docker-internal IP (172.17.x.x is the default docker0 bridge)
                is_docker_ip = ipv4.startswith('172.17.') or ipv4.startswith('172.18.') or ipv4.startswith('172.19.')
                
                # If we're in Docker and this looks like a docker bridge IP, mark as docker
                if self._is_running_in_docker() and is_docker_ip:
                    iface_type = 'docker'
                # Docker interfaces (check first - most specific)
                elif 'docker' in iface_lower or iface_lower.startswith('veth'):
                    iface_type = 'docker'
                # Bridge interfaces used by Docker (br-xxxxx)
                elif iface_lower.startswith('br-'):
                    iface_type = 'docker'
                # WiFi interfaces (various naming conventions)
                elif any(w in iface_lower for w in ['wlan', 'wifi', 'wlp', 'wlx', 'wireless', 'wi-fi', 'airport']):
                    iface_type = 'wifi'
                # VPN interfaces
                elif any(v in iface_lower for v in ['tun', 'tap', 'vpn', 'wg', 'wireguard', 'ppp', 'utun', 'tailscale']):
                    iface_type = 'vpn'
                # Virtual/VM interfaces
                elif any(v in iface_lower for v in ['vmnet', 'vbox', 'virbr', 'vnic', 'vmware']):
                    iface_type = 'virtual'
                # Known LAN/Ethernet interface naming patterns
                # eth0, eth1, en0, en1, eno1, enp0s3, ens33, enx..., em1, bond0, br0
                elif any(e in iface_lower for e in ['eth', 'eno', 'enp', 'ens', 'enx', 'em', 'bond']):
                    iface_type = 'lan'
                # macOS ethernet (en0, en1, etc. - but not "enabled" etc.)
                elif iface_lower.startswith('en') and len(iface_lower) <= 4 and iface_lower[2:].isdigit():
                    iface_type = 'lan'
                # Linux bridge interfaces (for bridged VMs, etc.) - NOT docker bridges
                elif iface_lower.startswith('br') and not iface_lower.startswith('br-'):
                    iface_type = 'lan'  # Regular bridge is considered part of LAN
                # Default: if IP is in private range and not matched, assume LAN
                elif ipv4.startswith(('10.', '192.168.', '172.')):
                    iface_type = 'lan'
                
                interfaces.append({
                    'name': iface_name,
                    'type': iface_type,
                    'ip': ipv4
                })
            
            # If running in Docker, try to add the host's IP
            if self._is_running_in_docker():
                host_ip = self._get_docker_host_ip()
                if host_ip:
                    # Check if we already have this IP (avoid duplicates)
                    existing_ips = [i['ip'] for i in interfaces]
                    if host_ip not in existing_ips:
                        interfaces.append({
                            'name': 'docker-host',
                            'type': 'lan',  # Host's LAN IP
                            'ip': host_ip
                        })
                
        except Exception as e:
            self.log(f"Error detecting network interfaces: {e}", "WARNING")
        
        return interfaces
    
    def _get_remote_ip_and_location(self) -> tuple:
        """Get remote/public IP and geolocation using ip-api.com (free, no key required)"""
        try:
            import urllib.request
            # ip-api.com provides IP + location in one call (free for non-commercial, 45 req/min)
            with urllib.request.urlopen("http://ip-api.com/json/?fields=status,query,country,regionName,city,lat,lon,isp", timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get('status') == 'success':
                    remote_ip = data.get('query')
                    location = {
                        'country': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'isp': data.get('isp')
                    }
                    return remote_ip, location
        except Exception as e:
            self.log(f"Failed to get remote IP/location: {e}", "WARNING")
        return None, None
    
    def refresh_network_info(self):
        """Refresh network information (local IP, remote IP, location, interfaces)"""
        old_local_ip = self.local_ip
        old_remote_ip = self.remote_ip
        
        self.local_ip = self._get_local_ip()
        self.remote_ip, self.location = self._get_remote_ip_and_location()
        self.network_interfaces = self._get_network_interfaces()
        
        if old_local_ip != self.local_ip:
            self.log(f"Local IP changed: {old_local_ip} -> {self.local_ip}")
        if old_remote_ip != self.remote_ip:
            self.log(f"Remote IP: {self.remote_ip}")
        if self.location:
            self.log(f"Location: {self.location.get('city')}, {self.location.get('country')}")
        if self.network_interfaces:
            iface_types = list(set(i['type'] for i in self.network_interfaces))
            self.log(f"Network interfaces: {', '.join(iface_types)}")
    
    def log(self, message: str, level: str = "INFO"):
        """Simple logging"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}", flush=True)
    
    async def connect(self):
        """Establish WebSocket connection to server"""
        # Refresh IP on each connection attempt
        self.refresh_network_info()
        
        ws_url = f"{self.server_url}/ws/agent?api_key={self.api_key}"
        
        self.log(f"Connecting to {self.server_url}...")
        
        try:
            self.ws = await websockets.connect(
                ws_url,
                ping_interval=PING_INTERVAL,
                ping_timeout=10,
                close_timeout=5
            )
            self.connected = True
            self.reconnect_delay = RECONNECT_DELAY  # Reset backoff on successful connect
            self.log("Connected to server!")
            return True
        except InvalidStatusCode as e:
            if e.status_code == 4001:
                self.log("Connection rejected: Missing API key", "ERROR")
                self.log("Set MICROHACK_API_KEY environment variable and restart", "ERROR")
                self.key_invalidated = True  # No point retrying without a key
            elif e.status_code == 4002:
                self.log("Connection rejected: Invalid or deleted API key", "ERROR")
                self.log("This API key no longer exists. Agent will stop reconnecting.", "ERROR")
                self.log("Generate a new API key and update MICROHACK_API_KEY to reconnect.", "ERROR")
                self.key_invalidated = True  # Key was deleted, stop retrying
            elif e.status_code == 4003:
                self.log("Connection rejected: API key is disabled", "ERROR")
                self.log("Re-enable the API key in the web UI to allow reconnection.", "WARNING")
                # Don't set key_invalidated - key still exists, just disabled
                # Agent will keep trying with exponential backoff
            else:
                self.log(f"Connection rejected: HTTP {e.status_code}", "ERROR")
            return False
        except Exception as e:
            self.log(f"Connection failed: {e}", "ERROR")
            return False
    
    async def register(self):
        """Register agent with server"""
        if not self.ws:
            return
        
        # Collect comprehensive host info on registration
        self.log("Collecting host information...")
        host_info = self.collect_host_info()
        self.log(f"Host info collected: OS={host_info.get('os', {}).get('distro_pretty') or host_info.get('os', {}).get('system')}, RAM={host_info.get('hardware', {}).get('ram_total_gb')}GB")
        
        registration = {
            "type": "register",
            "data": {
                "agent_id": self.agent_id,
                "hostname": self.hostname,
                "ip": self.local_ip,
                "remote_ip": self.remote_ip,
                "location": self.location,
                "version": VERSION,
                "os": self.os_info,
                "python_version": platform.python_version(),
                "is_docker": self._is_running_in_docker(),
                "is_root": self._is_root(),
                "network_interfaces": self.network_interfaces,
                "host_info": host_info,  # Comprehensive host scan data
                # All nmap_* commands are covered by 'nmap' capability
                "capabilities": [
                    "ping", "info", "nmap", "nikto", "dirb", "sslscan", "gobuster", "whatweb", "traceroute", "ssh_audit", "ftp_anon", "smtp", "imap", "banner", "screenshot", "http_headers", "robots", "dns", "install_tool", "check_tools", "update_agent",
                    # PTY/shell interactive commands
                    "shell_start", "shell_input", "shell_stop", "shell_resize"
                ],
                # Whether this agent supports a PTY (shown in UI for enabling interactive sessions)
                "shell_pty_available": shutil.which("tmux") is not None
            }
        }
        
        await self.ws.send(json.dumps(registration))
        self.log(f"Registration payload capabilities: {registration['data'].get('capabilities')}", "DEBUG")
        loc_str = f" @ {self.location.get('city')}, {self.location.get('country')}" if self.location else ""
        self.log(f"Registered as {self.hostname} ({self.os_info}){loc_str}")
    
    def get_system_metrics(self) -> dict:
        """Collect system metrics using psutil"""
        if not PSUTIL_AVAILABLE:
            return {}
        
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            
            # Memory
            mem = psutil.virtual_memory()
            memory_percent = mem.percent
            memory_used_gb = round(mem.used / (1024 ** 3), 2)
            memory_total_gb = round(mem.total / (1024 ** 3), 2)
            
            # Disk (root partition)
            try:
                if platform.system() == "Windows":
                    disk = psutil.disk_usage("C:\\")
                else:
                    disk = psutil.disk_usage("/")
                disk_percent = disk.percent
                disk_used_gb = round(disk.used / (1024 ** 3), 2)
                disk_total_gb = round(disk.total / (1024 ** 3), 2)
            except Exception:
                disk_percent = 0
                disk_used_gb = 0
                disk_total_gb = 0
            
            # Network
            net = psutil.net_io_counters()
            net_bytes_sent = net.bytes_sent
            net_bytes_recv = net.bytes_recv
            
            # Load average (Unix only)
            try:
                load_avg = os.getloadavg()
                load_1min = round(load_avg[0], 2)
            except (AttributeError, OSError):
                load_1min = None
            
            return {
                "cpu_percent": cpu_percent,
                "cpu_count": cpu_count,
                "memory_percent": memory_percent,
                "memory_used_gb": memory_used_gb,
                "memory_total_gb": memory_total_gb,
                "disk_percent": disk_percent,
                "disk_used_gb": disk_used_gb,
                "disk_total_gb": disk_total_gb,
                "net_bytes_sent": net_bytes_sent,
                "net_bytes_recv": net_bytes_recv,
                "load_1min": load_1min
            }
        except Exception as e:
            self.log(f"Error collecting system metrics: {e}", "WARNING")
            return {}
    
    async def send_heartbeat(self):
        """Send periodic heartbeat to server"""
        if not self.ws:
            return
        
        heartbeat = {
            "type": "heartbeat",
            "status": {
                "uptime": "running",
                "timestamp": datetime.utcnow().isoformat()
            },
            "system_metrics": self.get_system_metrics()
        }
        
        await self.ws.send(json.dumps(heartbeat))
    
    async def send_traceroute_hop(self, command_id: str, host_id: str, job_id: str, target: str, hop: dict):
        """Send a live traceroute hop update to the server for real-time UI updates"""
        if not self.ws:
            return
        
        hop_update = {
            "type": "traceroute_hop",
            "command_id": command_id,
            "host_id": host_id,
            "job_id": job_id,
            "target": target,
            "hop": hop,
            "agent_id": self.agent_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            await self.ws.send(json.dumps(hop_update))
            self.log(f"Sent hop {hop.get('hop')} update", "DEBUG")
        except Exception as e:
            self.log(f"Failed to send hop update: {e}", "WARNING")
    
    async def send_job_progress(self, job_id: str, progress: int, message: str = ""):
        """Send job progress update to the server for real-time UI updates"""
        if not self.ws or not job_id:
            return
        
        progress_update = {
            "type": "job_progress",
            "job_id": job_id,
            "progress": progress,
            "message": message,
            "agent_id": self.agent_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            await self.ws.send(json.dumps(progress_update))
            self.log(f"Job {job_id[:8]} progress: {progress}% - {message}", "DEBUG")
        except Exception as e:
            self.log(f"Failed to send job progress: {e}", "WARNING")

    async def send_job_output(self, job_id: str, output_line: str):
        """Send a single command output line back to server for live UI streaming"""
        if not self.ws or not job_id or not output_line:
            return

        try:
            output_msg = {
                "type": "job_output",
                "job_id": job_id,
                "line": output_line,
                "agent_id": self.agent_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            await self.ws.send(json.dumps(output_msg))
            self.log(f"Job {job_id[:8]} output: {output_line.strip()}", "DEBUG")
        except Exception as e:
            self.log(f"Failed to send job output: {e}", "WARNING")

    async def start_shell_session(self, command_id: str, command: str) -> dict:
        """Start a PTY-based shell session and stream output back to server.

        Returns a response dict including session_id on success.
        """
        import uuid as _uuid
        import os as _os

        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }

        session_id = str(_uuid.uuid4())
        
        try:
            self.log(f"Starting PTY shell: {command}", "DEBUG")
            
            # Create PTY pair
            master_fd, slave_fd = _os.openpty()
            
            # Set terminal size
            try:
                import fcntl, termios, struct
                winsize = struct.pack('HHHH', 24, 80, 0, 0)
                fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
            except Exception as e:
                self.log(f"Could not set terminal size: {e}", "DEBUG")
            
            # Set up environment for full interactive shell
            env = os.environ.copy()
            env['TERM'] = 'xterm-256color'
            env['COLORTERM'] = 'truecolor'
            env['LANG'] = env.get('LANG', 'en_US.UTF-8')
            env['LC_ALL'] = env.get('LC_ALL', env.get('LANG', 'en_US.UTF-8'))
            # Ensure HOME is set for bash to load .bashrc
            if 'HOME' not in env:
                import pwd
                try:
                    env['HOME'] = pwd.getpwuid(_os.getuid()).pw_dir
                except Exception:
                    env['HOME'] = '/root' if _os.getuid() == 0 else '/tmp'
            
            # Use login shell for proper initialization (tab completion, aliases, etc.)
            # Wrap command to start as interactive login shell
            if command in ('/bin/bash', 'bash'):
                shell_cmd = '/bin/bash --login -i'
            elif command in ('/bin/sh', 'sh'):
                shell_cmd = command
            else:
                shell_cmd = command
            
            # Start shell with PTY
            proc = subprocess.Popen(
                shell_cmd,
                shell=True,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=env,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None
            )
            
            # Close slave in parent - child has it
            _os.close(slave_fd)
            
            # Make master non-blocking for async reading
            import fcntl
            flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
            fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            # Save session
            self.shell_sessions[session_id] = {
                "process": proc,
                "master_fd": master_fd
            }

            # Start reader task
            task = asyncio.create_task(self._session_reader(session_id))
            self._session_tasks[session_id] = task
            
            # Send MOTD after a short delay to ensure shell is ready
            asyncio.create_task(self._send_shell_motd(session_id))

            response["data"] = {"session_id": session_id}
            response["success"] = True
            self.log(f"Started shell session {session_id} with pid {proc.pid}")
            return response
        except Exception as e:
            self.log(f"Failed to start shell: {e}", "ERROR")
            response["success"] = False
            response["error"] = str(e)
            return response

    async def _send_shell_motd(self, session_id: str):
        """Send a fancy MOTD banner after shell starts"""
        await asyncio.sleep(0.3)  # Wait for shell to initialize
        
        if session_id not in self.shell_sessions:
            return
        
        # Get system info for MOTD
        import platform
        try:
            uname = platform.uname()
            kernel = uname.release
            arch = uname.machine
        except:
            kernel = "unknown"
            arch = "unknown"
        
        # Fancy MOTD with μHack branding
        motd = f'''\r
\033[38;5;51m╔══════════════════════════════════════════════════════════════╗\033[0m
\033[38;5;51m║\033[0m  \033[1;38;5;201m   __ __  __ __           __  \033[0m                               \033[38;5;51m║\033[0m
\033[38;5;51m║\033[0m  \033[1;38;5;201m  / // / / // /__ _ ____ / /__\033[0m                               \033[38;5;51m║\033[0m
\033[38;5;51m║\033[0m  \033[1;38;5;201m / _  / / _  / _ `// __//  '_/\033[0m                               \033[38;5;51m║\033[0m
\033[38;5;51m║\033[0m  \033[1;38;5;201m/_//_(_)_//_/\\_,_/ \\__//_/\\_\\ \033[0m                               \033[38;5;51m║\033[0m
\033[38;5;51m║\033[0m  \033[38;5;245mμHack Remote Agent v{VERSION:<8}\033[0m                              \033[38;5;51m║\033[0m
\033[38;5;51m╠══════════════════════════════════════════════════════════════╣\033[0m
\033[38;5;51m║\033[0m  \033[38;5;82m●\033[0m \033[1mHost:\033[0m    {self.hostname:<20}                       \033[38;5;51m║\033[0m
\033[38;5;51m║\033[0m  \033[38;5;82m●\033[0m \033[1mKernel:\033[0m  {kernel:<20}                       \033[38;5;51m║\033[0m
\033[38;5;51m║\033[0m  \033[38;5;82m●\033[0m \033[1mArch:\033[0m    {arch:<20}                       \033[38;5;51m║\033[0m
\033[38;5;51m║\033[0m  \033[38;5;82m●\033[0m \033[1mSession:\033[0m {session_id[:8]}...                              \033[38;5;51m║\033[0m
\033[38;5;51m╚══════════════════════════════════════════════════════════════╝\033[0m
\r
'''
        
        # Send via WebSocket
        if self.ws:
            try:
                msg = json.dumps({
                    "type": "shell_output",
                    "session_id": session_id,
                    "output": motd,
                    "agent_id": self.agent_id,
                    "timestamp": datetime.utcnow().isoformat()
                })
                await self.ws.send(msg)
            except Exception as e:
                self.log(f"Failed to send MOTD: {e}", "WARNING")

    async def _session_reader(self, session_id: str):
        """Read from PTY master and send shell_output messages to the server."""
        import os as _os
        import errno as _errno
        import select as _select
        
        sess = self.shell_sessions.get(session_id)
        if not sess:
            self.log(f"Session {session_id} not found in reader", "WARNING")
            return
        
        master_fd = sess.get("master_fd")
        proc = sess.get("process")
        
        if not master_fd:
            self.log(f"Session {session_id} has no master_fd", "WARNING")
            return
            
        self.log(f"[SHELL] Starting PTY reader for session {session_id[:8]}, master_fd={master_fd}, proc.pid={proc.pid if proc else 'None'}")
        try:
            loop_count = 0
            while True:
                loop_count += 1
                # Use select to check if data is available (with short timeout for responsiveness)
                try:
                    readable, _, _ = _select.select([master_fd], [], [], 0.01)  # 10ms timeout for fast response
                except Exception as e:
                    self.log(f"[SHELL] select() failed for {session_id[:8]}: {e}")
                    break
                    
                if not readable:
                    # No data, check if process is still alive
                    if proc and proc.poll() is not None:
                        self.log(f"[SHELL] Session {session_id[:8]} process exited with code {proc.returncode}")
                        break
                    if loop_count % 500 == 0:
                        self.log(f"[SHELL] Session {session_id[:8]} waiting for data (loop {loop_count})", "DEBUG")
                    await asyncio.sleep(0.005)  # 5ms sleep - fast but yields to event loop
                    continue
                
                try:
                    data = _os.read(master_fd, 4096)
                    if not data:
                        self.log(f"[SHELL] Session {session_id[:8]} reader got EOF")
                        break
                except OSError as e:
                    if e.errno in (_errno.EIO, _errno.EBADF, _errno.EAGAIN, _errno.EWOULDBLOCK):
                        if e.errno in (_errno.EAGAIN, _errno.EWOULDBLOCK):
                            await asyncio.sleep(0.005)  # Quick retry
                            continue
                        self.log(f"[SHELL] Session {session_id[:8]} PTY closed (errno={e.errno})")
                        break
                    raise
                    
                try:
                    output = data.decode('utf-8', errors='replace')
                except Exception:
                    output = str(data)
                    
                self.log(f"[SHELL] Session {session_id[:8]} read {len(data)} bytes, sending shell_output")
                
                # Send shell_output message
                if self.ws:
                    try:
                        msg = json.dumps({
                            "type": "shell_output",
                            "session_id": session_id,
                            "output": output,
                            "agent_id": self.agent_id,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                        await self.ws.send(msg)
                        self.log(f"[SHELL] Sent shell_output for session {session_id[:8]}")
                    except Exception as e:
                        self.log(f"[SHELL] Failed to send shell_output: {e}", "WARNING")
                        if not self.ws:
                            break
                else:
                    self.log(f"[SHELL] No WebSocket, cannot send shell_output", "WARNING")
                            
        except Exception as e:
            self.log(f"Session reader error for {session_id}: {e}", "WARNING")
        finally:
            self.log(f"Session {session_id} reader exiting, cleaning up", "DEBUG")
            try:
                _os.close(master_fd)
            except Exception:
                pass
            # Clean up session
            if session_id in self.shell_sessions:
                del self.shell_sessions[session_id]
            if session_id in self._session_tasks:
                del self._session_tasks[session_id]

    async def write_shell_input(self, session_id: str, input_str: str) -> tuple[bool, str]:
        """Write input to PTY master for a given session."""
        import os as _os
        self.log(f"[SHELL] write_shell_input called: session={session_id[:8] if session_id else 'None'}, input={input_str!r}")
        sess = self.shell_sessions.get(session_id)
        if not sess:
            self.log(f'[SHELL] write_shell_input: Session {session_id[:8] if session_id else "None"} not found, active sessions: {list(self.shell_sessions.keys())[:3]}', 'WARNING')
            return False, "Session not found"
        
        master_fd = sess.get('master_fd')
        if not master_fd:
            return False, "Invalid session - no master_fd"
            
        try:
            if isinstance(input_str, str):
                data = input_str.encode('utf-8')
            else:
                data = bytes(input_str)
            _os.write(master_fd, data)
            self.log(f'[SHELL] Wrote {len(data)} bytes to session {session_id[:8]}')
            return True, ""
        except Exception as e:
            self.log(f'[SHELL] write_shell_input error: {e}', 'ERROR')
            return False, str(e)

    async def resize_shell_session(self, session_id: str, rows: int, cols: int) -> tuple[bool, str]:
        """Resize PTY window size."""
        sess = self.shell_sessions.get(session_id)
        if not sess:
            return False, "Session not found"
        master_fd = sess.get('master_fd')
        if not master_fd:
            return False, "Invalid session"

        try:
            import fcntl, termios, struct
            winsize = struct.pack('HHHH', int(rows), int(cols), 0, 0)
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
            return True, ""
        except Exception as e:
            return False, str(e)

    async def stop_shell_session(self, session_id: str) -> tuple[bool, str]:
        """Stop a shell session and clean up resources."""
        import os as _os
        sess = self.shell_sessions.get(session_id)
        if not sess:
            return False, "Session not found"
            
        proc = sess.get('process')
        master_fd = sess.get('master_fd')
        
        try:
            if proc and proc.poll() is None:
                proc.terminate()
                await asyncio.sleep(0.2)
                if proc.poll() is None:
                    proc.kill()
                    
            # Cancel reader task
            task = self._session_tasks.pop(session_id, None)
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                    
            # Close master fd
            if master_fd:
                try:
                    _os.close(master_fd)
                except:
                    pass
                    
            # Remove session
            if session_id in self.shell_sessions:
                del self.shell_sessions[session_id]
                
            return True, ""
        except Exception as e:
            return False, str(e)
    
    async def handle_message(self, message: str):
        """Handle incoming message from server"""
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            self.log(f"Invalid JSON received: {message}", "ERROR")
            return
        
        msg_type = data.get("type")
        
        if msg_type == "connected":
            self.log(f"Server confirmed connection: {data.get('message')}")
            # Register after connection confirmed
            await self.register()
        
        elif msg_type == "registered":
            self.log("Registration confirmed by server")
        
        elif msg_type == "pong":
            self.log("Received pong from server", "DEBUG")
        
        elif msg_type == "heartbeat_ack":
            pass  # Silent acknowledgment
        
        elif msg_type == "command":
            # Route to priority queue for fast commands, regular queue for scans
            command = data.get("command", "")
            if command in self._fast_commands:
                # Fast commands go to priority queue for immediate handling
                if self._priority_queue:
                    await self._priority_queue.put(data)
                else:
                    await self.handle_command(data)
            else:
                # Scan/heavy commands go to regular queue
                if self._command_queue:
                    await self._command_queue.put(data)
                else:
                    await self.handle_command(data)
        
        elif msg_type == "error":
            self.log(f"Server error: {data.get('message')}", "ERROR")
        
        else:
            self.log(f"Unknown message type: {msg_type}", "WARNING")
    
    async def run_host_ping(self, command_id: str, command_data: dict) -> dict:
        """
        Run a ping command against a target host.
        
        command_data should contain:
        - target: IP or hostname to ping
        - count: number of ping packets (optional, default: 10)
        """
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        count = command_data.get("count", 10)
        if count > 100:
            count = 100  # Limit to 100 pings
        
        # Check if ping is installed, auto-install if needed (Linux only)
        is_windows = platform.system().lower() == "windows"
        if not is_windows:
            installed, install_msg = await self.ensure_tool_installed("iputils-ping")
            if not installed:
                response["success"] = False
                response["error"] = install_msg
                return response
            if install_msg == "installed":
                response["data"]["auto_installed"] = "iputils-ping"
        
        # Build ping command based on OS
        if is_windows:
            cmd = ["ping", "-n", str(count), target]
        else:
            cmd = ["ping", "-c", str(count), target]
        
        self.log(f"Running ping: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=120  # 2 minute timeout
            )
            
            output = stdout.decode("utf-8", errors="replace")
            
            # Parse ping output
            result = self.parse_ping_output(output, is_windows)
            result["target"] = target
            result["count"] = count
            result["raw_output"] = output
            result["pinged_at"] = datetime.utcnow().isoformat()
            result["agent_id"] = self.agent_id
            
            response["data"] = result
            
            if result.get("packet_loss", 100) < 100:
                response["data"]["is_alive"] = True
                self.log(f"Ping complete: {target} is reachable, avg latency {result.get('avg_latency', 'N/A')}ms")
            else:
                response["data"]["is_alive"] = False
                self.log(f"Ping complete: {target} is not reachable")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Ping timed out"
            self.log("Ping timed out", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Ping error: {e}", "ERROR")
        
        return response
    
    def parse_ping_output(self, output: str, is_windows: bool) -> dict:
        """Parse ping output to extract statistics"""
        result = {
            "packets_sent": 0,
            "packets_received": 0,
            "packet_loss": 100.0,
            "min_latency": None,
            "max_latency": None,
            "avg_latency": None
        }
        
        import re
        
        try:
            if is_windows:
                # Windows format: Packets: Sent = 10, Received = 10, Lost = 0 (0% loss)
                packets_match = re.search(r'Sent = (\d+), Received = (\d+), Lost = (\d+)', output)
                if packets_match:
                    result["packets_sent"] = int(packets_match.group(1))
                    result["packets_received"] = int(packets_match.group(2))
                    lost = int(packets_match.group(3))
                    if result["packets_sent"] > 0:
                        result["packet_loss"] = (lost / result["packets_sent"]) * 100
                
                # Windows format: Minimum = 1ms, Maximum = 5ms, Average = 2ms
                latency_match = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', output)
                if latency_match:
                    result["min_latency"] = float(latency_match.group(1))
                    result["max_latency"] = float(latency_match.group(2))
                    result["avg_latency"] = float(latency_match.group(3))
            else:
                # Unix format: 10 packets transmitted, 10 received, 0% packet loss
                packets_match = re.search(r'(\d+) packets transmitted, (\d+) (?:packets )?received', output)
                if packets_match:
                    result["packets_sent"] = int(packets_match.group(1))
                    result["packets_received"] = int(packets_match.group(2))
                    if result["packets_sent"] > 0:
                        result["packet_loss"] = ((result["packets_sent"] - result["packets_received"]) / result["packets_sent"]) * 100
                
                # Unix format: rtt min/avg/max/mdev = 0.028/0.036/0.050/0.007 ms
                latency_match = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/[\d.]+ ms', output)
                if latency_match:
                    result["min_latency"] = float(latency_match.group(1))
                    result["avg_latency"] = float(latency_match.group(2))
                    result["max_latency"] = float(latency_match.group(3))
                else:
                    # Alternative format: min/avg/max = 1.234/2.345/3.456 ms
                    latency_match = re.search(r'min/avg/max = ([\d.]+)/([\d.]+)/([\d.]+)', output)
                    if latency_match:
                        result["min_latency"] = float(latency_match.group(1))
                        result["avg_latency"] = float(latency_match.group(2))
                        result["max_latency"] = float(latency_match.group(3))
        except Exception as e:
            self.log(f"Error parsing ping output: {e}", "WARNING")
        
        return result
    
    async def run_nmap_scan(self, command_id: str, command_data: dict) -> dict:
        """
        Run an nmap scan and return results as JSON.
        
        command_data should contain:
        - target: IP, hostname, or CIDR range to scan
        - scan_type: 'quick', 'full', 'ports', 'vuln' (optional, default: 'quick')
        - ports: specific ports to scan (optional)
        - arguments: additional nmap arguments (optional)
        """
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        # Check if nmap is available, auto-install if needed
        installed, install_msg = await self.ensure_tool_installed("nmap")
        if not installed:
            response["success"] = False
            response["error"] = install_msg
            return response
        if install_msg == "installed":
            response["data"]["auto_installed"] = "nmap"
        
        target = command_data.get("target")
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        scan_type = command_data.get("scan_type", "quick")
        ports = command_data.get("ports")
        # Support 'arguments' for extra CLI args (must be string, not dict)
        # 'options' is now a dict for structured data, so only use it if it's a string
        extra_args = command_data.get("arguments", "")
        if not extra_args:
            opts = command_data.get("options")
            if isinstance(opts, str):
                extra_args = opts
            # If options is a dict, ignore it for CLI args - it's structured data
        project_id = command_data.get("project_id")  # For associating results
        
        # Build nmap command
        # Always use -oX - for XML output to stdout
        cmd = ["nmap", "-oX", "-"]
        
        # =================================================================
        # SCAN TYPES - Clear separation between network and host scans
        # =================================================================
        # 
        # NETWORK SCANS (discover hosts in a network/CIDR):
        #   nmap_network_quick    - Fast ping sweep, may miss some hosts
        #   nmap_network_thorough - Thorough discovery, finds hidden hosts
        #
        # HOST SCANS (scan ports/services on a single host):
        #   nmap_host_quick       - Quick port scan (top 100 ports)
        #   nmap_host_thorough    - Full port scan with service detection
        #   nmap_host_vuln        - Vulnerability scan on known ports
        #
        # LEGACY (for backwards compatibility):
        #   quick, nmap_quick, discovery, full, nmap_full, vuln, nmap_vuln
        # =================================================================
        
        # --- NETWORK SCANS (host discovery) ---
        if scan_type in ("nmap_network_quick", "discovery", "nmap_discovery"):
            # Fast ping sweep - quick but may miss hosts with ICMP blocked
            cmd.extend(["-sn", "-T4"])
        elif scan_type == "nmap_network_thorough":
            # Thorough network discovery - finds hosts that block ICMP
            # -sn: no port scan, -PE: ICMP echo, -PP: timestamp, -PM: netmask
            # -PS: TCP SYN ping, -PA: TCP ACK ping, -PU: UDP ping
            cmd.extend(["-sn", "-T4", "-PE", "-PP", "-PM", "-PS21,22,23,25,80,443,3389", "-PA80,443", "-PU53,67,68,123"])
        
        # --- HOST SCANS (port/service scanning) ---
        elif scan_type in ("nmap_host_quick", "quick", "nmap_quick", "syn"):
            # Quick port scan - top 100 ports, fast
            cmd.extend(["-T4", "-F"])
        elif scan_type in ("nmap_host_thorough", "full", "nmap_full", "thorough", "nmap_thorough"):
            # Thorough host scan - all ports, service/OS detection
            # -sS: SYN scan, -sV: version, -O: OS, -p-: all ports, -Pn: skip discovery
            cmd.extend(["-T4", "-sS", "-sV", "-O", "-Pn", "-p-"])
        elif scan_type in ("nmap_host_vuln", "vuln", "nmap_vuln"):
            # Vulnerability scan - runs vuln scripts
            # Check for custom scripts in options
            opts = command_data.get("options", {})
            scripts = opts.get("scripts") if isinstance(opts, dict) else None
            if scripts and isinstance(scripts, list) and len(scripts) > 0:
                # Use custom script selection
                script_str = ",".join(scripts)
                self.log(f"Using custom vuln scripts: {script_str}")
                cmd.extend(["-T4", "-sV", "--script", script_str, "-Pn"])
            else:
                # Default vuln scripts
                cmd.extend(["-T4", "-sV", "--script", "vuln", "-Pn"])
            if ports:
                cmd.extend(["-p", ports])
        
        # --- UTILITY SCANS ---
        elif scan_type in ("ports", "connect"):
            # Specific port scan with version detection
            cmd.extend(["-T4", "-sV"])
            if ports:
                cmd.extend(["-p", ports])
        
        else:
            # Default to quick host scan for any unrecognized type
            self.log(f"Unknown scan_type '{scan_type}', defaulting to quick host scan")
            cmd.extend(["-T4", "-F"])
        
        # Add extra arguments if provided (be careful with this)
        if extra_args and isinstance(extra_args, str):
            # Only allow safe arguments
            safe_args = extra_args.replace(";", "").replace("&", "").replace("|", "")
            cmd.extend(safe_args.split())
        
        cmd.append(target)
        
        self.log(f"Running nmap scan: {' '.join(cmd)}")
        
        # Get job_id for progress updates
        job_id = command_data.get("job_id")
        
        try:
            # Send initial progress
            if job_id:
                await self.send_job_progress(job_id, 15, f"Starting {scan_type} scan on {target}...")
            
            # Run nmap asynchronously with stats output for progress
            # Add --stats-every to get periodic progress updates
            nmap_cmd = cmd.copy()
            if "--stats-every" not in " ".join(cmd):
                nmap_cmd.insert(1, "--stats-every")
                nmap_cmd.insert(2, "5s")

            # Attempt to run; if -sS fails due to permission/raw socket errors,
            # retry once with -sT (connect scan) as a fallback.
            attempt = 0
            max_attempts = 2
            xml_output = ""
            stderr_data = b""
            fallback_used = False

            while attempt < max_attempts:
                attempt += 1

                process = await asyncio.create_subprocess_exec(
                    *nmap_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                # Read stdout and stderr concurrently, parsing progress from stderr
                stdout_data = b""
                stderr_data = b""
                last_progress = 15

                async def read_stdout():
                    nonlocal stdout_data
                    stdout_data = await process.stdout.read()
                    # Stream full stdout as job_output if job exists
                    if job_id and stdout_data:
                        try:
                            for line in stdout_data.decode('utf-8', errors='replace').splitlines():
                                await self.send_job_output(job_id, line)
                        except Exception:
                            pass

                async def read_stderr_with_progress():
                    nonlocal stderr_data, last_progress
                    while True:
                        line = await process.stderr.readline()
                        if not line:
                            break
                        stderr_data += line
                        line_str = line.decode("utf-8", errors="replace")
                        # Also stream stderr as job_output
                        if job_id and line_str.strip():
                            try:
                                await self.send_job_output(job_id, f"[stderr] {line_str.strip()}")
                            except Exception:
                                pass
                        # Debug: log stderr lines so we can see nmap progress output
                        try:
                            self.log(f"nmap stderr: {line_str.strip()}", "DEBUG")
                        except Exception:
                            pass

                        # Parse nmap progress from stats output
                        if job_id:
                            import re
                            # Try to match explicit percent patterns first
                            percent_match = re.search(r'(\d+(?:\.\d+)?)\s*%\s*done', line_str)
                            if percent_match:
                                percent = float(percent_match.group(1))
                                progress = int(20 + (percent * 0.7))
                                if progress > last_progress:
                                    last_progress = progress
                                    await self.send_job_progress(job_id, progress, f"Scanning {target}... {int(percent)}% complete")
                                continue

                            # Match 'About X% done' without the '%' token capture
                            about_match = re.search(r'About\s+(\d+(?:\.\d+)?)\s*%?\s*done', line_str, re.IGNORECASE)
                            if about_match:
                                percent = float(about_match.group(1))
                                progress = int(20 + (percent * 0.7))
                                if progress > last_progress:
                                    last_progress = progress
                                    await self.send_job_progress(job_id, progress, f"Scanning {target}... {int(percent)}% complete")
                                continue

                            # Try to parse 'Stats:' lines for approximate progress by searching for 'hosts completed' messages
                            stats_match = re.search(r'([0-9]+) hosts completed', line_str)
                            if stats_match:
                                try:
                                    completed = int(stats_match.group(1))
                                    # Heuristic: map completed hosts to progress (bounded)
                                    # This is approximate; we map completed -> progress up to 85%
                                    progress = min(85, 20 + completed)
                                    if progress > last_progress:
                                        last_progress = progress
                                        await self.send_job_progress(job_id, progress, f"Scanning {target}... hosts completed: {completed}")
                                except Exception:
                                    pass

                try:
                    await asyncio.wait_for(
                        asyncio.gather(read_stdout(), read_stderr_with_progress()),
                        timeout=600  # 10 minute timeout for scans
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    raise

                await process.wait()

                xml_output = stdout_data.decode("utf-8", errors="replace")
                stderr_text = stderr_data.decode("utf-8", errors="replace")

                # If nmap returned non-zero and indicates raw socket/permission errors, retry with -sT
                if process.returncode != 0:
                    self.log(f"nmap error (attempt {attempt}): {stderr_text}", "WARNING")
                    # Check for common permission/raw socket error messages
                    perm_errors = ["operation not permitted", "can't open raw socket", "raw socket", "requires root", "permission denied"]
                    if any(err in stderr_text.lower() for err in perm_errors) and "-sS" in nmap_cmd and not fallback_used:
                        # Replace -sS with -sT and retry once
                        nmap_cmd = [("-sT" if a == "-sS" else a) for a in nmap_cmd]
                        fallback_used = True
                        self.log("nmap -sS failed due to permissions, retrying with -sT (connect scan)", "INFO")
                        # small pause before retry
                        await asyncio.sleep(0.5)
                        continue
                    else:
                        # Still try to parse partial results if any
                        if not xml_output or "<nmaprun" not in xml_output:
                            response["success"] = False
                            response["error"] = f"nmap failed: {stderr_text}"
                            return response
                # If success or no fatal error, break loop
                break
            
            # Send final progress
            if job_id:
                await self.send_job_progress(job_id, 95, "Parsing scan results...")
            
            # Parse XML to JSON
            hosts = self.parse_nmap_xml(xml_output)
            
            response["data"] = {
                "target": target,
                "scan_type": scan_type,
                "hosts": hosts,
                "host_count": len(hosts),
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"Scan complete: found {len(hosts)} host(s)")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Scan timed out (10 minute limit)"
            self.log("nmap scan timed out", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"nmap error: {e}", "ERROR")
        
        return response
    
    def parse_nmap_xml(self, xml_output: str) -> list:
        """Parse nmap XML output to a list of host dictionaries"""
        import xml.etree.ElementTree as ET
        
        hosts = []
        
        try:
            root = ET.fromstring(xml_output)
            
            for host_elem in root.findall(".//host"):
                # Check if host is up
                status = host_elem.find("status")
                if status is None or status.get("state") != "up":
                    continue
                
                host = {
                    "ip_address": None,
                    "hostname": None,
                    "mac_address": None,
                    "mac_vendor": None,
                    "os": None,
                    "os_accuracy": None,
                    "ports": [],
                    "state": "up"
                }
                
                # Get addresses
                for addr in host_elem.findall("address"):
                    addr_type = addr.get("addrtype")
                    if addr_type == "ipv4":
                        host["ip_address"] = addr.get("addr")
                    elif addr_type == "mac":
                        host["mac_address"] = addr.get("addr")
                        host["mac_vendor"] = addr.get("vendor")
                
                # Get hostnames
                hostnames = host_elem.find("hostnames")
                if hostnames is not None:
                    hostname_elem = hostnames.find("hostname")
                    if hostname_elem is not None:
                        host["hostname"] = hostname_elem.get("name")
                
                # Get OS detection
                os_elem = host_elem.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        host["os"] = osmatch.get("name")
                        host["os_accuracy"] = int(osmatch.get("accuracy", 0))
                
                # Get ports
                ports_elem = host_elem.find("ports")
                if ports_elem is not None:
                    for port_elem in ports_elem.findall("port"):
                        state_elem = port_elem.find("state")
                        if state_elem is None or state_elem.get("state") != "open":
                            continue
                        
                        port = {
                            "port": int(port_elem.get("portid")),
                            "protocol": port_elem.get("protocol", "tcp"),
                            "state": state_elem.get("state"),
                            "service": None,
                            "version": None,
                            "product": None,
                            "extra_info": None
                        }
                        
                        service_elem = port_elem.find("service")
                        if service_elem is not None:
                            port["service"] = service_elem.get("name")
                            port["product"] = service_elem.get("product")
                            port["version"] = service_elem.get("version")
                            port["extra_info"] = service_elem.get("extrainfo")
                        
                        host["ports"].append(port)
                
                hosts.append(host)
            
        except ET.ParseError as e:
            self.log(f"XML parse error: {e}", "ERROR")
        except Exception as e:
            self.log(f"Error parsing nmap output: {e}", "ERROR")
        
        return hosts
    
    async def run_nikto_scan(self, command_id: str, command_data: dict) -> dict:
        """Run a Nikto web vulnerability scan"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        # Check if nikto is installed, auto-install if needed
        installed, install_msg = await self.ensure_tool_installed("nikto")
        if not installed:
            response["success"] = False
            response["error"] = install_msg
            return response
        if install_msg == "installed":
            response["data"]["auto_installed"] = "nikto"
        
        # Get options
        port = command_data.get("port", 80)
        ssl = command_data.get("ssl", False)
        tuning = command_data.get("tuning", "")  # Nikto tuning options
        project_id = command_data.get("project_id")
        
        # Build nikto command
        cmd = ["nikto", "-h", target, "-p", str(port), "-Format", "json", "-o", "-"]
        
        if ssl or port == 443:
            cmd.extend(["-ssl"])
        
        if tuning:
            safe_tuning = tuning.replace(";", "").replace("&", "").replace("|", "")
            cmd.extend(["-Tuning", safe_tuning])
        
        self.log(f"Running nikto scan: {' '.join(cmd)}")
        
        # Get job_id for progress updates
        job_id = command_data.get("job_id")
        
        try:
            # Send initial progress
            if job_id:
                await self.send_job_progress(job_id, 15, f"Starting Nikto scan on {target}:{port}...")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Read stderr for progress updates (nikto outputs to stderr)
            stdout_data = b""
            stderr_data = b""
            items_found = 0
            
            async def read_stdout():
                nonlocal stdout_data
                stdout_data = await process.stdout.read()
            
            async def read_stderr_with_progress():
                nonlocal stderr_data, items_found
                while True:
                    line = await process.stderr.readline()
                    if not line:
                        break
                    stderr_data += line
                    line_str = line.decode("utf-8", errors="replace")
                    
                    # Count items found and update progress
                    if job_id and ("+ " in line_str or "OSVDB" in line_str):
                        items_found += 1
                        # Update every 5 items
                        if items_found % 5 == 0:
                            await self.send_job_progress(job_id, min(85, 20 + items_found), f"Scanning... {items_found} items checked")
            
            try:
                await asyncio.wait_for(
                    asyncio.gather(read_stdout(), read_stderr_with_progress()),
                    timeout=1800  # 30 minute timeout for nikto
                )
            except asyncio.TimeoutError:
                process.kill()
                raise
            
            await process.wait()
            
            if job_id:
                await self.send_job_progress(job_id, 90, "Parsing scan results...")
            
            output = stdout_data.decode("utf-8", errors="replace")
            
            # Parse JSON output if possible
            findings = []
            try:
                nikto_data = json.loads(output)
                if isinstance(nikto_data, list):
                    for item in nikto_data:
                        if "vulnerabilities" in item:
                            findings.extend(item.get("vulnerabilities", []))
                elif isinstance(nikto_data, dict):
                    findings = nikto_data.get("vulnerabilities", [])
            except json.JSONDecodeError:
                # Fallback to raw output
                findings = [{"raw_output": output}]
            
            response["data"] = {
                "target": target,
                "port": port,
                "ssl": ssl,
                "findings": findings,
                "finding_count": len(findings),
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"Nikto scan complete: found {len(findings)} finding(s)")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Nikto scan timed out (30 minute limit)"
            self.log("Nikto scan timed out", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Nikto error: {e}", "ERROR")
        
        return response
    
    async def run_dirb_scan(self, command_id: str, command_data: dict) -> dict:
        """Run a Dirb directory brute force scan"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        # Check if dirb is installed, auto-install if needed
        installed, install_msg = await self.ensure_tool_installed("dirb")
        if not installed:
            response["success"] = False
            response["error"] = install_msg
            return response
        if install_msg == "installed":
            response["data"]["auto_installed"] = "dirb"
        
        # Ensure URL has scheme
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        
        # Get options
        wordlist = command_data.get("wordlist", "/usr/share/dirb/wordlists/common.txt")
        extensions = command_data.get("extensions", "")
        project_id = command_data.get("project_id")
        
        # Build dirb command
        cmd = ["dirb", target, wordlist, "-o", "-", "-S"]  # -S for silent mode, -o - for stdout
        
        if extensions:
            safe_ext = extensions.replace(";", "").replace("&", "").replace("|", "")
            cmd.extend(["-X", safe_ext])
        
        self.log(f"Running dirb scan: {' '.join(cmd)}")
        
        # Get job_id for progress updates
        job_id = command_data.get("job_id")
        
        try:
            # Send initial progress
            if job_id:
                await self.send_job_progress(job_id, 15, f"Starting directory scan on {target}...")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Read stdout for results and progress
            output_lines = []
            directories = []
            items_checked = 0
            
            async def read_stdout_with_progress():
                nonlocal output_lines, directories, items_checked
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    line_str = line.decode("utf-8", errors="replace").strip()
                    output_lines.append(line_str)
                    # Stream line back to server for live UI output
                    if job_id and line_str:
                        try:
                            await self.send_job_output(job_id, line_str)
                        except Exception:
                            pass
                    
                    # Parse results as they come in
                    if line_str.startswith("+ ") or line_str.startswith("==> DIRECTORY: "):
                        if line_str.startswith("+ "):
                            parts = line_str[2:].split(" ")
                            if parts:
                                directories.append({
                                    "url": parts[0],
                                    "type": "file",
                                    "status": parts[1] if len(parts) > 1 else ""
                                })
                        else:
                            url = line_str.replace("==> DIRECTORY: ", "").strip()
                            directories.append({
                                "url": url,
                                "type": "directory"
                            })
                        
                        # Update progress when finding items
                        if job_id and len(directories) % 3 == 0:
                            await self.send_job_progress(job_id, min(85, 25 + len(directories)), f"Found {len(directories)} items...")
                    
                    # Track tested words for progress
                    if "TESTED:" in line_str or "Testing:" in line_str.lower():
                        items_checked += 1
                        if job_id and items_checked % 100 == 0:
                            await self.send_job_progress(job_id, min(80, 20 + (items_checked // 50)), f"Testing... {items_checked} words checked")
            
            async def read_stderr():
                await process.stderr.read()
            
            try:
                await asyncio.wait_for(
                    asyncio.gather(read_stdout_with_progress(), read_stderr()),
                    timeout=1800  # 30 minute timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                raise
            
            await process.wait()
            
            if job_id:
                await self.send_job_progress(job_id, 95, "Finishing scan...")
            
            response["data"] = {
                "target": target,
                "wordlist": wordlist,
                "directories": directories,
                "directory_count": len(directories),
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"Dirb scan complete: found {len(directories)} directory/file(s)")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Dirb scan timed out (30 minute limit)"
            self.log("Dirb scan timed out", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Dirb error: {e}", "ERROR")
        
        return response
    
    async def run_sslscan(self, command_id: str, command_data: dict) -> dict:
        """Run an SSL/TLS scan"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        # Check if sslscan is installed, auto-install if needed
        installed, install_msg = await self.ensure_tool_installed("sslscan")
        if not installed:
            response["success"] = False
            response["error"] = install_msg
            return response
        if install_msg == "installed":
            response["data"]["auto_installed"] = "sslscan"
        
        # Get options
        port = command_data.get("port", 443)
        project_id = command_data.get("project_id")
        
        # Build sslscan command
        target_with_port = f"{target}:{port}"
        cmd = ["sslscan", "--xml=-", target_with_port]
        
        self.log(f"Running sslscan: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=120  # 2 minute timeout for sslscan
            )
            
            xml_output = stdout.decode("utf-8", errors="replace")
            
            # Parse XML output
            ssl_info = self.parse_sslscan_xml(xml_output)
            
            response["data"] = {
                "target": target,
                "port": port,
                "ssl_info": ssl_info,
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"SSLscan complete")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "SSLscan timed out (2 minute limit)"
            self.log("SSLscan timed out", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"SSLscan error: {e}", "ERROR")
        
        return response
    
    def parse_sslscan_xml(self, xml_output: str) -> dict:
        """Parse sslscan XML output"""
        import xml.etree.ElementTree as ET
        
        result = {
            "protocols": [],
            "ciphers": [],
            "certificate": {},
            "vulnerabilities": []
        }
        
        try:
            root = ET.fromstring(xml_output)
            
            # Parse SSL/TLS versions
            for proto in root.findall(".//protocol"):
                result["protocols"].append({
                    "type": proto.get("type"),
                    "version": proto.get("version"),
                    "enabled": proto.get("enabled") == "1"
                })
            
            # Parse ciphers
            for cipher in root.findall(".//cipher"):
                result["ciphers"].append({
                    "status": cipher.get("status"),
                    "sslversion": cipher.get("sslversion"),
                    "bits": cipher.get("bits"),
                    "cipher": cipher.get("cipher"),
                    "strength": cipher.get("strength", "unknown")
                })
            
            # Parse certificate info
            cert = root.find(".//certificate")
            if cert is not None:
                sig_algo = cert.find("signature-algorithm")
                pk = cert.find("pk")
                subject = cert.find("subject")
                issuer = cert.find("issuer")
                
                result["certificate"] = {
                    "signature_algorithm": sig_algo.text if sig_algo is not None else None,
                    "pk_type": pk.get("type") if pk is not None else None,
                    "pk_bits": pk.get("bits") if pk is not None else None,
                    "subject": subject.text if subject is not None else None,
                    "issuer": issuer.text if issuer is not None else None
                }
                
                # Check for self-signed
                self_signed = cert.find("self-signed")
                if self_signed is not None and self_signed.text == "true":
                    result["vulnerabilities"].append("Self-signed certificate")
                
                # Check expiry
                not_valid_after = cert.find("not-valid-after")
                if not_valid_after is not None:
                    result["certificate"]["expires"] = not_valid_after.text
            
            # Check for vulnerabilities
            heartbleed = root.find(".//heartbleed")
            if heartbleed is not None and heartbleed.get("vulnerable") == "1":
                result["vulnerabilities"].append("Heartbleed (CVE-2014-0160)")
            
        except ET.ParseError as e:
            self.log(f"XML parse error: {e}", "ERROR")
        except Exception as e:
            self.log(f"Error parsing sslscan output: {e}", "ERROR")
        
        return result
    
    async def run_gobuster_scan(self, command_id: str, command_data: dict) -> dict:
        """Run a Gobuster directory/DNS scan"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        # Check if gobuster is installed, auto-install if needed
        installed, install_msg = await self.ensure_tool_installed("gobuster")
        if not installed:
            response["success"] = False
            response["error"] = install_msg
            return response
        if install_msg == "installed":
            response["data"]["auto_installed"] = "gobuster"
        
        # Ensure URL has scheme
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        
        # Get options
        mode = command_data.get("mode", "dir")  # dir, dns, vhost
        wordlist = command_data.get("wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
        extensions = command_data.get("extensions", "")
        threads = command_data.get("threads", 10)
        project_id = command_data.get("project_id")
        
        # Build gobuster command
        cmd = ["gobuster", mode, "-u", target, "-w", wordlist, "-t", str(threads), "-q", "--no-progress"]
        
        if extensions and mode == "dir":
            safe_ext = extensions.replace(";", "").replace("&", "").replace("|", "")
            cmd.extend(["-x", safe_ext])
        
        self.log(f"Running gobuster scan: {' '.join(cmd)}")
        
        # Get job_id for progress updates
        job_id = command_data.get("job_id")
        
        try:
            # Send initial progress
            if job_id:
                await self.send_job_progress(job_id, 15, f"Starting Gobuster scan on {target}...")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Read stdout for results
            entries = []
            
            async def read_stdout_with_progress():
                nonlocal entries
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    line_str = line.decode("utf-8", errors="replace").strip()
                    if not line_str:
                        continue
                    # Stream line back to server for live UI output
                    if job_id and line_str:
                        try:
                            await self.send_job_output(job_id, line_str)
                        except Exception:
                            pass
                    
                    # Parse results: /path (Status: 200) [Size: 1234]
                    if "(Status:" in line_str:
                        parts = line_str.split(" ")
                        if parts:
                            path = parts[0]
                            status = ""
                            size = ""
                            for i, p in enumerate(parts):
                                if p == "(Status:":
                                    status = parts[i + 1].rstrip(")")
                                if p == "[Size:":
                                    size = parts[i + 1].rstrip("]")
                            entries.append({
                                "path": path,
                                "status": status,
                                "size": size
                            })
                            
                            # Update progress when finding items
                            if job_id and len(entries) % 5 == 0:
                                await self.send_job_progress(job_id, min(85, 25 + len(entries)), f"Found {len(entries)} entries...")
            
            async def read_stderr():
                await process.stderr.read()
            
            try:
                await asyncio.wait_for(
                    asyncio.gather(read_stdout_with_progress(), read_stderr()),
                    timeout=1800  # 30 minute timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                raise
            
            await process.wait()
            
            if job_id:
                await self.send_job_progress(job_id, 95, "Finishing scan...")
            
            response["data"] = {
                "target": target,
                "mode": mode,
                "wordlist": wordlist,
                "entries": entries,
                "entry_count": len(entries),
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"Gobuster scan complete: found {len(entries)} entries")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Gobuster scan timed out (30 minute limit)"
            self.log("Gobuster scan timed out", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Gobuster error: {e}", "ERROR")
        
        return response
    
    async def run_whatweb_scan(self, command_id: str, command_data: dict) -> dict:
        """Run a WhatWeb web technology fingerprinting scan"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        # Check if whatweb is installed, auto-install if needed
        installed, install_msg = await self.ensure_tool_installed("whatweb")
        if not installed:
            response["success"] = False
            response["error"] = install_msg
            return response
        if install_msg == "installed":
            response["data"]["auto_installed"] = "whatweb"
        
        # Ensure URL has scheme
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        
        # Get options
        aggression = command_data.get("aggression", 1)  # 1-4
        project_id = command_data.get("project_id")
        
        # Build whatweb command
        cmd = ["whatweb", "-a", str(aggression), "--log-json=-", target]
        
        self.log(f"Running whatweb scan: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=240  # 4 minute timeout for complex sites
            )
            
            output = stdout.decode("utf-8", errors="replace")
            
            # Parse JSON output
            technologies = []
            try:
                for line in output.strip().split("\n"):
                    if line:
                        data = json.loads(line)
                        if "plugins" in data:
                            for plugin, info in data.get("plugins", {}).items():
                                tech = {"name": plugin}
                                if isinstance(info, dict):
                                    tech["version"] = info.get("version", [None])[0] if info.get("version") else None
                                technologies.append(tech)
            except json.JSONDecodeError:
                technologies = [{"raw_output": output}]
            
            response["data"] = {
                "target": target,
                "technologies": technologies,
                "technology_count": len(technologies),
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"WhatWeb scan complete: found {len(technologies)} technologies")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "WhatWeb scan timed out (4 minute limit)"
            self.log("WhatWeb scan timed out", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"WhatWeb error: {e}", "ERROR")
        
        return response
    
    async def run_traceroute(self, command_id: str, command_data: dict) -> dict:
        """Run a visual traceroute to a target with live hop streaming"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        # Check if traceroute is installed, auto-install if needed
        installed, install_msg = await self.ensure_tool_installed("traceroute")
        if not installed:
            response["success"] = False
            response["error"] = install_msg
            return response
        if install_msg == "installed":
            response["data"]["auto_installed"] = "traceroute"
        
        # Get options
        max_hops = command_data.get("max_hops", 30)
        timeout = command_data.get("timeout", 2)
        project_id = command_data.get("project_id")
        host_id = command_data.get("host_id")
        job_id = command_data.get("job_id")
        
        # Build traceroute command
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout), target]
        
        self.log(f"Running live traceroute: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            hops = []
            raw_output = ""
            
            # Read stdout line by line for live streaming
            while True:
                try:
                    line = await asyncio.wait_for(
                        process.stdout.readline(),
                        timeout=30  # 30 second timeout per line
                    )
                    if not line:
                        break
                    
                    line_text = line.decode("utf-8", errors="replace").strip()
                    raw_output += line_text + "\n"
                    
                    # Skip header line
                    if line_text.startswith('traceroute') or 'hops max' in line_text.lower():
                        continue
                    
                    # Parse hop line: "1  192.168.1.1  1.234 ms  1.456 ms  1.789 ms"
                    parts = line_text.split()
                    if len(parts) >= 2:
                        try:
                            hop_num = int(parts[0])
                            ip = parts[1] if parts[1] != '*' else None
                            
                            # Get RTT values
                            rtts = []
                            for part in parts[2:]:
                                if part != '*' and part != 'ms':
                                    try:
                                        rtts.append(float(part))
                                    except ValueError:
                                        pass
                            
                            hop_data = {
                                "hop": hop_num,
                                "ip": ip,
                                "rtts": rtts,
                                "rtt_ms": round(sum(rtts) / len(rtts), 2) if rtts else None
                            }
                            hops.append(hop_data)
                            
                            # Send live hop update via WebSocket
                            await self.send_traceroute_hop(
                                command_id=command_id,
                                host_id=host_id,
                                job_id=job_id,
                                target=target,
                                hop=hop_data
                            )
                            
                            self.log(f"Hop {hop_num}: {ip or '* * *'} - {hop_data.get('rtt_ms', '-')}ms")
                            
                        except (ValueError, IndexError):
                            continue
                            
                except asyncio.TimeoutError:
                    self.log(f"Timeout waiting for hop, continuing...", "WARNING")
                    continue
            
            # Wait for process to complete
            await asyncio.wait_for(process.wait(), timeout=10)
            
            response["data"] = {
                "target": target,
                "hops": hops,
                "hop_count": len(hops),
                "raw_output": raw_output,
                "project_id": project_id,
                "host_id": host_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"Traceroute complete: {len(hops)} hops")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Traceroute timed out (2 minute limit)"
            self.log("Traceroute timed out", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Traceroute error: {e}", "ERROR")
        
        return response
    
    async def run_ssh_audit(self, command_id: str, command_data: dict) -> dict:
        """Run SSH audit to check SSH server security"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        port = command_data.get("port", 22)
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        project_id = command_data.get("project_id")
        
        # Try to connect and get SSH banner/info using socket
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, int(port)))
            
            # Get banner
            banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
            sock.close()
            
            # Parse banner for version info
            ssh_version = None
            software = None
            if banner:
                parts = banner.split()
                if len(parts) >= 1:
                    ssh_version = parts[0]
                if len(parts) >= 2:
                    software = parts[1] if len(parts) > 1 else None
            
            response["data"] = {
                "target": target,
                "port": port,
                "banner": banner,
                "ssh_version": ssh_version,
                "software": software,
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"SSH audit complete: {banner}")
            
        except socket.timeout:
            response["success"] = False
            response["error"] = "Connection timed out"
        except ConnectionRefusedError:
            response["success"] = False
            response["error"] = "Connection refused - SSH port may be closed"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"SSH audit error: {e}", "ERROR")
        
        return response
    
    async def run_ftp_anon(self, command_id: str, command_data: dict) -> dict:
        """Check if FTP server allows anonymous login"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        port = command_data.get("port", 21)
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        project_id = command_data.get("project_id")
        
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, int(port)))
            
            # Get banner
            banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
            
            # Try anonymous login
            sock.send(b"USER anonymous\r\n")
            user_response = sock.recv(1024).decode('utf-8', errors='replace').strip()
            
            anonymous_allowed = False
            if "331" in user_response:  # 331 = password required
                sock.send(b"PASS anonymous@\r\n")
                pass_response = sock.recv(1024).decode('utf-8', errors='replace').strip()
                anonymous_allowed = "230" in pass_response  # 230 = login successful
            
            sock.send(b"QUIT\r\n")
            sock.close()
            
            response["data"] = {
                "target": target,
                "port": port,
                "banner": banner,
                "anonymous_allowed": anonymous_allowed,
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"FTP anonymous check complete: anonymous={'allowed' if anonymous_allowed else 'denied'}")
            
        except socket.timeout:
            response["success"] = False
            response["error"] = "Connection timed out"
        except ConnectionRefusedError:
            response["success"] = False
            response["error"] = "Connection refused - FTP port may be closed"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"FTP anon check error: {e}", "ERROR")
        
        return response
    
    async def run_smtp_scan(self, command_id: str, command_data: dict) -> dict:
        """Scan SMTP server for info and capabilities"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        port = command_data.get("port", 25)
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        project_id = command_data.get("project_id")
        
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, int(port)))
            
            # Get banner
            banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
            
            # Send EHLO to get capabilities
            sock.send(b"EHLO test\r\n")
            ehlo_response = sock.recv(2048).decode('utf-8', errors='replace').strip()
            
            # Parse capabilities from EHLO response
            capabilities = []
            for line in ehlo_response.split('\n'):
                line = line.strip()
                if line.startswith('250-') or line.startswith('250 '):
                    cap = line[4:].strip()
                    if cap and cap.upper() != target.upper():
                        capabilities.append(cap)
            
            sock.send(b"QUIT\r\n")
            sock.close()
            
            response["data"] = {
                "target": target,
                "port": port,
                "banner": banner,
                "capabilities": capabilities,
                "supports_starttls": any('STARTTLS' in c.upper() for c in capabilities),
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"SMTP scan complete: {len(capabilities)} capabilities")
            
        except socket.timeout:
            response["success"] = False
            response["error"] = "Connection timed out"
        except ConnectionRefusedError:
            response["success"] = False
            response["error"] = "Connection refused - SMTP port may be closed"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"SMTP scan error: {e}", "ERROR")
        
        return response
    
    async def run_imap_scan(self, command_id: str, command_data: dict) -> dict:
        """Scan IMAP server for info and capabilities"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        port = command_data.get("port", 143)
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        project_id = command_data.get("project_id")
        
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, int(port)))
            
            # Get banner
            banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
            
            # Send CAPABILITY command
            sock.send(b"a001 CAPABILITY\r\n")
            cap_response = sock.recv(2048).decode('utf-8', errors='replace').strip()
            
            # Parse capabilities
            capabilities = []
            for line in cap_response.split('\n'):
                if 'CAPABILITY' in line.upper():
                    parts = line.split()
                    for part in parts:
                        part = part.strip()
                        if part and part.upper() not in ['*', 'CAPABILITY', 'A001', 'OK']:
                            capabilities.append(part)
            
            sock.send(b"a002 LOGOUT\r\n")
            sock.close()
            
            response["data"] = {
                "target": target,
                "port": port,
                "banner": banner,
                "capabilities": capabilities,
                "supports_starttls": any('STARTTLS' in c.upper() for c in capabilities),
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"IMAP scan complete: {len(capabilities)} capabilities")
            
        except socket.timeout:
            response["success"] = False
            response["error"] = "Connection timed out"
        except ConnectionRefusedError:
            response["success"] = False
            response["error"] = "Connection refused - IMAP port may be closed"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"IMAP scan error: {e}", "ERROR")
        
        return response
    
    async def run_banner_grab(self, command_id: str, command_data: dict) -> dict:
        """Grab banner from any TCP service"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        port = command_data.get("port", 80)
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        project_id = command_data.get("project_id")
        
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, int(port)))
            
            # Try to get banner (some services send on connect)
            banner = ""
            try:
                sock.setblocking(False)
                import select
                ready, _, _ = select.select([sock], [], [], 3)
                if ready:
                    banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
            except:
                pass
            
            # If no banner, try sending probe data
            if not banner:
                sock.setblocking(True)
                sock.settimeout(5)
                # Send HTTP probe for common ports
                if port in [80, 8080, 8000, 8888, 443]:
                    sock.send(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
                else:
                    sock.send(b"\r\n")
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
                except:
                    pass
            
            sock.close()
            
            response["data"] = {
                "target": target,
                "port": port,
                "banner": banner,
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"Banner grab complete: {len(banner)} bytes")
            
        except socket.timeout:
            response["success"] = False
            response["error"] = "Connection timed out"
        except ConnectionRefusedError:
            response["success"] = False
            response["error"] = f"Connection refused - port {port} may be closed"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Banner grab error: {e}", "ERROR")
        
        return response
    
    async def run_screenshot(self, command_id: str, command_data: dict) -> dict:
        """Take a screenshot of a web page"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        port = command_data.get("port", 80)
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        project_id = command_data.get("project_id")
        
        # Determine URL
        if not target.startswith(("http://", "https://")):
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{target}:{port}" if port not in [80, 443] else f"{scheme}://{target}"
        else:
            url = target
        
        # Check for chromium/chrome, auto-install if needed
        browser = None
        for b in ["chromium", "chromium-browser", "google-chrome", "chrome"]:
            if shutil.which(b):
                browser = b
                break
        
        if not browser:
            # Try to auto-install chromium
            installed, install_msg = await self.ensure_tool_installed("chromium")
            if installed:
                # Check again after install
                for b in ["chromium", "chromium-browser"]:
                    if shutil.which(b):
                        browser = b
                        break
                if browser and install_msg == "installed":
                    response["data"]["auto_installed"] = "chromium"
        
        if not browser:
            response["success"] = False
            response["error"] = "No browser available (chromium/chrome required). Auto-install failed or requires root privileges."
            return response
        
        try:
            import tempfile
            import base64
            
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
                tmp_path = tmp.name
            
            cmd = [
                browser,
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                f"--screenshot={tmp_path}",
                "--window-size=1280,1024",
                "--hide-scrollbars",
                "--timeout=60000",  # 60 second page load timeout
                url
            ]
            
            self.log(f"Taking screenshot: {url}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=90)  # 90 seconds for slow sites
            
            # Log chromium result for debugging
            if process.returncode != 0:
                self.log(f"Chromium exited with code {process.returncode}, stderr: {stderr.decode('utf-8', errors='replace')[:500]}", "WARNING")
            
            # Read and encode screenshot
            import os
            if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
                with open(tmp_path, 'rb') as f:
                    screenshot_data = base64.b64encode(f.read()).decode('utf-8')
                os.unlink(tmp_path)
                
                response["data"] = {
                    "target": target,
                    "url": url,
                    "port": port,
                    "screenshot": screenshot_data,
                    "project_id": project_id,
                    "scanned_at": datetime.utcnow().isoformat(),
                    "agent_id": self.agent_id,
                    "agent_hostname": self.hostname
                }
                # Log size info for debugging large responses
                response_size = len(json.dumps(response))
                self.log(f"Screenshot complete: {len(screenshot_data)} bytes base64, response size: {response_size} bytes")
            else:
                response["success"] = False
                response["error"] = "Screenshot file was not created"
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                    
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Screenshot timed out"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Screenshot error: {e}", "ERROR")
        
        return response
    
    async def run_http_headers(self, command_id: str, command_data: dict) -> dict:
        """Get HTTP headers from a web server"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        port = command_data.get("port", 80)
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        project_id = command_data.get("project_id")
        
        # Determine URL
        if not target.startswith(("http://", "https://")):
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{target}:{port}" if port not in [80, 443] else f"{scheme}://{target}"
        else:
            url = target
        
        try:
            import urllib.request
            import ssl
            
            # Create request
            req = urllib.request.Request(url, method='HEAD')
            req.add_header('User-Agent', 'Mozilla/5.0 (compatible; MicroHack/1.0)')
            
            # Handle SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=10, context=context) as resp:
                headers = dict(resp.headers)
                status_code = resp.status
            
            response["data"] = {
                "target": target,
                "url": url,
                "port": port,
                "status_code": status_code,
                "headers": headers,
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"HTTP headers complete: {len(headers)} headers")
            
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"HTTP headers error: {e}", "ERROR")
        
        return response
    
    async def run_robots_fetch(self, command_id: str, command_data: dict) -> dict:
        """Fetch robots.txt from a web server"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        port = command_data.get("port", 80)
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        project_id = command_data.get("project_id")
        
        # Determine base URL
        if not target.startswith(("http://", "https://")):
            scheme = "https" if port == 443 else "http"
            base_url = f"{scheme}://{target}:{port}" if port not in [80, 443] else f"{scheme}://{target}"
        else:
            base_url = target.rstrip('/')
        
        robots_url = f"{base_url}/robots.txt"
        
        try:
            import urllib.request
            import ssl
            
            req = urllib.request.Request(robots_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (compatible; MicroHack/1.0)')
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=10, context=context) as resp:
                content = resp.read().decode('utf-8', errors='replace')
                status_code = resp.status
            
            # Parse robots.txt
            disallowed = []
            allowed = []
            sitemaps = []
            
            for line in content.split('\n'):
                line = line.strip()
                if line.lower().startswith('disallow:'):
                    path = line[9:].strip()
                    if path:
                        disallowed.append(path)
                elif line.lower().startswith('allow:'):
                    path = line[6:].strip()
                    if path:
                        allowed.append(path)
                elif line.lower().startswith('sitemap:'):
                    sitemap = line[8:].strip()
                    if sitemap:
                        sitemaps.append(sitemap)
            
            response["data"] = {
                "target": target,
                "url": robots_url,
                "port": port,
                "status_code": status_code,
                "content": content,
                "disallowed": disallowed,
                "allowed": allowed,
                "sitemaps": sitemaps,
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"Robots.txt fetch complete: {len(disallowed)} disallowed, {len(sitemaps)} sitemaps")
            
        except urllib.error.HTTPError as e:
            if e.code == 404:
                response["data"] = {
                    "target": target,
                    "url": robots_url,
                    "port": port,
                    "status_code": 404,
                    "content": None,
                    "disallowed": [],
                    "allowed": [],
                    "sitemaps": [],
                    "project_id": project_id,
                    "scanned_at": datetime.utcnow().isoformat()
                }
                self.log("No robots.txt found (404)")
            else:
                response["success"] = False
                response["error"] = f"HTTP error: {e.code}"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Robots.txt fetch error: {e}", "ERROR")
        
        return response
    
    async def run_dns_server_scan(self, command_id: str, command_data: dict) -> dict:
        """Interrogate a DNS server for security issues (requires dig)"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        port = command_data.get("port", 53)
        
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        # Check if dig is available, auto-install if needed
        installed, install_msg = await self.ensure_tool_installed("dig")
        if not installed:
            response["success"] = False
            response["error"] = install_msg
            return response
        if install_msg == "installed":
            response["data"]["auto_installed"] = "dig"
        
        try:
            import re
            results = {
                'server_version': None,
                'server_hostname': None,
                'recursion_enabled': False,
                'recursion_test_result': None,
                'zone_transfer_enabled': False,
                'cache_snooping_possible': False,
                'cached_domains': [],
                'dnssec_enabled': False,
                'amplification_factor': None,
                'raw_output': ''
            }
            raw_outputs = []
            test_domain = 'google.com'
            
            # Version Query (CHAOS)
            try:
                process = await asyncio.create_subprocess_exec(
                    "dig", f"@{target}", "-p", str(port), "version.bind", "TXT", "CHAOS", "+short",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
                output = stdout.decode().strip().strip('"')
                raw_outputs.append(f"=== Version Query ===\n{output}")
                if output and not output.startswith(';') and 'connection refused' not in output.lower():
                    results['server_version'] = output
            except asyncio.TimeoutError:
                raw_outputs.append("Version query timed out")
            except Exception as e:
                raw_outputs.append(f"Version query failed: {e}")
            
            # Hostname Query (CHAOS)
            try:
                process = await asyncio.create_subprocess_exec(
                    "dig", f"@{target}", "-p", str(port), "hostname.bind", "TXT", "CHAOS", "+short",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
                output = stdout.decode().strip().strip('"')
                raw_outputs.append(f"=== Hostname Query ===\n{output}")
                if output and not output.startswith(';') and 'connection refused' not in output.lower():
                    results['server_hostname'] = output
            except asyncio.TimeoutError:
                raw_outputs.append("Hostname query timed out")
            except Exception as e:
                raw_outputs.append(f"Hostname query failed: {e}")
            
            # Recursion Check (Open Resolver Test)
            try:
                process = await asyncio.create_subprocess_exec(
                    "dig", f"@{target}", "-p", str(port), test_domain, "A", "+recurse", "+short",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
                output = stdout.decode().strip()
                raw_outputs.append(f"=== Recursion Test ===\n{output}")
                if output and not output.startswith(';') and 'REFUSED' not in output.upper():
                    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', output)
                    if ips:
                        results['recursion_enabled'] = True
                        results['recursion_test_result'] = f"Resolved {test_domain} to: {', '.join(ips)}"
            except asyncio.TimeoutError:
                raw_outputs.append("Recursion test timed out")
            except Exception as e:
                raw_outputs.append(f"Recursion test failed: {e}")
            
            # Cache Snooping
            cached_domains = []
            domains_to_check = ['google.com', 'facebook.com', 'microsoft.com']
            for domain in domains_to_check:
                try:
                    process = await asyncio.create_subprocess_exec(
                        "dig", f"@{target}", "-p", str(port), domain, "A", "+norecurse", "+short",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)
                    output = stdout.decode().strip()
                    if output and not output.startswith(';') and 'REFUSED' not in output.upper():
                        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', output)
                        if ips:
                            cached_domains.append({'domain': domain, 'cached_ips': ips})
                except:
                    pass
            
            if cached_domains:
                results['cache_snooping_possible'] = True
                results['cached_domains'] = cached_domains
            raw_outputs.append(f"=== Cache Snooping ===\nCached: {len(cached_domains)} domains")
            
            # DNSSEC Check
            try:
                process = await asyncio.create_subprocess_exec(
                    "dig", f"@{target}", "-p", str(port), test_domain, "DNSKEY", "+short",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
                output = stdout.decode().strip()
                if output and not output.startswith(';'):
                    results['dnssec_enabled'] = True
                raw_outputs.append(f"=== DNSSEC ===\n{output[:200] if output else 'None'}")
            except:
                pass
            
            # Amplification Test
            try:
                process = await asyncio.create_subprocess_exec(
                    "dig", f"@{target}", "-p", str(port), test_domain, "ANY", "+bufsize=4096",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
                output = stdout.decode()
                if output:
                    response_size = len(output)
                    request_size = 50
                    results['amplification_factor'] = round(response_size / request_size, 2)
                raw_outputs.append(f"=== Amplification ===\nResponse size: {len(output)} bytes")
            except:
                pass
            
            results['raw_output'] = '\n\n'.join(raw_outputs)
            
            response["data"] = {
                "target": target,
                "port": port,
                "dns_server": results,
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname,
                "scanned_at": datetime.utcnow().isoformat()
            }
            
            self.log(f"DNS server scan complete: recursion={results['recursion_enabled']}")
            
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"DNS server scan error: {e}", "ERROR")
        
        return response
    
    async def run_dig_lookup(self, command_id: str, command_data: dict) -> dict:
        """Perform dig DNS lookup (requires dig)"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        query_type = command_data.get("query_type", "A")
        dns_server = command_data.get("dns_server", "1.1.1.1")
        
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        # Check if dig is available, auto-install if needed
        installed, install_msg = await self.ensure_tool_installed("dig")
        if not installed:
            response["success"] = False
            response["error"] = install_msg
            return response
        if install_msg == "installed":
            response["data"]["auto_installed"] = "dig"
        
        try:
            # Run dig with full output to parse answers, authority, and additional sections
            process = await asyncio.create_subprocess_exec(
                "dig", f"@{dns_server}", target, query_type,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
            
            output = stdout.decode().strip()
            
            # Parse dig output into structured sections
            answers = []
            authority = []
            additional = []
            status = "NOERROR"
            query_time_ms = None
            
            current_section = None
            for line in output.split('\n'):
                line = line.strip()
                if not line or line.startswith(';;'):
                    # Check for section headers and status
                    if 'ANSWER SECTION' in line:
                        current_section = 'answer'
                    elif 'AUTHORITY SECTION' in line:
                        current_section = 'authority'
                    elif 'ADDITIONAL SECTION' in line:
                        current_section = 'additional'
                    elif 'status:' in line:
                        # Extract status like "status: NXDOMAIN"
                        import re
                        match = re.search(r'status:\s*(\w+)', line)
                        if match:
                            status = match.group(1)
                    elif 'Query time:' in line:
                        # Extract query time like "Query time: 23 msec"
                        import re
                        match = re.search(r'Query time:\s*(\d+)', line)
                        if match:
                            query_time_ms = int(match.group(1))
                    continue
                
                # Parse record lines (not comments)
                if current_section == 'answer' and line and not line.startswith(';'):
                    answers.append(line)
                elif current_section == 'authority' and line and not line.startswith(';'):
                    authority.append(line)
                elif current_section == 'additional' and line and not line.startswith(';'):
                    additional.append(line)
            
            response["data"] = {
                "target": target,
                "query_type": query_type,
                "dns_server": dns_server,
                "answers": answers,
                "authority": authority,
                "additional": additional,
                "status": status,
                "query_time_ms": query_time_ms,
                "success": status == "NOERROR" and len(answers) > 0,
                "raw_output": output,
                "records": answers,  # Keep for backwards compatibility
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname,
                "scanned_at": datetime.utcnow().isoformat()
            }
            
            self.log(f"Dig lookup complete: {len(answers)} answers, status={status}")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Dig lookup timed out"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Dig lookup error: {e}", "ERROR")
        
        return response
    
    async def run_ip_reputation(self, command_id: str, command_data: dict) -> dict:
        """Check IP reputation via DNS blacklists"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        try:
            import socket
            
            # Reverse the IP for DNSBL queries
            parts = target.split('.')
            if len(parts) != 4:
                response["success"] = False
                response["error"] = "Invalid IP address format"
                return response
            
            reversed_ip = '.'.join(reversed(parts))
            
            # Common DNSBLs to check
            dnsbls = [
                'zen.spamhaus.org',
                'bl.spamcop.net',
                'b.barracudacentral.org',
                'dnsbl.sorbs.net',
                'spam.dnsbl.sorbs.net'
            ]
            
            listings = []
            for dnsbl in dnsbls:
                query = f"{reversed_ip}.{dnsbl}"
                try:
                    socket.gethostbyname(query)
                    listings.append(dnsbl)
                except socket.gaierror:
                    pass  # Not listed
            
            response["data"] = {
                "target": target,
                "dnsbls_checked": len(dnsbls),
                "listings": listings,
                "is_listed": len(listings) > 0,
                "reputation_score": 100 - (len(listings) * 20),  # Simple score
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname,
                "scanned_at": datetime.utcnow().isoformat()
            }
            
            self.log(f"IP reputation check complete: listed on {len(listings)} DNSBLs")
            
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"IP reputation error: {e}", "ERROR")
        
        return response
    
    async def run_domain_reputation(self, command_id: str, command_data: dict) -> dict:
        """Check domain reputation"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        # Try to install dig for better results (optional - will work without it)
        installed, install_msg = await self.ensure_tool_installed("dig")
        if install_msg == "installed":
            response["data"]["auto_installed"] = "dig"
        
        try:
            import socket
            
            results = {
                'has_spf': False,
                'has_dkim': False,
                'has_dmarc': False,
                'mx_records': [],
                'ns_records': []
            }
            
            # Check SPF record
            try:
                if shutil.which("dig"):
                    process = await asyncio.create_subprocess_exec(
                        "dig", "+short", "TXT", target,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)
                    txt_records = stdout.decode().strip()
                    if 'v=spf1' in txt_records.lower():
                        results['has_spf'] = True
            except:
                pass
            
            # Check DMARC record
            try:
                if shutil.which("dig"):
                    process = await asyncio.create_subprocess_exec(
                        "dig", "+short", "TXT", f"_dmarc.{target}",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)
                    dmarc_record = stdout.decode().strip()
                    if 'v=dmarc1' in dmarc_record.lower():
                        results['has_dmarc'] = True
            except:
                pass
            
            # Get MX records
            try:
                if shutil.which("dig"):
                    process = await asyncio.create_subprocess_exec(
                        "dig", "+short", "MX", target,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)
                    mx = [r.strip() for r in stdout.decode().strip().split('\n') if r.strip()]
                    results['mx_records'] = mx
            except:
                pass
            
            # Get NS records
            try:
                if shutil.which("dig"):
                    process = await asyncio.create_subprocess_exec(
                        "dig", "+short", "NS", target,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)
                    ns = [r.strip() for r in stdout.decode().strip().split('\n') if r.strip()]
                    results['ns_records'] = ns
            except:
                pass
            
            # Calculate simple reputation score
            score = 50
            if results['has_spf']:
                score += 15
            if results['has_dmarc']:
                score += 20
            if results['mx_records']:
                score += 10
            if results['ns_records']:
                score += 5
            
            response["data"] = {
                "target": target,
                "reputation": results,
                "reputation_score": min(score, 100),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname,
                "scanned_at": datetime.utcnow().isoformat()
            }
            
            self.log(f"Domain reputation check complete: score={score}")
            
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Domain reputation error: {e}", "ERROR")
        
        return response
    
    async def run_speedtest(self, command_id: str, command_data: dict) -> dict:
        """Run internet speed test - prefers official Ookla CLI for accurate gigabit results"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        try:
            # Priority order:
            # 1. Official Ookla speedtest CLI (multi-threaded, accurate for gigabit)
            # 2. speedtest-cli (Python, single-threaded, caps around 100-200 Mbps)
            
            speedtest_cmd = None
            use_ookla = False
            
            # Check for official Ookla CLI first (it's just called 'speedtest')
            if shutil.which("speedtest"):
                # Verify it's the Ookla version by checking help output
                try:
                    process = await asyncio.create_subprocess_exec(
                        "speedtest", "--version",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await asyncio.wait_for(process.communicate(), timeout=5)
                    version_output = stdout.decode().lower()
                    if "ookla" in version_output or "speedtest by" in version_output:
                        speedtest_cmd = "speedtest"
                        use_ookla = True
                        self.log("Using official Ookla speedtest CLI (multi-threaded)")
                except:
                    pass
            
            # Fallback to speedtest-cli
            if not speedtest_cmd:
                if shutil.which("speedtest-cli"):
                    speedtest_cmd = "speedtest-cli"
                    self.log("Using speedtest-cli (note: may cap around 100-200 Mbps for fast connections)")
            
            # Try to install if nothing found
            if not speedtest_cmd:
                self.log("No speedtest tool found, attempting to install...")
                
                # Try to install official Ookla CLI first (Debian/Ubuntu)
                if self._is_root():
                    try:
                        # Add Ookla repository and install
                        install_script = """
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash && \
apt-get install -y speedtest
"""
                        process = await asyncio.create_subprocess_shell(
                            install_script,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        await asyncio.wait_for(process.communicate(), timeout=120)
                        if shutil.which("speedtest"):
                            speedtest_cmd = "speedtest"
                            use_ookla = True
                            response["data"]["auto_installed"] = "ookla-speedtest"
                    except:
                        pass
                
                # Fallback to pip install speedtest-cli
                if not speedtest_cmd:
                    try:
                        process = await asyncio.create_subprocess_exec(
                            "pip3", "install", "speedtest-cli",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        await asyncio.wait_for(process.communicate(), timeout=60)
                        if shutil.which("speedtest-cli"):
                            speedtest_cmd = "speedtest-cli"
                            response["data"]["auto_installed"] = "speedtest-cli"
                    except:
                        pass
            
            if not speedtest_cmd:
                response["success"] = False
                response["error"] = "No speedtest tool available. For gigabit speeds, install official Ookla CLI: https://www.speedtest.net/apps/cli"
                return response
            
            self.log(f"Running speedtest using {speedtest_cmd}...")
            
            if use_ookla:
                # Official Ookla CLI with JSON output and license acceptance
                process = await asyncio.create_subprocess_exec(
                    speedtest_cmd, "--format=json", "--accept-license", "--accept-gdpr",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=180)
                
                if process.returncode != 0:
                    response["success"] = False
                    response["error"] = f"Speedtest failed: {stderr.decode()}"
                    return response
                
                import json as json_module
                result = json_module.loads(stdout.decode())
                
                # Ookla CLI returns bandwidth in bytes/sec
                download_bps = result.get("download", {}).get("bandwidth", 0) * 8  # Convert to bits
                upload_bps = result.get("upload", {}).get("bandwidth", 0) * 8
                
                response["data"] = {
                    "ping_ms": result.get("ping", {}).get("latency"),
                    "jitter_ms": result.get("ping", {}).get("jitter"),
                    "download_mbps": round(download_bps / 1_000_000, 2),
                    "upload_mbps": round(upload_bps / 1_000_000, 2),
                    "download_bytes": result.get("download", {}).get("bytes"),
                    "upload_bytes": result.get("upload", {}).get("bytes"),
                    "packet_loss": result.get("packetLoss"),
                    "server": {
                        "id": result.get("server", {}).get("id"),
                        "name": result.get("server", {}).get("name"),
                        "location": result.get("server", {}).get("location"),
                        "country": result.get("server", {}).get("country"),
                        "host": result.get("server", {}).get("host"),
                        "ip": result.get("server", {}).get("ip")
                    },
                    "client": {
                        "ip": result.get("interface", {}).get("externalIp"),
                        "internal_ip": result.get("interface", {}).get("internalIp"),
                        "isp": result.get("isp"),
                    },
                    "result_url": result.get("result", {}).get("url"),
                    "tool": "ookla-speedtest",
                    "agent_id": self.agent_id,
                    "agent_hostname": self.hostname,
                    "tested_at": datetime.utcnow().isoformat()
                }
            else:
                # speedtest-cli (Python version)
                process = await asyncio.create_subprocess_exec(
                    speedtest_cmd, "--json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
                
                if process.returncode != 0:
                    # Try simple output
                    process = await asyncio.create_subprocess_exec(
                        speedtest_cmd, "--simple",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
                    
                    if process.returncode != 0:
                        response["success"] = False
                        response["error"] = f"Speedtest failed: {stderr.decode()}"
                        return response
                    
                    output = stdout.decode().strip()
                    lines = output.split('\n')
                    results = {"ping": None, "download": None, "upload": None}
                    for line in lines:
                        if line.startswith("Ping:"):
                            try: results["ping"] = float(line.split(":")[1].strip().split()[0])
                            except: pass
                        elif line.startswith("Download:"):
                            try: results["download"] = float(line.split(":")[1].strip().split()[0])
                            except: pass
                        elif line.startswith("Upload:"):
                            try: results["upload"] = float(line.split(":")[1].strip().split()[0])
                            except: pass
                    
                    response["data"] = {
                        "ping_ms": results["ping"],
                        "download_mbps": results["download"],
                        "upload_mbps": results["upload"],
                        "raw_output": output,
                        "tool": "speedtest-cli",
                        "note": "For accurate gigabit results, install official Ookla CLI",
                        "agent_id": self.agent_id,
                        "agent_hostname": self.hostname,
                        "tested_at": datetime.utcnow().isoformat()
                    }
                else:
                    import json as json_module
                    result = json_module.loads(stdout.decode())
                    
                    response["data"] = {
                        "ping_ms": result.get("ping"),
                        "download_mbps": round(result.get("download", 0) / 1_000_000, 2),
                        "upload_mbps": round(result.get("upload", 0) / 1_000_000, 2),
                        "server": {
                            "name": result.get("server", {}).get("name"),
                            "country": result.get("server", {}).get("country"),
                            "sponsor": result.get("server", {}).get("sponsor"),
                            "host": result.get("server", {}).get("host"),
                        },
                        "client": {
                            "ip": result.get("client", {}).get("ip"),
                            "isp": result.get("client", {}).get("isp"),
                            "country": result.get("client", {}).get("country")
                        },
                        "bytes_sent": result.get("bytes_sent"),
                        "bytes_received": result.get("bytes_received"),
                        "tool": "speedtest-cli",
                        "note": "For accurate gigabit results, install official Ookla CLI",
                        "agent_id": self.agent_id,
                        "agent_hostname": self.hostname,
                        "tested_at": datetime.utcnow().isoformat()
                    }
            
            self.log(f"Speedtest complete: {response['data'].get('download_mbps')} Mbps down, {response['data'].get('upload_mbps')} Mbps up")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Speedtest timed out (>180 seconds)"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Speedtest error: {e}", "ERROR")
        
        return response

    # =============================================================================
    # OSINT SCAN FUNCTIONS
    # =============================================================================
    
    async def run_email_osint(self, command_id: str, command_data: dict) -> dict:
        """Run email OSINT using holehe - checks which sites an email is registered on"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        email = command_data.get("email") or command_data.get("target")
        if not email:
            response["success"] = False
            response["error"] = "No email specified"
            return response
        
        # Auto-install holehe if not present
        installed, install_msg = await self.ensure_tool_installed("holehe")
        if not installed:
            response["success"] = False
            response["error"] = f"holehe not available and could not be installed: {install_msg}"
            return response
        if install_msg == "installed":
            response["data"]["auto_installed"] = "holehe"
        
        try:
            self.log(f"Running holehe email OSINT for: {email}")
            
            # Run holehe with CSV output for easier parsing
            process = await asyncio.create_subprocess_exec(
                "holehe", email, "--only-used", "-C",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            
            output = stdout.decode()
            results = []
            
            # Parse CSV output: site,used,email_recovery,phone_recovery,other
            lines = output.strip().split('\n')
            for line in lines[1:]:  # Skip header
                if not line.strip():
                    continue
                parts = line.split(',')
                if len(parts) >= 2:
                    site = parts[0].strip()
                    used = parts[1].strip().lower() == 'true'
                    if used:
                        results.append({
                            "platform": site,
                            "found": True,
                            "email_recovery": parts[2].strip() if len(parts) > 2 else None,
                            "phone_recovery": parts[3].strip() if len(parts) > 3 else None
                        })
            
            response["data"] = {
                "email": email,
                "tool": "holehe",
                "results": results,
                "total_found": len(results),
                "raw_output": output[:5000],  # Limit raw output size
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname,
                "scanned_at": datetime.utcnow().isoformat()
            }
            
            self.log(f"Email OSINT complete: found {len(results)} registrations")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Email OSINT timed out (>120 seconds)"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Email OSINT error: {e}", "ERROR")
        
        return response
    
    async def run_phone_osint(self, command_id: str, command_data: dict) -> dict:
        """Run phone OSINT using phoneinfoga"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        phone = command_data.get("phone") or command_data.get("target")
        if not phone:
            response["success"] = False
            response["error"] = "No phone number specified"
            return response
        
        # Auto-install phoneinfoga if not present
        installed, install_msg = await self.ensure_tool_installed("phoneinfoga")
        if not installed:
            response["success"] = False
            response["error"] = f"phoneinfoga not available and could not be installed: {install_msg}"
            return response
        if install_msg == "installed":
            response["data"]["auto_installed"] = "phoneinfoga"
        
        try:
            self.log(f"Running phoneinfoga for: {phone}")
            
            # Run phoneinfoga scan
            process = await asyncio.create_subprocess_exec(
                "phoneinfoga", "scan", "-n", phone,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            
            output = stdout.decode()
            
            # Parse output for useful info
            results = {
                "phone": phone,
                "valid": "valid" in output.lower(),
                "carrier": None,
                "country": None,
                "region": None,
                "line_type": None
            }
            
            # Extract info from output
            for line in output.split('\n'):
                line_lower = line.lower()
                if 'carrier:' in line_lower:
                    results["carrier"] = line.split(':', 1)[1].strip()
                elif 'country:' in line_lower:
                    results["country"] = line.split(':', 1)[1].strip()
                elif 'region:' in line_lower or 'location:' in line_lower:
                    results["region"] = line.split(':', 1)[1].strip()
                elif 'line type:' in line_lower or 'type:' in line_lower:
                    results["line_type"] = line.split(':', 1)[1].strip()
            
            response["data"] = {
                "phone": phone,
                "tool": "phoneinfoga",
                "results": [results],
                "raw_output": output[:5000],
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname,
                "scanned_at": datetime.utcnow().isoformat()
            }
            
            self.log(f"Phone OSINT complete for: {phone}")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Phone OSINT timed out (>60 seconds)"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Phone OSINT error: {e}", "ERROR")
        
        return response
    
    async def run_username_osint(self, command_id: str, command_data: dict) -> dict:
        """Run username OSINT using maigret - checks social networks for username"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        username = command_data.get("username") or command_data.get("target")
        if not username:
            response["success"] = False
            response["error"] = "No username specified"
            return response
        
        # Auto-install maigret if not present
        installed, install_msg = await self.ensure_tool_installed("maigret")
        if not installed:
            response["success"] = False
            response["error"] = f"maigret not available and could not be installed: {install_msg}"
            return response
        if install_msg == "installed":
            response["data"]["auto_installed"] = "maigret"
        
        try:
            self.log(f"Running maigret username OSINT for: {username}")
            
            # Create temp directory for output
            import tempfile
            with tempfile.TemporaryDirectory() as tmpdir:
                output_file = os.path.join(tmpdir, "results.json")
                
                # Run maigret with JSON output
                process = await asyncio.create_subprocess_exec(
                    "maigret", username, "--json", "simple", "-o", output_file, "--timeout", "10",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=180)
                
                results = []
                
                # Try to read JSON output
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r') as f:
                            import json as json_module
                            data = json_module.load(f)
                            # maigret outputs {username: {site: {url_user: ..., status: ...}}}
                            if username in data:
                                for site, info in data[username].items():
                                    if info.get('status') == 'Claimed':
                                        results.append({
                                            "platform": site,
                                            "found": True,
                                            "url": info.get('url_user', ''),
                                            "status": info.get('status', '')
                                        })
                    except Exception as e:
                        self.log(f"Error parsing maigret JSON: {e}", "WARNING")
                
                # Fallback: parse stdout
                if not results:
                    output = stdout.decode()
                    for line in output.split('\n'):
                        if '[+]' in line:  # Found indicator
                            parts = line.split()
                            for part in parts:
                                if part.startswith('http'):
                                    results.append({
                                        "platform": "unknown",
                                        "found": True,
                                        "url": part
                                    })
                                    break
                
                response["data"] = {
                    "username": username,
                    "tool": "maigret",
                    "results": results,
                    "total_found": len(results),
                    "raw_output": stdout.decode()[:5000],
                    "agent_id": self.agent_id,
                    "agent_hostname": self.hostname,
                    "scanned_at": datetime.utcnow().isoformat()
                }
                
                self.log(f"Username OSINT complete: found {len(results)} profiles")
            
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Username OSINT timed out (>180 seconds)"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Username OSINT error: {e}", "ERROR")
        
        return response
    
    async def run_person_osint(self, command_id: str, command_data: dict) -> dict:
        """Run comprehensive person OSINT - combines email, phone, username lookups"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        person_data = command_data.get("person_data", {})
        email = person_data.get("email") or command_data.get("email")
        phone = person_data.get("phone") or command_data.get("phone")
        username = person_data.get("nickname") or person_data.get("username") or command_data.get("username")
        
        if not email and not phone and not username:
            response["success"] = False
            response["error"] = "No identifiers (email, phone, or username) provided"
            return response
        
        try:
            all_results = []
            errors = []
            
            # Run email OSINT if email provided
            if email:
                self.log(f"Person OSINT: Running email lookup for {email}")
                email_result = await self.run_email_osint(command_id + "_email", {"email": email})
                if email_result.get("success"):
                    for r in email_result.get("data", {}).get("results", []):
                        r["source_type"] = "email"
                        r["source_value"] = email
                        all_results.append(r)
                else:
                    errors.append(f"Email OSINT: {email_result.get('error')}")
            
            # Run phone OSINT if phone provided
            if phone:
                self.log(f"Person OSINT: Running phone lookup for {phone}")
                phone_result = await self.run_phone_osint(command_id + "_phone", {"phone": phone})
                if phone_result.get("success"):
                    for r in phone_result.get("data", {}).get("results", []):
                        r["source_type"] = "phone"
                        r["source_value"] = phone
                        all_results.append(r)
                else:
                    errors.append(f"Phone OSINT: {phone_result.get('error')}")
            
            # Run username OSINT if username provided
            if username:
                self.log(f"Person OSINT: Running username lookup for {username}")
                username_result = await self.run_username_osint(command_id + "_username", {"username": username})
                if username_result.get("success"):
                    for r in username_result.get("data", {}).get("results", []):
                        r["source_type"] = "username"
                        r["source_value"] = username
                        all_results.append(r)
                else:
                    errors.append(f"Username OSINT: {username_result.get('error')}")
            
            response["data"] = {
                "person_data": person_data,
                "results": all_results,
                "total_found": len(all_results),
                "errors": errors if errors else None,
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname,
                "scanned_at": datetime.utcnow().isoformat()
            }
            
            # Mark as partial success if some lookups failed
            if errors and not all_results:
                response["success"] = False
                response["error"] = "; ".join(errors)
            
            self.log(f"Person OSINT complete: found {len(all_results)} total results")
            
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Person OSINT error: {e}", "ERROR")
        
        return response
    
    async def run_company_osint(self, command_id: str, command_data: dict) -> dict:
        """Run company OSINT - domain enumeration, email harvesting"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        company_data = command_data.get("company_data", {})
        domain = company_data.get("domain") or company_data.get("website") or command_data.get("target")
        
        if not domain:
            response["success"] = False
            response["error"] = "No domain specified for company OSINT"
            return response
        
        # Clean domain (remove http/https and paths)
        if domain.startswith('http'):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc or domain
        domain = domain.split('/')[0]
        
        try:
            results = []
            
            # 1. DNS enumeration
            self.log(f"Company OSINT: DNS enumeration for {domain}")
            dns_results = {
                "type": "dns",
                "mx_records": [],
                "ns_records": [],
                "txt_records": [],
                "a_records": []
            }
            
            if shutil.which("dig"):
                for rtype in ["A", "MX", "NS", "TXT"]:
                    try:
                        process = await asyncio.create_subprocess_exec(
                            "dig", "+short", rtype, domain,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)
                        records = [r.strip() for r in stdout.decode().strip().split('\n') if r.strip()]
                        dns_results[f"{rtype.lower()}_records"] = records
                    except:
                        pass
            
            if any(dns_results[k] for k in ["mx_records", "ns_records", "a_records"]):
                results.append(dns_results)
            
            # 2. Subdomain enumeration (basic - using common subdomains)
            self.log(f"Company OSINT: Subdomain enumeration for {domain}")
            common_subdomains = ["www", "mail", "webmail", "ftp", "admin", "blog", "dev", "staging", 
                                 "api", "app", "portal", "vpn", "remote", "secure", "shop", "store"]
            
            import socket
            found_subdomains = []
            for sub in common_subdomains:
                subdomain = f"{sub}.{domain}"
                try:
                    socket.gethostbyname(subdomain)
                    found_subdomains.append(subdomain)
                except:
                    pass
            
            if found_subdomains:
                results.append({
                    "type": "subdomains",
                    "found": found_subdomains
                })
            
            # 3. Check for SPF/DMARC/DKIM (email security)
            email_security = {
                "type": "email_security",
                "has_spf": False,
                "has_dmarc": False,
                "has_dkim": False
            }
            
            if shutil.which("dig"):
                # SPF
                try:
                    process = await asyncio.create_subprocess_exec(
                        "dig", "+short", "TXT", domain,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)
                    if 'v=spf1' in stdout.decode().lower():
                        email_security["has_spf"] = True
                except:
                    pass
                
                # DMARC
                try:
                    process = await asyncio.create_subprocess_exec(
                        "dig", "+short", "TXT", f"_dmarc.{domain}",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)
                    if 'v=dmarc1' in stdout.decode().lower():
                        email_security["has_dmarc"] = True
                except:
                    pass
            
            results.append(email_security)
            
            response["data"] = {
                "domain": domain,
                "company_name": company_data.get("name"),
                "results": results,
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname,
                "scanned_at": datetime.utcnow().isoformat()
            }
            
            self.log(f"Company OSINT complete for {domain}: {len(results)} result groups")
            
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Company OSINT error: {e}", "ERROR")
        
        return response
    
    async def run_dns_lookup(self, command_id: str, command_data: dict) -> dict:
        """Perform DNS lookup"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        target = command_data.get("target")
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        project_id = command_data.get("project_id")
        record_type = command_data.get("record_type", "A")
        
        import socket
        
        try:
            results = {
                "a_records": [],
                "aaaa_records": [],
                "mx_records": [],
                "ns_records": [],
                "txt_records": []
            }
            
            # Get A records
            try:
                ips = socket.gethostbyname_ex(target)
                results["a_records"] = ips[2]
            except:
                pass
            
            # Use dig if available for more record types
            if shutil.which("dig"):
                for rtype in ["MX", "NS", "TXT"]:
                    try:
                        process = await asyncio.create_subprocess_exec(
                            "dig", "+short", rtype, target,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)
                        records = [r.strip() for r in stdout.decode().strip().split('\n') if r.strip()]
                        results[f"{rtype.lower()}_records"] = records
                    except:
                        pass
            
            response["data"] = {
                "target": target,
                "records": results,
                "project_id": project_id,
                "scanned_at": datetime.utcnow().isoformat(),
                "agent_id": self.agent_id,
                "agent_hostname": self.hostname
            }
            
            self.log(f"DNS lookup complete: {len(results['a_records'])} A records")
            
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"DNS lookup error: {e}", "ERROR")
        
        return response
    
    async def ensure_tool_installed(self, tool_name: str) -> tuple[bool, str]:
        """
        Check if a tool is installed, and auto-install it if possible.
        
        Returns:
            tuple: (success: bool, message: str)
            - If tool is already installed: (True, "")
            - If tool was successfully installed: (True, "installed")
            - If installation failed: (False, error_message)
        """
        # Map command names to tool names in TOOL_INSTALL_COMMANDS
        tool_mapping = {
            "nmap": "nmap",
            "nikto": "nikto",
            "dirb": "dirb",
            "gobuster": "gobuster",
            "sslscan": "sslscan",
            "whatweb": "whatweb",
            "traceroute": "traceroute",
            "ssh-audit": "ssh-audit",
            "enum4linux": "enum4linux",
            "hydra": "hydra",
            "wpscan": "wpscan",
            "sqlmap": "sqlmap",
            "ffuf": "ffuf",
            "chromium": "chromium",
        }
        
        # Get the actual tool name for lookup
        lookup_name = tool_mapping.get(tool_name, tool_name)
        
        # Check if tool info exists
        if lookup_name not in TOOL_INSTALL_COMMANDS:
            # Tool not in our install list - just check if it exists
            if shutil.which(tool_name):
                return (True, "")
            return (False, f"{tool_name} is not installed and cannot be auto-installed")
        
        tool_info = TOOL_INSTALL_COMMANDS[lookup_name]
        check_cmd = tool_info.get("check", tool_name)
        
        # Check if already installed
        if shutil.which(check_cmd):
            return (True, "")
        
        # Tool not installed - try to auto-install
        # Check if another installation is already in progress
        if self._install_lock and self._install_lock.locked():
            return (False, f"Another tool installation is in progress ({self._installing_tool}). Please wait and try again.")
        
        self.log(f"Tool '{tool_name}' not found, attempting auto-install...")
        
        # Check if we have root access
        if not self._is_root():
            return (False, f"{tool_name} is not installed. Auto-install requires root privileges. Run agent as root or install manually.")
        
        # Acquire installation lock (only one install at a time)
        if not self._install_lock:
            self._install_lock = asyncio.Lock()
        
        # Try to acquire lock without blocking to give immediate feedback
        if self._install_lock.locked():
            return (False, f"Another tool installation is in progress ({self._installing_tool}). Please wait and try again.")
        
        async with self._install_lock:
            self._installing_tool = tool_name
            try:
                # Update package list first
                self.log("Updating package list...")
                update_process = await asyncio.create_subprocess_exec(
                    "apt-get", "update",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(update_process.communicate(), timeout=120)
                
                # Run pre-install dependencies if defined
                if tool_info.get("pre_install"):
                    self.log(f"Installing dependencies for {tool_name}...")
                    pre_process = await asyncio.create_subprocess_exec(
                        *tool_info["pre_install"],
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await asyncio.wait_for(pre_process.communicate(), timeout=180)
                
                # Try primary install method
                self.log(f"Installing {tool_name}: {' '.join(tool_info['install'])}")
                process = await asyncio.create_subprocess_exec(
                    *tool_info["install"],
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=300  # 5 minute timeout
                )
                
                # If primary install failed and there's an alternative, try it
                if process.returncode != 0 and tool_info.get("install_alt"):
                    error_msg = stderr.decode("utf-8", errors="replace")
                    self.log(f"Primary install failed, trying alternative method...")
                    
                    # Make sure git is installed for alt methods
                    if "git" in tool_info["install_alt"]:
                        git_process = await asyncio.create_subprocess_exec(
                            "apt-get", "install", "-y", "git",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        await asyncio.wait_for(git_process.communicate(), timeout=120)
                    
                    # Run alternative install
                    alt_process = await asyncio.create_subprocess_exec(
                        *tool_info["install_alt"],
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    alt_stdout, alt_stderr = await asyncio.wait_for(
                        alt_process.communicate(),
                        timeout=300
                    )
                    
                    # Run post-install for alt method if defined
                    if alt_process.returncode == 0 and tool_info.get("post_install_alt"):
                        post_process = await asyncio.create_subprocess_exec(
                            *tool_info["post_install_alt"],
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        await asyncio.wait_for(post_process.communicate(), timeout=60)
                    
                    if alt_process.returncode != 0:
                        alt_error = alt_stderr.decode("utf-8", errors="replace")
                        return (False, f"Failed to install {tool_name}: {alt_error}")
                elif process.returncode != 0:
                    error_msg = stderr.decode("utf-8", errors="replace")
                    return (False, f"Failed to install {tool_name}: {error_msg}")
                
                # Verify installation
                if shutil.which(check_cmd):
                    self.log(f"Successfully auto-installed {tool_name}")
                    return (True, "installed")
                else:
                    return (False, f"{tool_name} installation completed but binary not found in PATH")
                    
            except asyncio.TimeoutError:
                return (False, f"Timeout while installing {tool_name}")
            except Exception as e:
                return (False, f"Error installing {tool_name}: {str(e)}")
            finally:
                self._installing_tool = None
    
    async def check_tools_status(self) -> dict:
        """Return all known tools with their installed status and info, for full UI display."""
        import shutil, subprocess
        tools_status = {}
        for tool_name, tool_info in TOOL_INSTALL_COMMANDS.items():
            check_cmd = tool_info["check"]
            is_installed = shutil.which(check_cmd) is not None
            version = None
            if is_installed:
                try:
                    if tool_name == "nmap":
                        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            version = result.stdout.split("\n")[0]
                    elif tool_name == "nikto":
                        result = subprocess.run(["nikto", "-Version"], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            version = result.stdout.strip()
                    elif tool_name == "dirb":
                        result = subprocess.run(["dirb"], capture_output=True, text=True, timeout=5)
                        if result.stdout:
                            first_line = result.stdout.split("\n")[0]
                            if "DIRB" in first_line:
                                version = first_line.strip()
                except Exception as e:
                    print(f"[check_tools_status] Error getting version for {tool_name}: {e}")
            tools_status[tool_name] = {
                "installed": is_installed,
                "version": version,
                "description": tool_info["description"],
                "size": tool_info.get("size", "Unknown")
            }
        # Always return all known tools, even if none are installed
        if not tools_status:
            for tool_name, tool_info in TOOL_INSTALL_COMMANDS.items():
                tools_status[tool_name] = {
                    "installed": False,
                    "version": None,
                    "description": tool_info["description"],
                    "size": tool_info.get("size", "Unknown")
                }
        print(f"[check_tools_status] FINAL tools_status: {json.dumps(tools_status, indent=2)}")
        return {
            "tools": tools_status,
            "can_install": self._is_root()
        }
    
    async def install_tool(self, command_id: str, tool_name: str) -> dict:
        """Install a tool on the agent system"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        if not tool_name:
            response["success"] = False
            response["error"] = "No tool name specified"
            return response
        
        if tool_name not in TOOL_INSTALL_COMMANDS:
            response["success"] = False
            response["error"] = f"Unknown tool: {tool_name}. Supported: {list(TOOL_INSTALL_COMMANDS.keys())}"
            return response
        
        tool_info = TOOL_INSTALL_COMMANDS[tool_name]
        
        # Check if already installed
        if shutil.which(tool_info["check"]):
            response["data"] = {
                "tool": tool_name,
                "status": "already_installed",
                "message": f"{tool_name} is already installed"
            }
            return response
        
        # Check if we have root/sudo access
        is_root = self._is_root()
        
        if not is_root:
            response["success"] = False
            response["error"] = "Agent must run as root to install tools. Run with sudo or as root user."
            return response
        
        # Acquire installation lock (only one install at a time)
        if not self._install_lock:
            self._install_lock = asyncio.Lock()
        
        # Check if another installation is in progress
        if self._install_lock.locked():
            response["success"] = False
            response["error"] = f"Another tool installation is in progress ({self._installing_tool}). Please wait and try again."
            return response
        
        async with self._install_lock:
            self._installing_tool = tool_name
            self.log(f"Installing {tool_name}...")
            
            try:
                # Update package list first
                self.log("Updating package list...")
                update_process = await asyncio.create_subprocess_exec(
                    "apt-get", "update",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(update_process.communicate(), timeout=120)
                
                # Run pre-install dependencies if defined
                if tool_info.get("pre_install"):
                    self.log(f"Installing dependencies: {' '.join(tool_info['pre_install'])}")
                    pre_process = await asyncio.create_subprocess_exec(
                        *tool_info["pre_install"],
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await asyncio.wait_for(pre_process.communicate(), timeout=180)
                
                # Try primary install method
                self.log(f"Running: {' '.join(tool_info['install'])}")
                process = await asyncio.create_subprocess_exec(
                    *tool_info["install"],
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=300  # 5 minute timeout
                )
                
                # If primary install failed and there's an alternative, try it
                if process.returncode != 0 and tool_info.get("install_alt"):
                    error_msg = stderr.decode("utf-8", errors="replace")
                    self.log(f"Primary install failed ({error_msg.strip()}), trying alternative method...")
                    
                    # Make sure git is installed for alt methods
                    if "git" in tool_info["install_alt"]:
                        git_process = await asyncio.create_subprocess_exec(
                            "apt-get", "install", "-y", "git", "perl", "libnet-ssleay-perl",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        await asyncio.wait_for(git_process.communicate(), timeout=120)
                    
                    # Run alternative install
                    self.log(f"Running: {' '.join(tool_info['install_alt'])}")
                    alt_process = await asyncio.create_subprocess_exec(
                        *tool_info["install_alt"],
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    alt_stdout, alt_stderr = await asyncio.wait_for(
                        alt_process.communicate(),
                        timeout=300
                    )
                    
                    if alt_process.returncode != 0:
                        alt_error = alt_stderr.decode("utf-8", errors="replace")
                        response["success"] = False
                        response["error"] = f"Installation failed: {alt_error}"
                        self.log(f"Alt install failed: {alt_error}", "ERROR")
                        return response
                    
                    # Run post-install if exists
                    if tool_info.get("post_install_alt"):
                        self.log(f"Running post-install: {' '.join(tool_info['post_install_alt'])}")
                        post_process = await asyncio.create_subprocess_exec(
                            *tool_info["post_install_alt"],
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        await asyncio.wait_for(post_process.communicate(), timeout=30)
                
                elif process.returncode != 0:
                    error_msg = stderr.decode("utf-8", errors="replace")
                    response["success"] = False
                    response["error"] = f"Installation failed: {error_msg}"
                    self.log(f"Install failed: {error_msg}", "ERROR")
                    return response
                
                # Verify installation
                if shutil.which(tool_info["check"]):
                    response["data"] = {
                        "tool": tool_name,
                        "status": "installed",
                        "message": f"{tool_name} installed successfully"
                    }
                    self.log(f"{tool_name} installed successfully")
                else:
                    response["success"] = False
                    response["error"] = f"{tool_name} install command succeeded but tool not found in PATH"
                    
            except asyncio.TimeoutError:
                response["success"] = False
                response["error"] = "Timeout while installing {tool_name}"
            except Exception as e:
                response["success"] = False
                response["error"] = str(e)
                self.log(f"Install error: {e}", "ERROR")
            finally:
                self._installing_tool = None
        
        return response
    
    async def uninstall_tool(self, command_id: str, tool_name: str) -> dict:
        """Uninstall a tool from the agent system"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        if not tool_name:
            response["success"] = False
            response["error"] = "No tool name specified"
            return response
        
        if tool_name not in TOOL_INSTALL_COMMANDS:
            response["success"] = False
            response["error"] = f"Unknown tool: {tool_name}. Supported: {list(TOOL_INSTALL_COMMANDS.keys())}"
            return response
        
        tool_info = TOOL_INSTALL_COMMANDS[tool_name]
        
        # Check if tool is installed
        if not shutil.which(tool_info["check"]):
            response["data"] = {
                "tool": tool_name,
                "status": "not_installed",
                "message": f"{tool_name} is not installed"
            }
            return response
        
        # Check if we have root/sudo access
        is_root = self._is_root()
        
        if not is_root:
            response["success"] = False
            response["error"] = "Agent must run as root to uninstall tools. Run with sudo or as root user."
            return response
        
        # Check if uninstall command is available
        if not tool_info.get("uninstall"):
            response["success"] = False
            response["error"] = f"Uninstall not supported for {tool_name}"
            return response
        
        self.log(f"Uninstalling {tool_name}...")
        
        try:
            # Run uninstall command
            self.log(f"Running: {' '.join(tool_info['uninstall'])}")
            process = await asyncio.create_subprocess_exec(
                *tool_info["uninstall"],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=120  # 2 minute timeout
            )
            
            if process.returncode != 0:
                error_msg = stderr.decode("utf-8", errors="replace")
                response["success"] = False
                response["error"] = f"Uninstall failed: {error_msg}"
                self.log(f"Uninstall failed: {error_msg}", "ERROR")
                return response
            
            # Verify uninstallation
            if not shutil.which(tool_info["check"]):
                response["data"] = {
                    "tool": tool_name,
                    "status": "uninstalled",
                    "message": f"{tool_name} uninstalled successfully"
                }
                self.log(f"{tool_name} uninstalled successfully")
            else:
                response["success"] = False
                response["error"] = f"{tool_name} uninstall command succeeded but tool still found in PATH"
                
        except asyncio.TimeoutError:
            response["success"] = False
            response["error"] = "Uninstall timed out (2 minute limit)"
            self.log(f"Uninstall timed out", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Uninstall error: {e}", "ERROR")
        
        return response
    
    async def update_agent(self, command_id: str) -> dict:
        """Self-update the agent from the update URL"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        self.log(f"Checking for agent updates from {AGENT_UPDATE_URL}...")
        
        try:
            # Download the latest agent code
            import urllib.request
            import tempfile
            
            # Download to temp file first
            with urllib.request.urlopen(AGENT_UPDATE_URL, timeout=30) as resp:
                new_code = resp.read().decode('utf-8')
            
            # Validate that we got actual Python code, not an error page
            if not new_code.strip().startswith(('#', 'import', 'from', '"""', "'''")):
                if '404' in new_code.lower() or 'not found' in new_code.lower():
                    response["success"] = False
                    response["error"] = "Update URL returned 404 - agent repository not found"
                    return response
                if '<html' in new_code.lower() or '<!doctype' in new_code.lower():
                    response["success"] = False
                    response["error"] = "Update URL returned HTML instead of Python code"
                    return response
            
            # Extract version from new code
            new_version = None
            for line in new_code.split('\n'):
                if line.startswith('VERSION = '):
                    new_version = line.split('"')[1]
                    break
            
            if not new_version:
                response["success"] = False
                response["error"] = "Could not determine version from downloaded code"
                return response
            
            self.log(f"Current version: {VERSION}, Available version: {new_version}")
            
            # Compare versions
            if new_version == VERSION:
                response["data"] = {
                    "status": "up_to_date",
                    "current_version": VERSION,
                    "message": "Agent is already up to date"
                }
                return response
            
            # Get current script path
            current_script = os.path.abspath(__file__)
            
            # Backup current script
            backup_path = current_script + ".backup"
            shutil.copy2(current_script, backup_path)
            self.log(f"Backed up current agent to {backup_path}")
            
            # Write new code
            with open(current_script, 'w') as f:
                f.write(new_code)
            
            self.log(f"Updated agent to version {new_version}")
            
            response["data"] = {
                "status": "updated",
                "old_version": VERSION,
                "new_version": new_version,
                "message": f"Agent updated from {VERSION} to {new_version}. Restarting...",
                "backup_path": backup_path
            }
            
            # Send response before restarting
            if self.ws:
                await self.ws.send(json.dumps(response))
            
            # Auto-restart after successful update
            await asyncio.sleep(0.5)
            self.log(f"Updated to v{new_version}, restarting...")
            os.execv(sys.executable, [sys.executable, current_script] + sys.argv[1:])
            
        except urllib.error.URLError as e:
            response["success"] = False
            response["error"] = f"Failed to download update: {e}"
            self.log(f"Update download failed: {e}", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Update error: {e}", "ERROR")
        
        return response
    
    async def _check_upnp(self, command_id: str) -> dict:
        """Check if UPnP is available on the router and can open ports"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {
                "upnp_available": False,
                "gateway": None,
                "external_ip": None,
                "can_add_mapping": False,
                "existing_mappings": [],
                "error": None
            }
        }
        
        try:
            # Try to use miniupnpc if available
            try:
                import miniupnpc
                upnp = miniupnpc.UPnP()
                upnp.discoverdelay = 2000  # 2 seconds
                
                self.log("Discovering UPnP devices...")
                devices = upnp.discover()
                
                if devices > 0:
                    upnp.selectigd()
                    response["data"]["upnp_available"] = True
                    response["data"]["gateway"] = upnp.lanaddr
                    
                    try:
                        external_ip = upnp.externalipaddress()
                        response["data"]["external_ip"] = external_ip
                    except:
                        pass
                    
                    # Try to add a test mapping (then remove it)
                    test_port = 65432
                    try:
                        # Add mapping
                        result = upnp.addportmapping(
                            test_port, 'TCP', upnp.lanaddr, test_port,
                            'micro-hack-test', ''
                        )
                        if result:
                            response["data"]["can_add_mapping"] = True
                            # Remove the test mapping
                            upnp.deleteportmapping(test_port, 'TCP')
                    except Exception as e:
                        response["data"]["mapping_error"] = str(e)
                    
                    # Get existing mappings
                    try:
                        i = 0
                        while True:
                            mapping = upnp.getgenericportmapping(i)
                            if mapping is None:
                                break
                            response["data"]["existing_mappings"].append({
                                "external_port": mapping[0],
                                "protocol": mapping[1],
                                "internal_host": mapping[2][0],
                                "internal_port": mapping[2][1],
                                "description": mapping[3],
                                "enabled": mapping[4],
                                "duration": mapping[5]
                            })
                            i += 1
                            if i > 100:  # Safety limit
                                break
                    except:
                        pass
                else:
                    response["data"]["error"] = "No UPnP devices found"
                    
            except ImportError:
                # miniupnpc not installed, try upnpc command line tool
                upnpc_path = shutil.which("upnpc") or shutil.which("upnpc-static")
                if upnpc_path:
                    # Run upnpc -s to get status
                    proc = subprocess.run([upnpc_path, "-s"], capture_output=True, text=True, timeout=10)
                    output = proc.stdout + proc.stderr
                    
                    if "No IGD UPnP Device found" in output:
                        response["data"]["error"] = "No UPnP devices found"
                    elif "Found valid IGD" in output or "external IP" in output.lower():
                        response["data"]["upnp_available"] = True
                        # Parse external IP
                        for line in output.split('\n'):
                            if 'external' in line.lower() and 'ip' in line.lower():
                                parts = line.split()
                                for part in parts:
                                    if part.count('.') == 3:
                                        response["data"]["external_ip"] = part
                                        break
                        
                        # Try to test port mapping
                        test_port = 65432
                        proc = subprocess.run(
                            [upnpc_path, "-a", self.local_ip, str(test_port), str(test_port), "TCP"],
                            capture_output=True, text=True, timeout=10
                        )
                        if proc.returncode == 0 or "success" in proc.stdout.lower():
                            response["data"]["can_add_mapping"] = True
                            # Remove test mapping
                            subprocess.run([upnpc_path, "-d", str(test_port), "TCP"], 
                                         capture_output=True, timeout=5)
                else:
                    response["data"]["error"] = "UPnP tools not available (install miniupnpc or upnpc)"
                    response["data"]["install_hint"] = "pip install miniupnpc OR apt install miniupnpc"
                    
        except subprocess.TimeoutExpired:
            response["data"]["error"] = "UPnP discovery timed out"
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"UPnP check error: {e}", "ERROR")
        
        return response
    
    async def _redeploy_agent(self, command_id: str) -> dict:
        """Re-download and restart the agent (fresh deployment)"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {
                "message": "Agent redeploying...",
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        try:
            self.log("Starting redeploy: downloading fresh agent...")
            
            # Download fresh agent code
            import urllib.request
            with urllib.request.urlopen(AGENT_UPDATE_URL, timeout=30) as resp:
                new_code = resp.read().decode('utf-8')
            
            # Validate the downloaded code
            if not new_code.strip().startswith(('#', 'import', 'from', '"""', "'''")):
                response["success"] = False
                response["error"] = "Downloaded code doesn't look like valid Python"
                return response
            
            # Get current script path
            current_script = os.path.abspath(__file__)
            
            # Write new code
            with open(current_script, 'w') as f:
                f.write(new_code)
            
            self.log("Fresh agent downloaded, restarting...")
            
            # Send response before restarting
            if self.ws:
                await self.ws.send(json.dumps(response))
            
            await asyncio.sleep(0.5)
            os.execv(sys.executable, [sys.executable, current_script] + sys.argv[1:])
            
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Redeploy error: {e}", "ERROR")
        
        return response
    
    async def _destroy_agent(self, command_id: str) -> dict:
        """Clean up everything and terminate the agent"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {
                "message": "Agent destroying itself...",
                "cleanup_steps": [],
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        cleanup_steps = []
        
        try:
            # 1. Stop any running shell sessions
            try:
                if hasattr(self, 'shell_sessions') and self.shell_sessions:
                    for session_id in list(self.shell_sessions.keys()):
                        await self.stop_shell_session(session_id)
                    cleanup_steps.append("Stopped shell sessions")
            except Exception as e:
                cleanup_steps.append(f"Shell cleanup: {e}")
            
            # 2. Stop webserver if running
            try:
                if hasattr(self, '_local_webserver') and self._local_webserver:
                    await self._stop_webserver(command_id)
                    cleanup_steps.append("Stopped webserver")
            except Exception as e:
                cleanup_steps.append(f"Webserver cleanup: {e}")
            
            # 3. Clean up Docker containers created by this agent (if any)
            try:
                docker_path = shutil.which("docker")
                if docker_path:
                    # Find and stop containers with micro-hack label
                    proc = subprocess.run(
                        [docker_path, "ps", "-aq", "--filter", "label=micro-hack-agent"],
                        capture_output=True, text=True, timeout=10
                    )
                    container_ids = proc.stdout.strip().split('\n')
                    container_ids = [c for c in container_ids if c]
                    
                    if container_ids:
                        for cid in container_ids:
                            subprocess.run([docker_path, "rm", "-f", cid], 
                                         capture_output=True, timeout=10)
                        cleanup_steps.append(f"Removed {len(container_ids)} Docker container(s)")
            except Exception as e:
                cleanup_steps.append(f"Docker cleanup: {e}")
            
            # 4. Clean up virtual environments
            try:
                agent_dir = os.path.dirname(os.path.abspath(__file__))
                venv_paths = [
                    os.path.join(agent_dir, 'venv'),
                    os.path.join(agent_dir, '.venv'),
                    os.path.join(agent_dir, 'env'),
                ]
                for venv_path in venv_paths:
                    if os.path.exists(venv_path) and os.path.isdir(venv_path):
                        shutil.rmtree(venv_path, ignore_errors=True)
                        cleanup_steps.append(f"Removed virtualenv: {venv_path}")
            except Exception as e:
                cleanup_steps.append(f"Venv cleanup: {e}")
            
            # 5. Remove micro-hack/micro-dam directories
            try:
                home_dir = os.path.expanduser("~")
                dirs_to_remove = [
                    os.path.join(home_dir, 'micro-dam'),
                    os.path.join(home_dir, 'micro-hack'),
                    os.path.join(home_dir, '.micro-hack'),
                    os.path.join(home_dir, '.micro-dam'),
                ]
                for dir_path in dirs_to_remove:
                    if os.path.exists(dir_path) and os.path.isdir(dir_path):
                        shutil.rmtree(dir_path, ignore_errors=True)
                        cleanup_steps.append(f"Removed directory: {dir_path}")
            except Exception as e:
                cleanup_steps.append(f"Directory cleanup: {e}")
            
            # 6. Remove agent script and backup
            agent_script = os.path.abspath(__file__)
            backup_script = agent_script + ".backup"
            
            response["data"]["cleanup_steps"] = cleanup_steps
            response["data"]["final_step"] = "Terminating agent process"
            
            # Send response before termination
            if self.ws:
                await self.ws.send(json.dumps(response))
                await asyncio.sleep(0.5)
                try:
                    await self.ws.close()
                except:
                    pass
            
            # Remove script files (do this last)
            try:
                if os.path.exists(backup_script):
                    os.remove(backup_script)
                if os.path.exists(agent_script):
                    os.remove(agent_script)
            except Exception as e:
                self.log(f"Could not remove agent script: {e}", "WARNING")
            
            # Terminate the process
            self.log("Agent destroyed, terminating...")
            os._exit(0)
            
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            response["data"]["cleanup_steps"] = cleanup_steps
            self.log(f"Destroy error: {e}", "ERROR")
        
        return response
    
    async def handle_command(self, data: dict):
        """Handle a command from the server"""
        import time
        
        command = data.get("command", "")
        
        # Spam prevention: enforce 3-second cooldown only for SCAN commands
        # Fast commands (ping, info, shell, terminal) skip cooldown
        if command not in self._fast_commands:
            current_time = time.time()
            time_since_last_scan = current_time - self._last_scan_time
            if time_since_last_scan < self._scan_cooldown:
                wait_time = self._scan_cooldown - time_since_last_scan
                self.log(f"Scan cooldown active ({wait_time:.1f}s remaining), waiting...", "DEBUG")
                await asyncio.sleep(wait_time)
            # Update last scan time
            self._last_scan_time = time.time()
        
        # Handler stubs for new nmap command variants
        async def run_nmap_quick_scan(command_id, command_data):
            command_data = dict(command_data)
            command_data["scan_type"] = "quick"
            return await self.run_nmap_scan(command_id, command_data)

        async def run_nmap_normal_scan(command_id, command_data):
            command_data = dict(command_data)
            command_data["scan_type"] = "normal"
            return await self.run_nmap_scan(command_id, command_data)

        async def run_nmap_thorough_scan(command_id, command_data):
            command_data = dict(command_data)
            command_data["scan_type"] = "thorough"
            return await self.run_nmap_scan(command_id, command_data)

        async def run_nmap_vulns_scan(command_id, command_data):
            command_data = dict(command_data)
            command_data["scan_type"] = "vuln"
            return await self.run_nmap_scan(command_id, command_data)

        # Attach to self for handler use
        self.run_nmap_quick_scan = run_nmap_quick_scan
        self.run_nmap_normal_scan = run_nmap_normal_scan
        self.run_nmap_thorough_scan = run_nmap_thorough_scan
        self.run_nmap_vulns_scan = run_nmap_vulns_scan

        command_id = data.get("command_id")
        command = data.get("command")
        command_data = data.get("data", {})

        # Standardize command names and provide aliases for backward compatibility
        command_aliases = {
            "nmap_network": "nmap",
            "nmap_quick": "nmap_quick",
            "nmap_normal": "nmap_normal",
            "nmap_thorough": "nmap_thorough",
            "nmap_vulns": "nmap_vulns",
            "dirb": "dirb",
            "nikto": "nikto",
            "ssh-audit": "ssh_audit",
            "banner_grab": "banner",
            "banner-grab": "banner",
            # Add more aliases as needed
        }
        # Map old/alias command to new short name and normalize the command
        command_std = command_aliases.get(command, command)
        # Ensure the rest of the function uses the standardized name
        command = command_std
        self.log(f"Received command: {command}")
        
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        try:
            if command_std == "ping":
                response["data"] = {
                    "message": "pong",
                    "timestamp": datetime.utcnow().isoformat()
                }
            elif command_std == "host_ping":
                self.log(f"Starting host_ping for command_id: {command_id}")
                response = await self.run_host_ping(command_id, command_data)
                self.log(f"host_ping complete, success: {response.get('success')}")
            elif command_std == "info":
                response["data"] = {
                    "agent_id": self.agent_id,
                    "hostname": self.hostname,
                    "local_ip": self.local_ip,
                    "remote_ip": self.remote_ip,
                    "location": self.location,
                    "os": self.os_info,
                    "version": VERSION,
                    "python_version": platform.python_version()
                }
            elif command_std == "echo":
                response["data"] = {
                    "echo": command_data.get("message", ""),
                    "timestamp": datetime.utcnow().isoformat()
                }
            elif command_std == "nmap":
                self.log(f"Starting nmap for command_id: {command_id}")
                response = await self.run_nmap_scan(command_id, command_data)
                self.log(f"nmap complete, success: {response.get('success')}")
            elif command_std == "nmap_quick":
                self.log(f"Starting nmap_quick for command_id: {command_id}")
                response = await self.run_nmap_quick_scan(command_id, command_data)
                self.log(f"nmap_quick complete, success: {response.get('success')}")
            elif command_std == "nmap_normal":
                self.log(f"Starting nmap_normal for command_id: {command_id}")
                response = await self.run_nmap_normal_scan(command_id, command_data)
                self.log(f"nmap_normal complete, success: {response.get('success')}")
            elif command_std == "nmap_thorough":
                self.log(f"Starting nmap_thorough for command_id: {command_id}")
                response = await self.run_nmap_thorough_scan(command_id, command_data)
                self.log(f"nmap_thorough complete, success: {response.get('success')}")
            elif command_std == "nmap_vulns":
                self.log(f"Starting nmap_vulns for command_id: {command_id}")
                response = await self.run_nmap_vulns_scan(command_id, command_data)
                self.log(f"nmap_vulns complete, success: {response.get('success')}")
            elif command_std == "nikto":
                self.log(f"Starting nikto for command_id: {command_id}")
                response = await self.run_nikto_scan(command_id, command_data)
                self.log(f"nikto complete, success: {response.get('success')}")
            elif command_std == "dirb":
                self.log(f"Starting dirb for command_id: {command_id}")
                response = await self.run_dirb_scan(command_id, command_data)
                self.log(f"dirb complete, success: {response.get('success')}")
            elif command_std == "sslscan":
                self.log(f"Starting sslscan for command_id: {command_id}")
                response = await self.run_sslscan(command_id, command_data)
                self.log(f"sslscan complete, success: {response.get('success')}")
            elif command_std == "gobuster":
                self.log(f"Starting gobuster for command_id: {command_id}")
                response = await self.run_gobuster_scan(command_id, command_data)
                self.log(f"gobuster complete, success: {response.get('success')}")
            elif command_std == "whatweb":
                self.log(f"Starting whatweb for command_id: {command_id}")
                response = await self.run_whatweb_scan(command_id, command_data)
                self.log(f"whatweb complete, success: {response.get('success')}")
            elif command_std == "traceroute":
                self.log(f"Starting traceroute for command_id: {command_id}")
                response = await self.run_traceroute(command_id, command_data)
                self.log(f"traceroute complete, success: {response.get('success')}")
            elif command_std == "ssh_audit":
                # Run SSH audit
                self.log(f"Starting SSH audit for command_id: {command_id}")
                response = await self.run_ssh_audit(command_id, command_data)
                self.log(f"SSH audit complete, success: {response.get('success')}")
            
            elif command == "ftp_anon":
                # Check FTP anonymous access
                self.log(f"Starting FTP anon check for command_id: {command_id}")
                response = await self.run_ftp_anon(command_id, command_data)
                self.log(f"FTP anon check complete, success: {response.get('success')}")
            
            elif command == "smtp":
                # SMTP scan
                self.log(f"Starting SMTP scan for command_id: {command_id}")
                response = await self.run_smtp_scan(command_id, command_data)
                self.log(f"SMTP scan complete, success: {response.get('success')}")
            
            elif command == "imap":
                # IMAP scan
                self.log(f"Starting IMAP scan for command_id: {command_id}")
                response = await self.run_imap_scan(command_id, command_data)
                self.log(f"IMAP scan complete, success: {response.get('success')}")
            
            elif command == "banner":
                # Banner grab
                self.log(f"Starting banner grab for command_id: {command_id}")
                response = await self.run_banner_grab(command_id, command_data)
                self.log(f"Banner grab complete, success: {response.get('success')}")
            
            elif command == "screenshot":
                # Take screenshot
                self.log(f"Starting screenshot for command_id: {command_id}")
                response = await self.run_screenshot(command_id, command_data)
                self.log(f"Screenshot complete, success: {response.get('success')}")
            
            elif command == "http_headers":
                # Get HTTP headers
                self.log(f"Starting HTTP headers scan for command_id: {command_id}")
                response = await self.run_http_headers(command_id, command_data)
                self.log(f"HTTP headers complete, success: {response.get('success')}")
            
            elif command == "robots":
                # Fetch robots.txt
                self.log(f"Starting robots.txt fetch for command_id: {command_id}")
                response = await self.run_robots_fetch(command_id, command_data)
                self.log(f"Robots.txt fetch complete, success: {response.get('success')}")
            
            elif command == "dns":
                # DNS lookup
                self.log(f"Starting DNS lookup for command_id: {command_id}")
                response = await self.run_dns_lookup(command_id, command_data)
                self.log(f"DNS lookup complete, success: {response.get('success')}")
            
            elif command == "dns_server":
                # DNS server security scan
                self.log(f"Starting DNS server scan for command_id: {command_id}")
                response = await self.run_dns_server_scan(command_id, command_data)
                self.log(f"DNS server scan complete, success: {response.get('success')}")
            
            elif command == "dig":
                # Dig DNS lookup
                self.log(f"Starting dig lookup for command_id: {command_id}")
                response = await self.run_dig_lookup(command_id, command_data)
                self.log(f"Dig lookup complete, success: {response.get('success')}")
            
            elif command == "ip_reputation":
                # IP reputation check
                self.log(f"Starting IP reputation check for command_id: {command_id}")
                response = await self.run_ip_reputation(command_id, command_data)
                self.log(f"IP reputation check complete, success: {response.get('success')}")
            
            elif command == "domain_reputation":
                # Domain reputation check
                self.log(f"Starting domain reputation check for command_id: {command_id}")
                response = await self.run_domain_reputation(command_id, command_data)
                self.log(f"Domain reputation check complete, success: {response.get('success')}")
            
            elif command == "speedtest":
                # Internet speed test
                self.log(f"Starting speedtest for command_id: {command_id}")
                response = await self.run_speedtest(command_id, command_data)
                self.log(f"Speedtest complete, success: {response.get('success')}")
            
            # OSINT Commands
            elif command == "email_osint":
                self.log(f"Starting email OSINT for command_id: {command_id}")
                response = await self.run_email_osint(command_id, command_data)
                self.log(f"Email OSINT complete, success: {response.get('success')}")
            
            elif command == "phone_osint":
                self.log(f"Starting phone OSINT for command_id: {command_id}")
                response = await self.run_phone_osint(command_id, command_data)
                self.log(f"Phone OSINT complete, success: {response.get('success')}")
            
            elif command == "username_osint":
                self.log(f"Starting username OSINT for command_id: {command_id}")
                response = await self.run_username_osint(command_id, command_data)
                self.log(f"Username OSINT complete, success: {response.get('success')}")
            
            elif command == "person_osint":
                self.log(f"Starting person OSINT for command_id: {command_id}")
                response = await self.run_person_osint(command_id, command_data)
                self.log(f"Person OSINT complete, success: {response.get('success')}")
            
            elif command == "company_osint":
                self.log(f"Starting company OSINT for command_id: {command_id}")
                response = await self.run_company_osint(command_id, command_data)
                self.log(f"Company OSINT complete, success: {response.get('success')}")
            
            elif command == "name_osint":
                # Name OSINT - use person_osint with name as target
                self.log(f"Starting name OSINT for command_id: {command_id}")
                # Convert name to username for lookup
                name = command_data.get("name") or command_data.get("target", "")
                username = name.replace(" ", "").lower()
                response = await self.run_username_osint(command_id, {"username": username})
                response["data"]["original_name"] = name
                self.log(f"Name OSINT complete, success: {response.get('success')}")
            
            elif command == "capabilities":
                # Return what this agent can do
                response["data"] = {
                    "commands": ["ping", "host_ping", "info", "echo", "nmap", "nikto", "dirb", "sslscan", "gobuster", "whatweb", "traceroute", "ssh_audit", "ftp_anon", "smtp", "imap", "banner", "screenshot", "http_headers", "robots", "dns", "dns_server", "dig", "ip_reputation", "domain_reputation", "speedtest", "email_osint", "phone_osint", "username_osint", "person_osint", "company_osint", "name_osint", "capabilities", "install_tool", "uninstall_tool", "check_tools", "update_agent", "restart", "redeploy", "destroy", "check_upnp", "run_command", "shell_start", "shell_input", "shell_stop", "shell_resize"],
                    "nmap_available": shutil.which("nmap") is not None,
                    "nikto_available": shutil.which("nikto") is not None,
                    "dirb_available": shutil.which("dirb") is not None,
                    "sslscan_available": shutil.which("sslscan") is not None,
                    "gobuster_available": shutil.which("gobuster") is not None,
                    "whatweb_available": shutil.which("whatweb") is not None,
                    "traceroute_available": shutil.which("traceroute") is not None,
                    "dig_available": shutil.which("dig") is not None,
                    "speedtest_available": shutil.which("speedtest-cli") is not None or shutil.which("speedtest") is not None,
                    "holehe_available": shutil.which("holehe") is not None,
                    "phoneinfoga_available": shutil.which("phoneinfoga") is not None,
                    "maigret_available": shutil.which("maigret") is not None,
                    "upnp_available": shutil.which("upnpc") is not None or shutil.which("upnpc-static") is not None,
                    "version": VERSION,
                    "shell_pty_available": shutil.which("tmux") is not None
                }
            
            elif command == "check_tools":
                # Check which tools are installed (always return all known tools)
                tools_data = await self.check_tools_status()
                print(f"[handle_command] check_tools response: {json.dumps(tools_data, indent=2)}")
                response["data"] = tools_data
            
            elif command == "install_tool":
                # Install a tool
                tool_name = command_data.get("tool")
                response = await self.install_tool(command_id, tool_name)
            
            elif command == "uninstall_tool":
                # Uninstall a tool
                tool_name = command_data.get("tool")
                response = await self.uninstall_tool(command_id, tool_name)
            
            elif command == "update_agent":
                # Self-update the agent
                response = await self.update_agent(command_id)
            
            elif command == "restart":
                # Restart the agent
                self.log(f"Restart requested via command_id: {command_id}")
                response["data"] = {
                    "message": "Agent restarting...",
                    "timestamp": datetime.utcnow().isoformat()
                }
                # Send response before restarting
                if self.ws:
                    await self.ws.send(json.dumps(response))
                # Schedule restart after a short delay
                await asyncio.sleep(0.5)
                self.log("Restarting agent...")
                current_script = os.path.abspath(__file__)
                os.execv(sys.executable, [sys.executable, current_script] + sys.argv[1:])
            elif command == "run_command":
                # Run a single shell command and return stdout/stderr and code
                cmd = command_data.get('cmd') or command_data.get('command') or ''
                timeout = command_data.get('timeout', 30)
                if not cmd:
                    response["success"] = False
                    response["error"] = "No command provided"
                else:
                    import shlex
                    try:
                        args = shlex.split(cmd)
                        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
                        response["data"] = {
                            "stdout": proc.stdout,
                            "stderr": proc.stderr,
                            "returncode": proc.returncode
                        }
                        response["success"] = proc.returncode == 0
                        if proc.returncode != 0:
                            response["error"] = proc.stderr or f"Command failed with code {proc.returncode}"
                    except subprocess.TimeoutExpired:
                        response["success"] = False
                        response["error"] = f"Command timed out after {timeout}s"
                    except FileNotFoundError as e:
                        response["success"] = False
                        response["error"] = str(e)
                    except Exception as e:
                        response["success"] = False
                        response["error"] = str(e)
            
            elif command == "shell_start":
                # Start a new PTY-based shell session and stream output
                cmd = command_data.get('command') or '/bin/sh'
                self.log(f"shell_start request: command={cmd}, current sessions={list(self.shell_sessions.keys())}")
                response = await self.start_shell_session(command_id, cmd)
                self.log(f"shell_start response: session_id={response.get('data', {}).get('session_id')}, sessions now={list(self.shell_sessions.keys())}")
            elif command == "shell_input":
                # Write input to an existing session (fire and forget)
                session_id = command_data.get('session_id')
                inp = command_data.get('input', '')
                self.log(f"shell_input request: session_id={session_id}, active_sessions={list(self.shell_sessions.keys())}", "DEBUG")
                ok, msg = await self.write_shell_input(session_id, inp)
                response = {
                    "type": "response",
                    "command_id": command_id,
                    "success": ok,
                    "data": {"session_id": session_id},
                    "error": None if ok else msg
                }
            elif command == "shell_stop":
                session_id = command_data.get('session_id')
                ok, msg = await self.stop_shell_session(session_id)
                response = {
                    "type": "response",
                    "command_id": command_id,
                    "success": ok,
                    "data": {"session_id": session_id},
                    "error": None if ok else msg
                }
            elif command == "shell_resize":
                # Resize pty window
                session_id = command_data.get('session_id')
                rows = command_data.get('rows') or command_data.get('rows', 24)
                cols = command_data.get('cols') or command_data.get('cols', 80)
                ok, msg = await self.resize_shell_session(session_id, rows, cols)
                response = {
                    "type": "response",
                    "command_id": command_id,
                    "success": ok,
                    "data": {"session_id": session_id},
                    "error": None if ok else msg
                }
            elif command == "webserver_start":
                # Start local web server
                port = command_data.get('port', 8888)
                token = command_data.get('token')
                response = await self._start_webserver(command_id, port, token)
            elif command == "webserver_stop":
                # Stop local web server
                response = await self._stop_webserver(command_id)
            elif command == "webserver_status":
                # Get webserver status
                response = {
                    "type": "response",
                    "command_id": command_id,
                    "success": True,
                    "data": {
                        "running": self._webserver_enabled and self._local_webserver is not None and self._local_webserver.running,
                        "port": self._webserver_port,
                        "url": f"http://{self.local_ip}:{self._webserver_port}" if self._webserver_enabled else None
                    }
                }
            
            elif command == "check_upnp":
                # Check UPnP availability on router
                response = await self._check_upnp(command_id)
            
            elif command == "redeploy":
                # Re-download and restart the agent
                self.log(f"Redeploy requested via command_id: {command_id}")
                response = await self._redeploy_agent(command_id)
            
            elif command == "destroy":
                # Clean up everything and terminate
                self.log(f"Destroy requested via command_id: {command_id}")
                response = await self._destroy_agent(command_id)
            
            else:
                response["success"] = False
                response["error"] = f"Unknown command: {command}"
                self.log(f"Unknown command: {command}", "WARNING")
        
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Command error: {e}", "ERROR")
        
        # Send response
        if self.ws:
            try:
                response_json = json.dumps(response)
                response_size = len(response_json)
                self.log(f"Sending response for command_id: {command_id}, size: {response_size} bytes ({response_size/1024:.1f} KB)")
                await self.ws.send(response_json)
                self.log(f"Response sent successfully for command_id: {command_id}")
            except Exception as send_err:
                self.log(f"Failed to send response for command_id {command_id}: {send_err}", "ERROR")
        else:
            self.log(f"Cannot send response for command_id {command_id}: no WebSocket connection", "ERROR")
    
    async def _priority_worker(self, worker_id: int):
        """Worker that processes high-priority commands (info, ping, shell) with no cooldown"""
        self.log(f"Priority worker {worker_id} started")
        
        while self.running and self.connected:
            try:
                # Get command from priority queue with timeout
                try:
                    command_data = await asyncio.wait_for(
                        self._priority_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Process the command immediately (no cooldown for priority commands)
                command = command_data.get("command", "unknown")
                self.log(f"Priority worker {worker_id} executing: {command}", "DEBUG")
                
                try:
                    await self.handle_command(command_data)
                except Exception as e:
                    self.log(f"Priority worker {worker_id} error: {e}", "ERROR")
                
                self._priority_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.log(f"Priority worker {worker_id} error: {e}", "ERROR")
                await asyncio.sleep(0.1)
        
        self.log(f"Priority worker {worker_id} stopped")
    
    async def _command_worker(self, worker_id: int):
        """Worker that processes scan commands from the queue (with cooldown)"""
        self.log(f"Command worker {worker_id} started")
        
        while self.running and self.connected:
            try:
                # Get command from queue with timeout to check running flag
                try:
                    command_data = await asyncio.wait_for(
                        self._command_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Process the command
                command = command_data.get("command", "unknown")
                self.log(f"Worker {worker_id} executing: {command}")
                
                try:
                    await self.handle_command(command_data)
                except Exception as e:
                    self.log(f"Worker {worker_id} command error: {e}", "ERROR")
                
                self._command_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.log(f"Worker {worker_id} error: {e}", "ERROR")
                await asyncio.sleep(0.5)
        
        self.log(f"Command worker {worker_id} stopped")
    
    async def message_loop(self):
        """Main loop for receiving messages"""
        if not self.ws:
            return
        
        try:
            async for message in self.ws:
                await self.handle_message(message)
        except ConnectionClosed as e:
            self.log(f"Connection closed: code={e.code} reason={e.reason}", "WARNING")
            # Check if key was invalidated while connected
            if e.code == 4002:
                self.log("API key was deleted or invalidated. Agent will stop reconnecting.", "ERROR")
                self.key_invalidated = True
            elif e.code == 4003:
                self.log("API key was disabled. Agent will retry with backoff.", "WARNING")
        except Exception as e:
            self.log(f"Message loop error: {e}", "ERROR")
        finally:
            self.connected = False
    
    async def heartbeat_loop(self):
        """Send periodic heartbeats"""
        while self.running and self.connected:
            try:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                if self.connected and self.ws:
                    await self.send_heartbeat()
            except Exception as e:
                self.log(f"Heartbeat error: {e}", "ERROR")
                break
    
    async def run(self):
        """Main agent run loop with auto-reconnect"""
        self.running = True
        
        # Create command queues - priority queue for fast commands, regular for scans
        self._command_queue = asyncio.Queue()
        self._priority_queue = asyncio.Queue()
        
        # Create installation lock
        self._install_lock = asyncio.Lock()
        
        self.log(f"micro-hack agent v{VERSION} starting...")
        self.log(f"Agent ID: {self.agent_id}")
        self.log(f"Hostname: {self.hostname}")
        self.log(f"OS: {self.os_info}")
        self.log(f"Local IP: {self.local_ip}")
        self.log(f"Command workers: {self._num_workers} + 2 priority workers")
        
        if not self.api_key:
            self.log("ERROR: MICROHACK_API_KEY environment variable not set!", "ERROR")
            return
        
        while self.running:
            # Connect
            if await self.connect():
                # Start command workers
                self._worker_tasks = []
                
                # 2 priority workers for fast commands (info, ping, shell)
                for i in range(2):
                    task = asyncio.create_task(self._priority_worker(i))
                    self._worker_tasks.append(task)
                
                # Regular workers for scan commands
                for i in range(self._num_workers):
                    task = asyncio.create_task(self._command_worker(i))
                    self._worker_tasks.append(task)
                
                # Start message and heartbeat loops
                message_task = asyncio.create_task(self.message_loop())
                heartbeat_task = asyncio.create_task(self.heartbeat_loop())
                
                # Wait for message or heartbeat to complete (connection closed)
                done, pending = await asyncio.wait(
                    [message_task, heartbeat_task],
                    return_when=asyncio.FIRST_COMPLETED
                )
                
                # Cancel pending tasks (message/heartbeat)
                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                
                # Cancel worker tasks
                for task in self._worker_tasks:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                self._worker_tasks = []
                
                # Close WebSocket
                if self.ws:
                    try:
                        await self.ws.close()
                    except:
                        pass
                    self.ws = None
                
                self.connected = False
            
            # Check if key was invalidated - stop reconnecting
            if self.key_invalidated:
                self.log("API key is invalid or deleted. Agent stopping.", "ERROR")
                self.log("To reconnect: generate a new API key, update MICROHACK_API_KEY, and restart the agent.", "ERROR")
                self.running = False
                break
            
            # Reconnect with backoff
            if self.running:
                self.log(f"Reconnecting in {self.reconnect_delay} seconds...")
                await asyncio.sleep(self.reconnect_delay)
                self.reconnect_delay = min(self.reconnect_delay * 2, MAX_RECONNECT_DELAY)
    
    async def _start_webserver(self, command_id: str, port: int = 8888, token: str = None) -> dict:
        """Start the local web server"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        try:
            # Stop existing webserver if running
            if self._local_webserver and self._local_webserver.running:
                await self._local_webserver.stop()
                if self._webserver_task:
                    self._webserver_task.cancel()
                    try:
                        await self._webserver_task
                    except asyncio.CancelledError:
                        pass
            
            # Create and start new webserver
            self._webserver_port = port
            self._webserver_token = token
            self._local_webserver = AgentLocalWebServer(self, port, token)
            self._webserver_enabled = True
            
            # Start in background task
            self._webserver_task = asyncio.create_task(self._local_webserver.start())
            
            # Wait a moment for it to start
            await asyncio.sleep(0.5)
            
            url = f"http://{self.local_ip}:{port}"
            if token:
                url += f"?token={token}"
            
            response["data"] = {
                "running": True,
                "port": port,
                "url": url,
                "token_required": token is not None
            }
            self.log(f"Local webserver started on port {port}")
            
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Failed to start webserver: {e}", "ERROR")
        
        return response
    
    async def _stop_webserver(self, command_id: str) -> dict:
        """Stop the local web server"""
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        try:
            if self._local_webserver and self._local_webserver.running:
                await self._local_webserver.stop()
            
            if self._webserver_task:
                self._webserver_task.cancel()
                try:
                    await self._webserver_task
                except asyncio.CancelledError:
                    pass
                self._webserver_task = None
            
            self._webserver_enabled = False
            self._local_webserver = None
            
            response["data"] = {"running": False}
            self.log("Local webserver stopped")
            
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Failed to stop webserver: {e}", "ERROR")
        
        return response
    
    def stop(self):
        """Stop the agent"""
        self.log("Stopping agent...")
        self.running = False


async def main():
    """Main entry point"""
    agent = MicroHackAgent(SERVER_URL, API_KEY)
    
    # Handle shutdown signals
    loop = asyncio.get_event_loop()
    
    def signal_handler():
        agent.stop()
    
    try:
        loop.add_signal_handler(signal.SIGINT, signal_handler)
        loop.add_signal_handler(signal.SIGTERM, signal_handler)
    except NotImplementedError:
        # Windows doesn't support add_signal_handler
        pass
    
    await agent.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAgent stopped by user")
