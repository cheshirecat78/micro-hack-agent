#!/usr/bin/env python3
"""
micro-hack remote agent

A lightweight agent that connects to the micro-hack server via WebSocket
and executes commands on demand (including nmap scans).

Usage:
    Set environment variables:
    - MICROHACK_SERVER_URL: WebSocket URL (e.g., ws://localhost:8000 or wss://app.micro-hack.nl)
    - MICROHACK_API_KEY: Your agent API key from micro-hack
    
    Then run:
    python agent.py
"""
import os
import sys
import json
import uuid
import socket
import platform
import asyncio
import signal
import subprocess
import shutil
from datetime import datetime
from typing import Optional

try:
    import websockets
    from websockets.exceptions import ConnectionClosed, InvalidStatusCode
except ImportError:
    print("ERROR: websockets library not installed. Run: pip install websockets")
    sys.exit(1)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    print("WARNING: psutil library not installed. System metrics will not be available. Run: pip install psutil")
    PSUTIL_AVAILABLE = False

# Agent version
VERSION = "1.3.2"

# Agent update URL (raw Python file)
AGENT_UPDATE_URL = os.environ.get(
    "MICROHACK_AGENT_UPDATE_URL", 
    "https://raw.githubusercontent.com/cheshirecat78/micro-hack/main/agent/agent.py"
)

# Supported tools and their install commands (Debian/Ubuntu based)
# Note: Some tools require additional setup or alternative installation methods
TOOL_INSTALL_COMMANDS = {
    "nmap": {
        "check": "nmap",
        "install": ["apt-get", "install", "-y", "nmap"],
        "description": "Network scanner",
        "pre_install": None
    },
    "nikto": {
        "check": "nikto",
        # nikto is in Debian, but might need to enable non-free or use git
        "install": ["apt-get", "install", "-y", "nikto"],
        "install_alt": ["git", "clone", "https://github.com/sullo/nikto.git", "/opt/nikto"],
        "post_install_alt": ["ln", "-sf", "/opt/nikto/program/nikto.pl", "/usr/local/bin/nikto"],
        "description": "Web server scanner",
        "pre_install": None
    },
    "dirb": {
        "check": "dirb",
        "install": ["apt-get", "install", "-y", "dirb"],
        "description": "Web content scanner",
        "pre_install": None
    },
    "gobuster": {
        "check": "gobuster",
        "install": ["apt-get", "install", "-y", "gobuster"],
        "description": "Directory/file brute-forcer",
        "pre_install": None
    },
    "whatweb": {
        "check": "whatweb",
        "install": ["apt-get", "install", "-y", "whatweb"],
        "description": "Web technology scanner",
        "pre_install": None
    },
    "enum4linux": {
        "check": "enum4linux",
        "install": ["apt-get", "install", "-y", "enum4linux"],
        "install_alt": ["git", "clone", "https://github.com/CiscoCXSecurity/enum4linux.git", "/opt/enum4linux"],
        "post_install_alt": ["ln", "-sf", "/opt/enum4linux/enum4linux.pl", "/usr/local/bin/enum4linux"],
        "description": "SMB/Samba enumeration tool",
        "pre_install": ["apt-get", "install", "-y", "smbclient", "ldap-utils", "perl"]
    },
    "smbclient": {
        "check": "smbclient",
        "install": ["apt-get", "install", "-y", "smbclient"],
        "description": "SMB protocol client",
        "pre_install": None
    },
    "testssl": {
        "check": "testssl",
        "install": ["apt-get", "install", "-y", "testssl.sh"],
        "install_alt": ["git", "clone", "--depth", "1", "https://github.com/drwetter/testssl.sh.git", "/opt/testssl"],
        "post_install_alt": ["ln", "-sf", "/opt/testssl/testssl.sh", "/usr/local/bin/testssl"],
        "description": "TLS/SSL encryption testing",
        "pre_install": None
    },
    "hydra": {
        "check": "hydra",
        "install": ["apt-get", "install", "-y", "hydra"],
        "description": "Network login brute-forcer",
        "pre_install": None
    },
    "sqlmap": {
        "check": "sqlmap",
        "install": ["apt-get", "install", "-y", "sqlmap"],
        "description": "SQL injection detection",
        "pre_install": None
    },
    "wpscan": {
        "check": "wpscan",
        "install": ["gem", "install", "wpscan"],
        "description": "WordPress vulnerability scanner",
        "pre_install": ["apt-get", "install", "-y", "ruby", "ruby-dev", "build-essential", "libcurl4-openssl-dev", "zlib1g-dev"]
    },
    "ffuf": {
        "check": "ffuf",
        "install": ["apt-get", "install", "-y", "ffuf"],
        "install_alt": ["go", "install", "github.com/ffuf/ffuf/v2@latest"],
        "description": "Fast web fuzzer",
        "pre_install": None
    },
    "masscan": {
        "check": "masscan",
        "install": ["apt-get", "install", "-y", "masscan"],
        "description": "High-speed port scanner",
        "pre_install": None
    },
    "tcpdump": {
        "check": "tcpdump",
        "install": ["apt-get", "install", "-y", "tcpdump"],
        "description": "Packet analyzer",
        "pre_install": None
    },
    "whois": {
        "check": "whois",
        "install": ["apt-get", "install", "-y", "whois"],
        "description": "Domain registration lookup",
        "pre_install": None
    },
    "dig": {
        "check": "dig",
        "install": ["apt-get", "install", "-y", "dnsutils"],
        "description": "DNS lookup utility",
        "pre_install": None
    },
    "curl": {
        "check": "curl",
        "install": ["apt-get", "install", "-y", "curl"],
        "description": "HTTP client and transfer tool",
        "pre_install": None
    },
    "wget": {
        "check": "wget",
        "install": ["apt-get", "install", "-y", "wget"],
        "description": "Network file downloader",
        "pre_install": None
    },
    "netcat": {
        "check": "nc",
        "install": ["apt-get", "install", "-y", "netcat-openbsd"],
        "description": "Network connection utility",
        "pre_install": None
    },
    "traceroute": {
        "check": "traceroute",
        "install": ["apt-get", "install", "-y", "traceroute"],
        "description": "Network path tracer",
        "pre_install": None
    },
    "openssl": {
        "check": "openssl",
        "install": ["apt-get", "install", "-y", "openssl"],
        "description": "SSL/TLS toolkit",
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
        
        # Gather system info
        self.hostname = socket.gethostname()
        self.os_info = f"{platform.system()} {platform.release()}"
        
        self.local_ip = self._get_local_ip()
        self.remote_ip = None
        self.location = None
    
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
        """Refresh network information (local IP, remote IP, location)"""
        old_local_ip = self.local_ip
        old_remote_ip = self.remote_ip
        
        self.local_ip = self._get_local_ip()
        self.remote_ip, self.location = self._get_remote_ip_and_location()
        
        if old_local_ip != self.local_ip:
            self.log(f"Local IP changed: {old_local_ip} -> {self.local_ip}")
        if old_remote_ip != self.remote_ip:
            self.log(f"Remote IP: {self.remote_ip}")
        if self.location:
            self.log(f"Location: {self.location.get('city')}, {self.location.get('country')}")
    
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
            elif e.status_code == 4002:
                self.log("Connection rejected: Invalid API key", "ERROR")
            elif e.status_code == 4003:
                self.log("Connection rejected: API key is disabled", "ERROR")
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
                "capabilities": ["ping", "info", "nmap", "install_tool", "check_tools", "update_agent"]
            }
        }
        
        await self.ws.send(json.dumps(registration))
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
            await self.handle_command(data)
        
        elif msg_type == "error":
            self.log(f"Server error: {data.get('message')}", "ERROR")
        
        else:
            self.log(f"Unknown message type: {msg_type}", "WARNING")
    
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
        
        # Check if nmap is available
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            response["success"] = False
            response["error"] = "nmap is not installed on this agent"
            return response
        
        target = command_data.get("target")
        if not target:
            response["success"] = False
            response["error"] = "No target specified"
            return response
        
        scan_type = command_data.get("scan_type", "quick")
        ports = command_data.get("ports")
        extra_args = command_data.get("arguments", "")
        project_id = command_data.get("project_id")  # For associating results
        
        # Build nmap command
        # Always use -oX - for XML output to stdout
        cmd = ["nmap", "-oX", "-"]
        
        if scan_type == "quick":
            cmd.extend(["-T4", "-F"])  # Fast scan, top 100 ports
        elif scan_type == "full":
            cmd.extend(["-T4", "-A", "-p-"])  # All ports, version detection, scripts
        elif scan_type == "ports":
            cmd.extend(["-T4", "-sV"])  # Version detection
            if ports:
                cmd.extend(["-p", ports])
        elif scan_type == "vuln":
            cmd.extend(["-T4", "-sV", "--script", "vuln"])
            if ports:
                cmd.extend(["-p", ports])
        elif scan_type == "discovery":
            cmd.extend(["-sn"])  # Ping scan only, no port scan
        
        # Add extra arguments if provided (be careful with this)
        if extra_args:
            # Only allow safe arguments
            safe_args = extra_args.replace(";", "").replace("&", "").replace("|", "")
            cmd.extend(safe_args.split())
        
        cmd.append(target)
        
        self.log(f"Running nmap scan: {' '.join(cmd)}")
        
        try:
            # Run nmap asynchronously
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=600  # 10 minute timeout for scans
            )
            
            xml_output = stdout.decode("utf-8", errors="replace")
            
            if process.returncode != 0:
                error_msg = stderr.decode("utf-8", errors="replace")
                self.log(f"nmap error: {error_msg}", "ERROR")
                # Still try to parse partial results if any
                if not xml_output or "<nmaprun" not in xml_output:
                    response["success"] = False
                    response["error"] = f"nmap failed: {error_msg}"
                    return response
            
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
        
        # Check if nikto is installed
        if not shutil.which("nikto"):
            response["success"] = False
            response["error"] = "nikto is not installed. Use the install_tool command to install it."
            return response
        
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
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=1800  # 30 minute timeout for nikto
            )
            
            output = stdout.decode("utf-8", errors="replace")
            
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
        
        # Check if dirb is installed
        if not shutil.which("dirb"):
            response["success"] = False
            response["error"] = "dirb is not installed. Use the install_tool command to install it."
            return response
        
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
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=1800  # 30 minute timeout
            )
            
            output = stdout.decode("utf-8", errors="replace")
            
            # Parse dirb output
            directories = []
            for line in output.split("\n"):
                line = line.strip()
                if line.startswith("+ ") or line.startswith("==> DIRECTORY: "):
                    # Extract URL
                    if line.startswith("+ "):
                        parts = line[2:].split(" ")
                        if parts:
                            directories.append({
                                "url": parts[0],
                                "type": "file",
                                "status": parts[1] if len(parts) > 1 else ""
                            })
                    else:
                        url = line.replace("==> DIRECTORY: ", "").strip()
                        directories.append({
                            "url": url,
                            "type": "directory"
                        })
            
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
        
        # Check if sslscan is installed
        if not shutil.which("sslscan"):
            response["success"] = False
            response["error"] = "sslscan is not installed. Use the install_tool command to install it."
            return response
        
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
        
        # Check if gobuster is installed
        if not shutil.which("gobuster"):
            response["success"] = False
            response["error"] = "gobuster is not installed. Use the install_tool command to install it."
            return response
        
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
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=1800  # 30 minute timeout
            )
            
            output = stdout.decode("utf-8", errors="replace")
            
            # Parse gobuster output
            entries = []
            for line in output.split("\n"):
                line = line.strip()
                if not line:
                    continue
                # Format: /path (Status: 200) [Size: 1234]
                if "(Status:" in line:
                    parts = line.split(" ")
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
        
        # Check if whatweb is installed
        if not shutil.which("whatweb"):
            response["success"] = False
            response["error"] = "whatweb is not installed. Use the install_tool command to install it."
            return response
        
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
                timeout=120  # 2 minute timeout
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
            response["error"] = "WhatWeb scan timed out (2 minute limit)"
            self.log("WhatWeb scan timed out", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"WhatWeb error: {e}", "ERROR")
        
        return response
    
    async def check_tools_status(self) -> dict:
        """Check which tools are installed and available"""
        tools_status = {}
        
        for tool_name, tool_info in TOOL_INSTALL_COMMANDS.items():
            check_cmd = tool_info["check"]
            is_installed = shutil.which(check_cmd) is not None
            
            # Try to get version if installed
            version = None
            if is_installed:
                try:
                    if tool_name == "nmap":
                        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            # Extract version from first line
                            version = result.stdout.split("\n")[0]
                    elif tool_name == "nikto":
                        result = subprocess.run(["nikto", "-Version"], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            version = result.stdout.strip()
                    elif tool_name == "dirb":
                        result = subprocess.run(["dirb"], capture_output=True, text=True, timeout=5)
                        # dirb prints version in first line
                        if result.stdout:
                            first_line = result.stdout.split("\n")[0]
                            if "DIRB" in first_line:
                                version = first_line.strip()
                except:
                    pass
            
            tools_status[tool_name] = {
                "installed": is_installed,
                "version": version,
                "description": tool_info["description"]
            }
        
        return {
            "tools": tools_status,
            "can_install": self._is_root()  # Check if running as root
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
            response["error"] = "Installation timed out (5 minute limit)"
            self.log(f"Install timed out", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Install error: {e}", "ERROR")
        
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
                "message": f"Agent updated from {VERSION} to {new_version}. Restart agent to apply changes.",
                "backup_path": backup_path
            }
            
        except urllib.error.URLError as e:
            response["success"] = False
            response["error"] = f"Failed to download update: {e}"
            self.log(f"Update download failed: {e}", "ERROR")
        except Exception as e:
            response["success"] = False
            response["error"] = str(e)
            self.log(f"Update error: {e}", "ERROR")
        
        return response
    
    async def handle_command(self, data: dict):
        """Handle a command from the server"""
        command_id = data.get("command_id")
        command = data.get("command")
        command_data = data.get("data", {})
        
        self.log(f"Received command: {command}")
        
        response = {
            "type": "response",
            "command_id": command_id,
            "success": True,
            "data": {}
        }
        
        try:
            if command == "ping":
                response["data"] = {
                    "message": "pong",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            elif command == "info":
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
            
            elif command == "echo":
                # Echo back the data
                response["data"] = {
                    "echo": command_data.get("message", ""),
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            elif command == "nmap":
                # Run nmap scan
                self.log(f"Starting nmap scan for command_id: {command_id}")
                response = await self.run_nmap_scan(command_id, command_data)
                self.log(f"Nmap scan complete, success: {response.get('success')}")
            
            elif command == "nikto":
                # Run nikto web vulnerability scan
                self.log(f"Starting nikto scan for command_id: {command_id}")
                response = await self.run_nikto_scan(command_id, command_data)
                self.log(f"Nikto scan complete, success: {response.get('success')}")
            
            elif command == "dirb":
                # Run dirb directory scan
                self.log(f"Starting dirb scan for command_id: {command_id}")
                response = await self.run_dirb_scan(command_id, command_data)
                self.log(f"Dirb scan complete, success: {response.get('success')}")
            
            elif command == "sslscan":
                # Run SSL/TLS scan
                self.log(f"Starting sslscan for command_id: {command_id}")
                response = await self.run_sslscan(command_id, command_data)
                self.log(f"SSLscan complete, success: {response.get('success')}")
            
            elif command == "gobuster":
                # Run gobuster directory scan
                self.log(f"Starting gobuster scan for command_id: {command_id}")
                response = await self.run_gobuster_scan(command_id, command_data)
                self.log(f"Gobuster scan complete, success: {response.get('success')}")
            
            elif command == "whatweb":
                # Run whatweb fingerprinting scan
                self.log(f"Starting whatweb scan for command_id: {command_id}")
                response = await self.run_whatweb_scan(command_id, command_data)
                self.log(f"WhatWeb scan complete, success: {response.get('success')}")
            
            elif command == "capabilities":
                # Return what this agent can do
                response["data"] = {
                    "commands": ["ping", "info", "echo", "nmap", "nikto", "dirb", "sslscan", "gobuster", "whatweb", "capabilities", "install_tool", "check_tools", "update_agent"],
                    "nmap_available": shutil.which("nmap") is not None,
                    "nikto_available": shutil.which("nikto") is not None,
                    "dirb_available": shutil.which("dirb") is not None,
                    "sslscan_available": shutil.which("sslscan") is not None,
                    "gobuster_available": shutil.which("gobuster") is not None,
                    "whatweb_available": shutil.which("whatweb") is not None,
                    "version": VERSION
                }
            
            elif command == "check_tools":
                # Check which tools are installed
                response["data"] = await self.check_tools_status()
            
            elif command == "install_tool":
                # Install a tool
                tool_name = command_data.get("tool")
                response = await self.install_tool(command_id, tool_name)
            
            elif command == "update_agent":
                # Self-update the agent
                response = await self.update_agent(command_id)
            
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
            response_json = json.dumps(response)
            self.log(f"Sending response for command_id: {command_id}, size: {len(response_json)} bytes")
            await self.ws.send(response_json)
            self.log(f"Response sent successfully")
    
    async def message_loop(self):
        """Main loop for receiving messages"""
        if not self.ws:
            return
        
        try:
            async for message in self.ws:
                await self.handle_message(message)
        except ConnectionClosed as e:
            self.log(f"Connection closed: {e}", "WARNING")
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
        
        self.log(f"micro-hack agent v{VERSION} starting...")
        self.log(f"Agent ID: {self.agent_id}")
        self.log(f"Hostname: {self.hostname}")
        self.log(f"OS: {self.os_info}")
        self.log(f"Local IP: {self.local_ip}")
        
        if not self.api_key:
            self.log("ERROR: MICROHACK_API_KEY environment variable not set!", "ERROR")
            return
        
        while self.running:
            # Connect
            if await self.connect():
                # Start message and heartbeat loops
                message_task = asyncio.create_task(self.message_loop())
                heartbeat_task = asyncio.create_task(self.heartbeat_loop())
                
                # Wait for either to complete (connection closed)
                done, pending = await asyncio.wait(
                    [message_task, heartbeat_task],
                    return_when=asyncio.FIRST_COMPLETED
                )
                
                # Cancel pending tasks
                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                
                # Close WebSocket
                if self.ws:
                    try:
                        await self.ws.close()
                    except:
                        pass
                    self.ws = None
                
                self.connected = False
            
            # Reconnect with backoff
            if self.running:
                self.log(f"Reconnecting in {self.reconnect_delay} seconds...")
                await asyncio.sleep(self.reconnect_delay)
                self.reconnect_delay = min(self.reconnect_delay * 2, MAX_RECONNECT_DELAY)
    
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
