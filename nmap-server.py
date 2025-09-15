# Nmap Server - This requires root privileges

import json
import sys
import asyncio
import os
import subprocess
import xml.etree.ElementTree as ET
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("nmap-server")


def validate_target(target: str) -> bool:
    """Validate target format for security."""
    # IP address pattern
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # CIDR pattern
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    # Hostname pattern
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    
    return bool(
        re.match(ip_pattern, target) or 
        re.match(cidr_pattern, target) or 
        re.match(hostname_pattern, target)
    )

async def execute_nmap(target: str, options: List[str], scan_type: str, use_sudo: bool = False) -> Dict[str, Any]:
    """Execute Nmap scan with comprehensive error handling and optional sudo."""
    if not validate_target(target):
        return {"error": "Invalid target format. Use IP address, hostname, or CIDR notation."}

    # Construct command with XML output for better parsing
    base_cmd = ["nmap", "-oX", "-"] + options + [target]
    
    # Add sudo if needed
    if use_sudo:
        # Check if we can use sudo
        if os.geteuid() != 0:  # Not running as root
            # Try to check if sudo is available and configured
            try:
                sudo_check = subprocess.run(
                    ["sudo", "-n", "nmap", "--version"], 
                    capture_output=True, 
                    timeout=5
                )
                if sudo_check.returncode != 0:
                    return {
                        "error": "Sudo privileges required but not available. Configure sudoers or run as root.",
                        "suggestion": "Run: sudo visudo and add: 'your_username ALL=(ALL) NOPASSWD: /usr/bin/nmap'"
                    }
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return {
                    "error": "Cannot verify sudo access. Ensure sudo is installed and configured.",
                    "suggestion": "Try running the application with: sudo python nmap_server.py"
                }
        
        cmd = ["sudo"] + base_cmd
    else:
        cmd = base_cmd
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Apply timeout to communicate() instead of process creation
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=600  # 10 minute timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return {"error": "Scan timeout (10 minutes exceeded)"}
        
        result = {
            "scan_type": scan_type,
            "target": target,
            "command": " ".join(cmd),
            "return_code": process.returncode,
            "raw_output": stdout.decode('utf-8', errors='ignore'),
            "error_output": stderr.decode('utf-8', errors='ignore') if stderr else None,
            "timestamp": datetime.now().isoformat()
        }
        
        # Parse XML output if successful
        if process.returncode == 0 and result["raw_output"]:
            try:
                parsed_data = parse_nmap_xml(result["raw_output"])
                result["parsed_results"] = parsed_data
                result["summary"] = generate_scan_summary(parsed_data)
            except Exception as e:
                result["parse_error"] = str(e)
        
        return result
        
    except FileNotFoundError:
        return {"error": "Nmap not found. Please install: sudo apt install nmap"}
    except Exception as e:
        return {"error": f"Execution error: {str(e)}"}

def parse_nmap_xml(xml_output: str) -> Dict[str, Any]:
    """Parse Nmap XML output into structured data."""
    try:
        root = ET.fromstring(xml_output)
        
        parsed = {
            "scan_info": {},
            "hosts": [],
            "total_hosts": 0,
            "up_hosts": 0,
            "down_hosts": 0
        }
        
        # Parse scan info
        scaninfo = root.find('scaninfo')
        if scaninfo is not None:
            parsed["scan_info"] = {
                "type": scaninfo.get('type'),
                "protocol": scaninfo.get('protocol'),
                "numservices": scaninfo.get('numservices'),
                "services": scaninfo.get('services')
            }
        
        # Parse hosts
        for host in root.findall('host'):
            host_data = {
                "state": host.find('status').get('state') if host.find('status') is not None else 'unknown',
                "addresses": [],
                "hostnames": [],
                "ports": [],
                "os": {},
                "services": []
            }
            
            # Parse addresses
            for address in host.findall('address'):
                host_data["addresses"].append({
                    "addr": address.get('addr'),
                    "addrtype": address.get('addrtype')
                })
            
            # Parse hostnames
            hostnames_elem = host.find('hostnames')
            if hostnames_elem is not None:
                for hostname in hostnames_elem.findall('hostname'):
                    host_data["hostnames"].append({
                        "name": hostname.get('name'),
                        "type": hostname.get('type')
                    })
            
            # Parse ports
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    state = port.find('state')
                    service = port.find('service')
                    
                    port_data = {
                        "portid": port.get('portid'),
                        "protocol": port.get('protocol'),
                        "state": state.get('state') if state is not None else 'unknown'
                    }
                    
                    if service is not None:
                        port_data["service"] = {
                            "name": service.get('name'),
                            "product": service.get('product'),
                            "version": service.get('version'),
                            "extrainfo": service.get('extrainfo'),
                            "method": service.get('method'),
                            "conf": service.get('conf')
                        }
                    
                    host_data["ports"].append(port_data)
            
            # Parse OS detection
            os_elem = host.find('os')
            if os_elem is not None:
                osmatch = os_elem.find('osmatch')
                if osmatch is not None:
                    host_data["os"] = {
                        "name": osmatch.get('name'),
                        "accuracy": osmatch.get('accuracy'),
                        "line": osmatch.get('line')
                    }
            
            parsed["hosts"].append(host_data)
            
            # Count host states
            if host_data["state"] == "up":
                parsed["up_hosts"] += 1
            elif host_data["state"] == "down":
                parsed["down_hosts"] += 1
            parsed["total_hosts"] += 1
        
        return parsed
        
    except ET.ParseError as e:
        raise Exception(f"XML parsing error: {e}")

# Verbose summary of the scan
def generate_scan_summary(parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a summary of scan results."""
    summary = {
        "total_hosts_scanned": parsed_data["total_hosts"],
        "hosts_up": parsed_data["up_hosts"],
        "hosts_down": parsed_data["down_hosts"],
        "total_open_ports": 0,
        "services_detected": [],
        "open_ports_by_host": {}
    }
    
    for host in parsed_data["hosts"]:
        if host["addresses"]:
            host_addr = host["addresses"][0]["addr"]
            open_ports = [p for p in host["ports"] if p["state"] == "open"]
            summary["total_open_ports"] += len(open_ports)
            summary["open_ports_by_host"][host_addr] = len(open_ports)
            
            # Collect unique services
            for port in open_ports:
                if "service" in port and port["service"]["name"]:
                    service_info = f"{port['service']['name']}:{port['portid']}"
                    if service_info not in summary["services_detected"]:
                        summary["services_detected"].append(service_info)
    
    return summary


# Discovery tool

@mcp.tool()
async def nmap_ping_sweep(target_network: str, timeout: int = 5):
    """
    Perform ping sweep to discover live hosts.
    
    Args:
        target_network: Network range (e.g., 192.168.1.0/24)
        timeout: Timeout in seconds for each host
    """
    try:
        options = ["-sn", "--host-timeout", f"{timeout}s"]
        result = await execute_nmap(target_network, options, "Ping Sweep", use_sudo=False)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Ping sweep failed: {str(e)}"})

# TCP port scan tool

@mcp.tool()
async def nmap_tcp_scan(target: str, ports: str = "1-1000", scan_type: str = "connect"):
    """
    Perform TCP port scan.
    
    Args:
        target: Target IP or hostname
        ports: Port specification (e.g., "22,80,443" or "1-1000")
        scan_type: Scan type ("connect" for -sT, "syn" for -sS)
    """
    try:
        if scan_type == "syn":
            options = ["-sS", "-p", ports]
            scan_name = "TCP SYN Scan"
            use_sudo = True
        else:
            options = ["-sT", "-p", ports]
            scan_name = "TCP Connect Scan"
            use_sudo = False
            
        result = await execute_nmap(target, options, scan_name, use_sudo)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"TCP scan failed: {str(e)}"})

# UDP service scan tool

@mcp.tool()
async def nmap_udp_scan(target: str, ports: str = "53,67,68,69,123,161,162"):
    """
    Perform UDP scan on common ports.
    
    Args:
        target: Target IP or hostname  
        ports: UDP ports to scan (default: common UDP services)
    """
    try:
        options = ["-sU", "-p", ports]
        result = await execute_nmap(target, options, "UDP Scan", use_sudo=True)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"UDP scan failed: {str(e)}"})

# Service detection tool

@mcp.tool()
async def nmap_service_scan(target: str, ports: str = "1-1000"):
    """
    Detect service versions on open ports.
    
    Args:
        target: Target IP or hostname
        ports: Port specification to scan
    """
    try:
        options = ["-sV", "-p", ports]
        result = await execute_nmap(target, options, "Service Version Detection", use_sudo=False)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Service scan failed: {str(e)}"})

@mcp.tool()
async def nmap_os_detection(target: str):
    """
    Perform OS detection (requires root privileges).
    
    Args:
        target: Target IP or hostname
    """
    try:
        options = ["-O"]
        result = await execute_nmap(target, options, "OS Detection", use_sudo=True)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"OS detection failed: {str(e)}"})

@mcp.tool()
async def nmap_aggressive_scan(target: str, ports: str = "1-1000"):
    """
    Perform aggressive scan with OS detection, version detection, and scripts.
    
    Args:
        target: Target IP or hostname
        ports: Port specification to scan
    """
    try:
        options = ["-A", "-p", ports]
        result = await execute_nmap(target, options, "Aggressive Scan", use_sudo=True)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Aggressive scan failed: {str(e)}"})

# Script scanning tool 
@mcp.tool()
async def nmap_vuln_scan(target: str, ports: str = "1-1000"):
    """
    Run vulnerability detection scripts.
    
    Args:
        target: Target IP or hostname
        ports: Port specification to scan
    """
    try:
        options = ["--script", "vuln", "-p", ports]
        result = await execute_nmap(target, options, "Vulnerability Scan", use_sudo=False)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Vulnerability scan failed: {str(e)}"})

@mcp.tool()
async def nmap_script_scan(target: str, script_name: str, ports: str = "1-1000"):
    """
    Run specific NSE scripts.
    
    Args:
        target: Target IP or hostname
        script_name: NSE script name (e.g., "http-enum", "smb-enum-shares")
        ports: Port specification to scan
    """
    try:
        options = ["--script", script_name, "-p", ports]
        result = await execute_nmap(target, options, f"NSE Script: {script_name}", use_sudo=False)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Script scan failed: {str(e)}"})

@mcp.tool()
async def nmap_default_scripts(target: str, ports: str = "1-1000"):
    """
    Run default NSE scripts (safe and informative).
    
    Args:
        target: Target IP or hostname
        ports: Port specification to scan
    """
    try:
        options = ["-sC", "-p", ports]
        result = await execute_nmap(target, options, "Default Scripts Scan", use_sudo=False)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Default scripts scan failed: {str(e)}"})

#  Stealth scan tool 
@mcp.tool()
async def nmap_stealth_scan(target: str, ports: str = "1-1000"):
    """
    Perform stealth scan to avoid detection.
    
    Args:
        target: Target IP or hostname
        ports: Port specification to scan
    """
    try:
        options = ["-sS", "-T2", "-f", "--source-port", "53", "-p", ports]
        result = await execute_nmap(target, options, "Stealth Scan", use_sudo=True)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Stealth scan failed: {str(e)}"})

@mcp.tool()
async def nmap_timing_scan(target: str, timing: str = "T3", ports: str = "1-1000"):
    """
    Scan with specific timing template.
    
    Args:
        target: Target IP or hostname
        timing: Timing template (T0=paranoid, T1=sneaky, T2=polite, T3=normal, T4=aggressive, T5=insane)
        ports: Port specification to scan
    """
    try:
        if timing not in ["T0", "T1", "T2", "T3", "T4", "T5"]:
            return json.dumps({"error": "Invalid timing. Use T0-T5 (e.g., T3)"})
        
        options = ["-sS", f"-{timing}", "-p", ports]
        result = await execute_nmap(target, options, f"Timing {timing} Scan", use_sudo=True)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Timing scan failed: {str(e)}"})

@mcp.tool()
async def nmap_top_ports(target: str, top_ports: int = 1000):
    """
    Scan most common ports.
    
    Args:
        target: Target IP or hostname
        top_ports: Number of top ports to scan (default: 1000)
    """
    try:
        options = ["-sS", "--top-ports", str(top_ports)]
        result = await execute_nmap(target, options, f"Top {top_ports} Ports Scan", use_sudo=True)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Top ports scan failed: {str(e)}"})

# Custom scan
@mcp.tool()
async def nmap_custom_scan(target: str, options: str):
    """
    Execute custom Nmap command with specified options.
    
    Args:
        target: Target IP or hostname
        options: Custom Nmap options string (space-separated)
    """
    try:
        option_list = options.split()
        # Determine if sudo is needed based on scan type
        use_sudo = any(opt in option_list for opt in ["-sS", "-sU", "-O", "-A"])
        
        result = await execute_nmap(target, option_list, "Custom Nmap Command", use_sudo)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Custom scan failed: {str(e)}"})

# System prompt
@mcp.prompt()
def nmap_analysis_prompt(target: str = "") -> str:
    """
    Guide Claude to perform Nmap reconnaissance and analysis.
    
    Args:
        target: Optional target to focus analysis on
    """
    target_text = f" focusing on: {target}" if target else ""
    
    return f"""
You are a cybersecurity analyst using Nmap for network reconnaissance{target_text}.

Available Nmap tools:

Discovery Tools:
1. nmap_ping_sweep(target_network, timeout) - Discover live hosts
2. nmap_tcp_scan(target, ports, scan_type) - TCP port scanning
3. nmap_udp_scan(target, ports) - UDP port scanning (requires sudo)

Service Detection Tools:
4. nmap_service_scan(target, ports) - Service version detection
5. nmap_os_detection(target) - Operating system detection (requires sudo)
6. nmap_aggressive_scan(target, ports) - Comprehensive scan (requires sudo)

Script Scanning Tools:
7. nmap_vuln_scan(target, ports) - Vulnerability detection
8. nmap_script_scan(target, script_name, ports) - Specific NSE scripts
9. nmap_default_scripts(target, ports) - Safe default scripts

Stealth and Evasion Tools:
10. nmap_stealth_scan(target, ports) - Avoid detection (requires sudo)
11. nmap_timing_scan(target, timing, ports) - Control scan speed (requires sudo)
12. nmap_top_ports(target, top_ports) - Scan common ports (requires sudo)

Custom Tool:
13. nmap_custom_scan(target, options) - Custom Nmap command (auto-detects sudo need)

Common port specifications:
- "22,80,443" - Specific ports
- "1-1000" - Port range
- "1-65535" - All ports (use carefully!)

Timing templates:
- T0 (Paranoid) - Very slow, stealthy
- T1 (Sneaky) - Slow, less likely to be detected
- T2 (Polite) - Slows down to avoid network congestion
- T3 (Normal) - Default timing
- T4 (Aggressive) - Faster scan
- T5 (Insane) - Very fast, may miss results

Popular NSE scripts:
- "http-enum" - Enumerate web directories
- "smb-enum-shares" - SMB share enumeration
- "dns-brute" - DNS subdomain bruteforcing
- "ssl-cert" - SSL certificate information

Analyze results for:
- Open ports and services
- Service versions and potential vulnerabilities
- Operating system information
- Security misconfigurations
- Attack surface assessment

Remember: Only scan systems you own or have permission to test!
"""

# Main function
if __name__ == "__main__":
    # Check if Nmap is installed
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: Nmap not found", file=sys.stderr)
        print("   Install with: sudo apt install nmap (Linux) or brew install nmap (macOS)", file=sys.stderr)
        sys.exit(1)
    
    print(" Nmap MCP Server running...", file=sys.stderr)
    print("Remember: Only scan systems you own or have permission to test!", file=sys.stderr)
    
    # Check sudo configuration for privileged scans
    if os.geteuid() != 0:
        try:
            sudo_check = subprocess.run(
                ["sudo", "-n", "nmap", "--version"], 
                capture_output=True, 
                timeout=5
            )
            if sudo_check.returncode == 0:
                print("✓ Sudo access configured for privileged scans", file=sys.stderr)
            else:
                print(" Sudo access not configured. Some scans may fail.", file=sys.stderr)
                print(" Configure with: sudo visudo", file=sys.stderr)
                print(" Add line: your_username ALL=(ALL) NOPASSWD: /usr/bin/nmap", file=sys.stderr)
        except:
            print("Cannot verify sudo access", file=sys.stderr)
    else:
        print(" Running as root - all scan types available", file=sys.stderr)
    
    mcp.run(transport="stdio")
