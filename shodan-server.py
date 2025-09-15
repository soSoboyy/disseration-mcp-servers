import json
import sys
import asyncio
import os
from mcp.server.fastmcp import FastMCP
import shodan
from datetime import datetime  # Fixed import

# Initialize FastMCP server
mcp = FastMCP("shodan-server")

# Get Shodan API key from environment variable
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

def get_shodan_client():
    """Get Shodan API client with proper error handling."""
    if not SHODAN_API_KEY:
        raise ValueError("SHODAN_API_KEY environment variable not set")
    return shodan.Shodan(SHODAN_API_KEY)

#  Shodan intelligence search
@mcp.tool()
async def shodan_host_intelligence(ip_address: str):
    """
    Gather comprehensive intelligence on a specific host
    
    Args:
        ip_address: Target IP address to investigate
    """
    try:
        api = get_shodan_client()
        
        # Validate IP address
        import ipaddress
        ipaddress.ip_address(ip_address)
        
        host_data = api.host(ip_address)
        
        intelligence = {
            "target_ip": ip_address,
            "basic_info": {
                "country": host_data.get("country_name"),
                "country_code": host_data.get("country_code"),
                "city": host_data.get("city"),
                "region": host_data.get("region_code"),
                "postal_code": host_data.get("postal_code"),
                "latitude": host_data.get("latitude"),
                "longitude": host_data.get("longitude"),
                "organization": host_data.get("org"),
                "isp": host_data.get("isp"),
                "asn": host_data.get("asn"),
                "last_update": host_data.get("last_update")
            },
            "network_info": {
                "hostnames": host_data.get("hostnames", []),
                "domains": host_data.get("domains", []),
                "ports": sorted(host_data.get("ports", [])),
                "tags": host_data.get("tags", [])
            },
            "security_info": {
                "vulnerabilities": list(host_data.get("vulns", [])),
                "total_vulns": len(host_data.get("vulns", [])),
            },
            "services": [],
            "timestamp": datetime.now().isoformat() 
        }
        
        # Process service data
        for service in host_data.get("data", []):
            service_info = {
                "port": service.get("port"),
                "protocol": service.get("transport"),
                "service": service.get("product", "unknown"),
                "version": service.get("version"),
                "banner": service.get("data", "")[:500].strip(),
                "timestamp": service.get("timestamp"),
            }
            intelligence["services"].append(service_info)
        
        return json.dumps(intelligence, indent=2)
        
    except shodan.APIError as e:
        return json.dumps({"error": f"Shodan API Error: {e}"})
    except ValueError as e:
        return json.dumps({"error": f"Invalid IP address format: {e}"})
    except Exception as e:
        return json.dumps({"error": f"Unexpected error: {e}"})

@mcp.tool()
async def shodan_search_devices(query: str, limit: int = 50):
    """
    Search for devices and services using Shodan queries
    
    Args:
        query: Search query (e.g., "apache", "port:22", "country:US webcam")
        limit: Maximum results to return (max 100)
    """
    try:
        api = get_shodan_client()
        limit = min(max(1, limit), 100)  # Ensure limit is between 1-100
        
        results = api.search(query, limit=limit)
        
        devices = []
        for i, match in enumerate(results.get("matches", [])):
            if i >= limit:
                break
            
            device = {
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "protocol": match.get("transport"),
                "timestamp": match.get("timestamp"),
                "location": {
                    "country": match.get("location", {}).get("country_name"),
                    "city": match.get("location", {}).get("city"),
                    "latitude": match.get("location", {}).get("latitude"),
                    "longitude": match.get("location", {}).get("longitude")
                },
                "organization": match.get("org"),
                "isp": match.get("isp"),
                "domains": match.get("domains", []),
                "hostnames": match.get("hostnames", []),
                "service": {
                    "product": match.get("product"),
                    "version": match.get("version"),
                    "banner": match.get("data", "")[:200].strip()
                }
            }
            devices.append(device)
        
        response = {
            "query": query,
            "total_results": results.get("total", 0),
            "returned_results": len(devices),
            "devices": devices,
            "facets": results.get("facets", {}),
            "timestamp": datetime.now().isoformat()  # Fixed
        }
        
        return json.dumps(response, indent=2)
        
    except shodan.APIError as e:
        return json.dumps({"error": f"Shodan API Error: {e}"})
    except ValueError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Unexpected error: {e}"})

@mcp.tool()
async def shodan_vulnerability_search(cve_id: str, limit: int = 20):
    """
    Search for devices affected by specific CVE
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
        limit: Maximum results to return
    """
    try:
        query = f"vuln:{cve_id}"
        api = get_shodan_client()
        limit = min(max(1, limit), 100)
        
        results = api.search(query, limit=limit)
        
        devices = []
        for i, match in enumerate(results.get("matches", [])):
            if i >= limit:
                break
            
            device = {
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "protocol": match.get("transport"),
                "location": {
                    "country": match.get("location", {}).get("country_name"),
                    "city": match.get("location", {}).get("city")
                },
                "organization": match.get("org"),
                "service": {
                    "product": match.get("product"),
                    "version": match.get("version"),
                    "banner": match.get("data", "")[:200].strip()
                }
            }
            devices.append(device)
        
        response = {
            "cve_id": cve_id,
            "query": query,
            "total_results": results.get("total", 0),
            "returned_results": len(devices),
            "vulnerable_devices": devices,
            "timestamp": datetime.now().isoformat()  # Fixed
        }
        
        return json.dumps(response, indent=2)
        
    except shodan.APIError as e:
        return json.dumps({"error": f"Shodan API Error: {e}"})
    except ValueError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Unexpected error: {e}"})

@mcp.tool()
async def shodan_port_intelligence(port: int, limit: int = 50):
    """
    Gather intelligence on devices running services on specific port
    
    Args:
        port: Port number to investigate
        limit: Maximum results to return
    """
    try:
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535")
            
        query = f"port:{port}"
        api = get_shodan_client()
        limit = min(max(1, limit), 100)
        
        results = api.search(query, limit=limit, facets="country,product,org")
        
        devices = []
        for i, match in enumerate(results.get("matches", [])):
            if i >= limit:
                break
            
            device = {
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "protocol": match.get("transport"),
                "location": {
                    "country": match.get("location", {}).get("country_name"),
                    "city": match.get("location", {}).get("city")
                },
                "organization": match.get("org"),
                "service": {
                    "product": match.get("product"),
                    "version": match.get("version"),
                    "banner": match.get("data", "")[:200].strip()
                }
            }
            devices.append(device)
        
        response = {
            "port_analyzed": port,
            "query": query,
            "total_results": results.get("total", 0),
            "returned_results": len(devices),
            "devices": devices,
            "facets": results.get("facets", {}),
            "timestamp": datetime.now().isoformat()  # Fixed
        }
        
        return json.dumps(response, indent=2)
        
    except shodan.APIError as e:
        return json.dumps({"error": f"Shodan API Error: {e}"})
    except ValueError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Unexpected error: {e}"})

@mcp.tool()
async def shodan_organization_search(org_name: str, limit: int = 30):
    """
    Search for devices belonging to specific organization
    
    Args:
        org_name: Organization name or ASN
        limit: Maximum results to return
    """
    try:
        query = f'org:"{org_name}"'
        api = get_shodan_client()
        limit = min(max(1, limit), 100)
        
        results = api.search(query, limit=limit, facets="port,country")
        
        devices = []
        for i, match in enumerate(results.get("matches", [])):
            if i >= limit:
                break
            
            device = {
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "protocol": match.get("transport"),
                "location": {
                    "country": match.get("location", {}).get("country_name"),
                    "city": match.get("location", {}).get("city")
                },
                "organization": match.get("org"),
                "service": {
                    "product": match.get("product"),
                    "version": match.get("version"),
                    "banner": match.get("data", "")[:200].strip()
                }
            }
            devices.append(device)
        
        response = {
            "organization": org_name,
            "query": query,
            "total_results": results.get("total", 0),
            "returned_results": len(devices),
            "devices": devices,
            "facets": results.get("facets", {}),
            "timestamp": datetime.now().isoformat()  # Fixed
        }
        
        return json.dumps(response, indent=2)
        
    except shodan.APIError as e:
        return json.dumps({"error": f"Shodan API Error: {e}"})
    except ValueError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Unexpected error: {e}"})

@mcp.tool()
async def shodan_technology_search(technology: str, limit: int = 40):
    """
    Search for devices running specific technology/software
    
    Args:
        technology: Technology name (e.g., "nginx", "apache", "ssh")
        limit: Maximum results to return
    """
    try:
        api = get_shodan_client()
        limit = min(max(1, limit), 100)
        
        results = api.search(technology, limit=limit, facets="version,country")
        
        devices = []
        for i, match in enumerate(results.get("matches", [])):
            if i >= limit:
                break
            
            device = {
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "protocol": match.get("transport"),
                "location": {
                    "country": match.get("location", {}).get("country_name"),
                    "city": match.get("location", {}).get("city")
                },
                "organization": match.get("org"),
                "service": {
                    "product": match.get("product"),
                    "version": match.get("version"),
                    "banner": match.get("data", "")[:200].strip()
                }
            }
            devices.append(device)
        
        response = {
            "technology": technology,
            "query": technology,
            "total_results": results.get("total", 0),
            "returned_results": len(devices),
            "devices": devices,
            "facets": results.get("facets", {}),
            "timestamp": datetime.now().isoformat()  # Fixed
        }
        
        return json.dumps(response, indent=2)
        
    except shodan.APIError as e:
        return json.dumps({"error": f"Shodan API Error: {e}"})
    except ValueError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Unexpected error: {e}"})

@mcp.tool()
async def shodan_country_analysis(country_code: str, service: str = None, limit: int = 50):
    """
    Analyze internet-facing devices in specific country
    
    Args:
        country_code: Two-letter country code (e.g., "US", "CN", "RU")
        service: Optional service filter (e.g., "ssh", "http")
        limit: Maximum results to return
    """
    try:
        if len(country_code) != 2:
            raise ValueError("Country code must be 2 letters (e.g., 'US', 'GB')")
            
        query = f"country:{country_code.upper()}"
        if service:
            query += f" {service}"
            
        api = get_shodan_client()
        limit = min(max(1, limit), 100)
        
        results = api.search(query, limit=limit, facets="port,org,product")
        
        devices = []
        for i, match in enumerate(results.get("matches", [])):
            if i >= limit:
                break
            
            device = {
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "protocol": match.get("transport"),
                "location": {
                    "country": match.get("location", {}).get("country_name"),
                    "city": match.get("location", {}).get("city")
                },
                "organization": match.get("org"),
                "service": {
                    "product": match.get("product"),
                    "version": match.get("version"),
                    "banner": match.get("data", "")[:200].strip()
                }
            }
            devices.append(device)
        
        response = {
            "country_code": country_code.upper(),
            "service_filter": service,
            "query": query,
            "total_results": results.get("total", 0),
            "returned_results": len(devices),
            "devices": devices,
            "facets": results.get("facets", {}),
            "timestamp": datetime.now().isoformat()  # Fixed
        }
        
        return json.dumps(response, indent=2)
        
    except shodan.APIError as e:
        return json.dumps({"error": f"Shodan API Error: {e}"})
    except ValueError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Unexpected error: {e}"})

@mcp.tool()
async def shodan_get_my_ip():
    """
    Get your public IP address using Shodan
    """
    try:
        api = get_shodan_client()
        ip = api.tools.myip()
        
        return json.dumps({
            "public_ip": ip,
            "timestamp": datetime.now().isoformat()  # Fixed
        }, indent=2)
        
    except shodan.APIError as e:
        return json.dumps({"error": f"Shodan API Error: {e}"})
    except ValueError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Unexpected error: {e}"})

@mcp.tool()
async def shodan_api_status():
    """
    Check Shodan API status and account information
    """
    try:
        api = get_shodan_client()
        info = api.info()
        
        return json.dumps({
            "api_status": "active",
            "plan": info.get('plan', 'Unknown'),
            "query_credits": info.get("query_credits", 0),
            "scan_credits": info.get("scan_credits", 0),
            "monitored_ips": info.get('monitored_ips', 0),
            "telnet": info.get("telnet", False),
            "https": info.get("https", False),
            "unlocked": info.get("unlocked", False),
            "timestamp": datetime.now().isoformat()  # Fixed
        }, indent=2)
        
    except shodan.APIError as e:
        return json.dumps({"error": f"Shodan API Error: {e}"})
    except ValueError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Unexpected error: {e}"})

@mcp.tool()
async def shodan_dns_intelligence(hostname: str):
    """
    Gather DNS intelligence for a hostname
    
    Args:
        hostname: Domain or hostname to investigate
    """
    try:
        api = get_shodan_client()
        dns_info = api.dns.resolve(hostname)
        
        intelligence = {
            "hostname": hostname,
            "ip_addresses": dns_info.get(hostname, []),
            "timestamp": datetime.now().isoformat()  # Fixed
        }
        
        # Get basic info for each IP (limited to avoid quota exhaustion)
        detailed_hosts = []
        for ip in intelligence["ip_addresses"][:3]:  # Limit to 3 IPs
            try:
                host_basic = api.host(ip)
                host_summary = {
                    "ip": ip,
                    "country": host_basic.get("country_name"),
                    "organization": host_basic.get("org"),
                    "ports": sorted(host_basic.get("ports", []))[:10]  # Limit ports shown
                }
                detailed_hosts.append(host_summary)
            except:
                detailed_hosts.append({"ip": ip, "error": "Unable to gather details"})
        
        intelligence["host_details"] = detailed_hosts
        
        return json.dumps(intelligence, indent=2)
        
    except shodan.APIError as e:
        return json.dumps({"error": f"Shodan API Error: {e}"})
    except ValueError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"Unexpected error: {e}"})

#  PROMPT 
@mcp.prompt()
def shodan_analysis_prompt(target: str = "") -> str:
    """
    Guide Claude to perform Shodan reconnaissance and analysis.
    
    Args:
        target: Optional target to focus analysis on
    """
    target_text = f" focusing on: {target}" if target else ""
    
    return f"""
You are a cybersecurity analyst using Shodan for reconnaissance{target_text}.

Available Shodan tools:
1. shodan_search(query, limit) - Search for devices/services
2. shodan_host_info(ip) - Get detailed info about a specific IP
3. shodan_count(query) - Count results without fetching data
4. shodan_account_info() - Check API credits and plan
5. shodan_search_facets(query, facets) - Get statistical breakdowns

Common Shodan search queries:
- "apache" - Find Apache web servers
- "port:22" - Find SSH services
- "country:US" - Limit to US results
- "org:Microsoft" - Find Microsoft-owned IPs
- "product:nginx" - Find Nginx servers
- "vuln:CVE-2021-44228" - Find Log4j vulnerable systems

Analyze the results for:
- Security vulnerabilities
- Exposed services
- Geographic distribution
- Common software versions
- Potential attack vectors

Remember to check your API credits before running large searches!
"""

# Main function
if __name__ == "__main__":
    if not SHODAN_API_KEY:
        print(" Error: SHODAN_API_KEY environment variable not set", file=sys.stderr)
        print(" Set it with: export SHODAN_API_KEY='your_api_key_here'", file=sys.stderr)
        sys.exit(1)
    
    print(" Shodan MCP Server running...", file=sys.stderr)
    print(f" API Key: {'*' * (len(SHODAN_API_KEY) - 2) + SHODAN_API_KEY[-2:]}", file=sys.stderr)
    mcp.run(transport="stdio")
