from mcp.server.fastmcp import FastMCP
import subprocess
import httpx
import os

# Initialise FastMCP server
mcp = FastMCP("external-recon")

# Function to execute OS commands:

def execute_os_command(command: str) -> str:
    """
    Executes an OS command and returns its output as a string.
    
    :param command: command string to execute
    :return: output from command execution
    """
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return e.stderr.strip()

# Prompt to initialise the AI model to the task:

@mcp.prompt()
def setup_prompt(domainname: str) -> str:
    """
    setup external reconnaissance by domain name

    :param domainname: domain name to target
    :type domainname: str
    :return:
    :rtype: str
    """

    return f"""
Your role is a highly skilled penetration tester specialising in network reconnaissance. Your primary objective is to enumerate the {domainname} domain and report on discovered IP addresses, subdomains,and HTTP headers.

Observer carefully the output of the tools in inform next steps:

Your objective is to perform reconnaissance against the organisation's domain name, identify IP addresses, discover subdomains, report on the ownership of the domains, and assess the HTTP security measures. When you find new IP addresses or subdomains I want you to repeat enumeration steps.

First, reflect on the objective, then execute any tools you have access to on the target domain {domainname} and report your findings on all IP addresses and subdomains discovered.
"""

#Implementing tools:

# Run dig to query DNS A records #

@mcp.tool()
async def run_dig_lookup(domainname: str) -> str:
    """
    perform simple lookup of any A records for the domain.
    :param domainname: domain to query
    :type domainname: str
    :return: DNS query results
    """
    try:
        command = f"dig {domainname}"
        result = execute_os_command(command)
        
        if not result:
            return f"No DNS records found for {domainname}"
            
        return result
    except Exception as e:
        return f"Error performing DNS lookup: {str(e)}"

# Do a reverse lookup from IP to domain name #
@mcp.tool()
async def run_reverse_dns_lookup(ip_address: str) -> str:
    """
    Perform detailed reverse DNS lookup showing full dig output.
    :param ip_address: IP address to perform reverse lookup on
    :type ip_address: str
    :return: Detailed reverse DNS lookup results
    """
    try:
        # Validate IP address format
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            return f"Invalid IP address format: {ip_address}"
        
        # Use dig with -x flag for reverse lookup (full output)
        command = f"dig -x {ip_address}"
        result = execute_os_command(command)
        
        if not result:
            return f"No reverse DNS records found for {ip_address}"
            
        return result
        
    except Exception as e:
        return f"Error performing detailed reverse DNS lookup: {str(e)}"

# Run whois on each IP address to show who it belongs to #
@mcp.tool()
async def run_whois_lookup(ipaddress: str) -> str:
    """
    perform query of domain ownership details.
    :param ipaddress: ip to query
    :type ipaddress: str
    :return: whois query results
    """
    try:
        command = f"whois {ipaddress}"
        return execute_os_command(command)
    except Exception as e:
        return f"Error performing whois lookup: {str(e)}"

# Perform DNS zone transfer attempt #
@mcp.tool()
async def attempt_zone_transfer(domainname: str) -> str:
    """
    Attempt to perform a DNS zone transfer (AXFR) to enumerate all DNS records.
    :param domainname: domain to attempt zone transfer against
    :type domainname: str
    :return: zone transfer results
    """
    try:
        command = f"dig axfr {domainname}"
        return execute_os_command(command)
    except Exception as e:
        return f"Error performing zone transfer: {str(e)}"

# Perform DNS record enumeration #
@mcp.tool()
async def enumerate_dns_records(domainname: str) -> str:
    """
    Enumerate various DNS record types for the target domain.
    :param domainname: domain to enumerate DNS records for
    :type domainname: str
    :return: DNS record enumeration results
    """
    record_types = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'SRV']
    results = []
    for record_type in record_types:
        command = f"dig {domainname} {record_type}"
        results.append(execute_os_command(command))
    return "\n\n".join(results)


# Perform HTTP headers analysis #
@mcp.tool()
async def analyze_http_headers(domainname: str) -> str:
    """
    Analyze HTTP headers of the target domain.
    :param domainname: domain to analyze HTTP headers for
    :type domainname: str
    :return: HTTP headers analysis results
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"https://{domainname}")
            headers = response.headers
            return "\n".join([f"{k}: {v}" for k, v in headers.items()])
        except Exception as e:
            return f"Error analyzing HTTP headers: {str(e)}"


if __name__ == "__main__":
    # Initialise and run the server
    print("Server is running..")
    mcp.run(transport='stdio')
    