# Ettercap MCP Server - Fixed Version
import asyncio
import json
import sys
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("etter-server")

# Hardcoded network interface (Interface in Macbook is en0)
INTERFACE = "en0"

# Streaming tool
@mcp.tool()
async def run_ettercap_stream(duration: int = 10):
    """
    Stream Ettercap lines in real time as JSON objects.
    """
    # Fixed: Added -M ARP for ARP poisoning or use unified sniffing
    # Option 1: Unified sniffing (captures all traffic on the interface)
    cmd = ["ettercap", "-T", "-i", INTERFACE, "-w", "/dev/null"]
    
    # Option 2: If you want to see more traffic details, use:
    # cmd = ["ettercap", "-Tq", "-i", INTERFACE, "-M", "unified"]
    
    # Option 3: For ARP poisoning between targets (replace IPs):
    # cmd = ["ettercap", "-T", "-i", INTERFACE, "-M", "arp:remote", "//", "//"]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
    except FileNotFoundError:
        yield json.dumps({"error": "Ettercap not found. Install via brew: brew install ettercap"})
        return
    except PermissionError:
        yield json.dumps({"error": "Permission denied. Run with sudo or enable BPF via ChmodBPF"})
        return

    if process.stdout is None:
        yield json.dumps({"error": "Failed to open stdout pipe for Ettercap."})
        return

    try:
        import time
        start_time = time.time()
        
        # Also capture stderr for initialization messages
        async def read_stderr():
            if process.stderr:
                while True:
                    line = await process.stderr.readline()
                    if not line:
                        break
                    decoded = line.decode(errors="ignore").strip()
                    if decoded:
                        yield json.dumps({"interface": INTERFACE, "type": "stderr", "line": decoded})
        
        # Create tasks for both stdout and stderr
        stderr_task = asyncio.create_task(read_stderr().__anext__())
        
        while True:
            if process.stdout.at_eof():
                break
                
            # Read with timeout to avoid hanging
            try:
                line = await asyncio.wait_for(
                    process.stdout.readline(), 
                    timeout=0.5
                )
            except asyncio.TimeoutError:
                # Check if duration exceeded
                if time.time() - start_time > duration:
                    break
                continue
                
            if line:
                decoded = line.decode(errors="ignore").strip()
                if decoded:
                    # Parse Ettercap output for better structure
                    output = {"interface": INTERFACE, "type": "stdout", "line": decoded}
                    
                    # Check for common Ettercap patterns
                    if "->" in decoded or "<-" in decoded:
                        output["type"] = "traffic"
                    elif "TCP" in decoded or "UDP" in decoded or "ICMP" in decoded:
                        output["type"] = "protocol"
                    elif decoded.startswith("["):
                        output["type"] = "info"
                        
                    yield json.dumps(output)

            if time.time() - start_time > duration:
                break
                
    except Exception as e:
        yield json.dumps({"error": str(e)})
    finally:
        process.terminate()
        await process.wait()
        yield json.dumps({"info": f"Capture finished after {duration} seconds."})

# Batch analysis 
@mcp.tool()
async def run_ettercap_batch(duration: int = 10):
    """
    Run Ettercap and return all captured lines as a JSON array.
    """
    results = []
    async for line_json in run_ettercap_stream(duration):
        obj = json.loads(line_json)
        results.append(obj)
    return results  # Return list directly, not JSON string

# TCP dump tool
@mcp.tool()
async def run_tcpdump(duration: int = 10, filter: str = ""):
    """
    Alternative: Run tcpdump for packet capture.
    Args:
        duration: Capture duration in seconds
        filter: BPF filter (e.g., "tcp port 80", "icmp", "host 192.168.1.1")
    """
    cmd = ["tcpdump", "-i", INTERFACE, "-n", "-l"]
    if filter:
        cmd.extend(filter.split())
    
    results = []
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        import time
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                line = await asyncio.wait_for(
                    process.stdout.readline(),
                    timeout=0.5
                )
                if line:
                    decoded = line.decode(errors="ignore").strip()
                    if decoded:
                        results.append({
                            "timestamp": time.time() - start_time,
                            "packet": decoded
                        })
            except asyncio.TimeoutError:
                continue
                
    except FileNotFoundError:
        return [{"error": "tcpdump not found"}]
    except PermissionError:
        return [{"error": "Permission denied. Run with sudo"}]
    finally:
        if 'process' in locals():
            process.terminate()
            await process.wait()
            
    return results

# Get network info
@mcp.tool()
async def get_network_info():
    """
    Get network interface information.
    """
    import subprocess
    
    info = {}
    
    # Get interface info
    try:
        result = subprocess.run(
            ["ifconfig", INTERFACE],
            capture_output=True,
            text=True
        )
        info["interface"] = result.stdout
    except:
        info["interface"] = "Unable to get interface info"
    
    # Get routing table
    try:
        result = subprocess.run(
            ["netstat", "-rn"],
            capture_output=True,
            text=True
        )
        info["routes"] = result.stdout
    except:
        info["routes"] = "Unable to get routing info"
    
    # Get ARP table
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True
        )
        info["arp"] = result.stdout
    except:
        info["arp"] = "Unable to get ARP table"
        
    return info

# Prompt
@mcp.prompt()
def setup_prompt(capture_time: int = 10) -> str:
    """
    Guide Claude to capture live network traffic using Ettercap.
    """
    return f"""
Your role is a network analyst using Ettercap on interface {INTERFACE}.

Available tools:
1. `run_ettercap_stream(duration)` - Real-time streaming capture
2. `run_ettercap_batch(duration)` - Batch capture returning array
3. `run_tcpdump(duration, filter)` - Alternative using tcpdump
4. `get_network_info()` - Get network interface information

To see network traffic:
- First run `get_network_info()` to understand the network
- Then use ettercap or tcpdump to capture packets
- Analyze any suspicious activity

Note: If Ettercap doesn't show traffic, try tcpdump as an alternative.
Ensure the server is running with sudo privileges.
"""

# ---------------------- MAIN ----------------------
if __name__ == "__main__":
    print(f" Ettercap MCP Server running on {INTERFACE}...", file=sys.stderr)
    print(f" Make sure to run with sudo for packet capture!", file=sys.stderr)
    mcp.run(transport="stdio")
