"""
Metasploit MCP Server
A Model Context Protocol server that exposes Metasploit Framework tools
for authorized security research and penetration testing.
"""

import asyncio
import subprocess
import json
import tempfile
import os
from typing import Dict, List, Any, Optional
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP("meta-server")

class MetasploitError(Exception):
    """Custom exception for Metasploit-related errors"""
    pass

def get_binary_path(binary_name: str) -> str:
    """Get the full path to a Metasploit binary"""
    return f"/opt/metasploit-framework/bin/{binary_name}"

def run_command(command: List[str], timeout: int = 30, cwd: str = None) -> Dict[str, Any]:
    """
    Execute a system command and return results
    
    Args:
        command: Command as list of strings
        timeout: Command timeout in seconds
        cwd: Working directory for the command
        
    Returns:
        Dict containing stdout, stderr, and return code
    """
    try:
        # Set up environment for Metasploit
        env = os.environ.copy()
        
        # Add Metasploit paths to environment
        msf_bin = '/opt/metasploit-framework/bin'
        msf_embedded_bin = '/opt/metasploit-framework/embedded/bin'
        current_path = env.get('PATH', '')
        
        # Prepend Metasploit paths
        env['PATH'] = f'{msf_bin}:{msf_embedded_bin}:{current_path}'
        
        # Set Ruby/Gem environment for embedded installation
        env['GEM_HOME'] = '/opt/metasploit-framework/embedded/lib/ruby/gems/3.0.0'
        env['GEM_PATH'] = '/opt/metasploit-framework/embedded/lib/ruby/gems/3.0.0'
        
        # For shell scripts, we need to run them from their directory or with proper working directory
        if cwd is None and any('metasploit-framework/bin' in str(cmd) for cmd in command):
            cwd = '/opt/metasploit-framework'
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
            cwd=cwd
        )
        
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds",
            "returncode": -1,
            "success": False
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "success": False
        }

@mcp.tool()
def search_exploits(search_term: str, platform: str = "", type_filter: str = "") -> str:
    """
    Search for Metasploit exploits and modules
    
    Args:
        search_term: Term to search for (e.g., "windows", "apache", "cve-2021-44228")
        platform: Optional platform filter (windows, linux, android, etc.)
        type_filter: Optional type filter (exploit, auxiliary, payload, etc.)
    
    Returns:
        Search results from Metasploit database
    """
    try:
        # Build msfconsole search command
        search_cmd = f"search {search_term}"
        if platform:
            search_cmd += f" platform:{platform}"
        if type_filter:
            search_cmd += f" type:{type_filter}"
            
        # Execute search via msfconsole
        command = [get_binary_path("msfconsole"), "-q", "-x", f"{search_cmd}; exit"]
        result = run_command(command, timeout=60)
        
        if not result["success"]:
            raise MetasploitError(f"Search failed: {result['stderr']}")
            
        return result["stdout"]
        
    except Exception as e:
        return f"Error searching exploits: {str(e)}"

@mcp.tool()
def get_module_info(module_path: str) -> str:
    """
    Get detailed information about a specific Metasploit module
    
    Args:
        module_path: Full path to the module (e.g., "exploit/windows/smb/ms17_010_eternalblue")
    
    Returns:
        Detailed module information including options, targets, and description
    """
    try:
        command = [get_binary_path("msfconsole"), "-q", "-x", f"use {module_path}; info; exit"]
        result = run_command(command, timeout=30)
        
        if not result["success"]:
            raise MetasploitError(f"Failed to get module info: {result['stderr']}")
            
        return result["stdout"]
        
    except Exception as e:
        return f"Error getting module info: {str(e)}"

@mcp.tool()
def generate_payload(
    payload: str,
    lhost: str,
    lport: int,
    format_type: str = "exe",
    arch: str = "x86",
    platform_target: str = "windows",
    encoder: str = "",
    iterations: int = 1
) -> str:
    """
    Generate a payload using msfvenom
    
    Args:
        payload: Payload type (e.g., "windows/meterpreter/reverse_tcp")
        lhost: Local host IP address
        lport: Local port number
        format_type: Output format (exe, elf, raw, python, etc.)
        arch: Target architecture (x86, x64)
        platform_target: Target platform (windows, linux, android, etc.)
        encoder: Optional encoder (e.g., "x86/shikata_ga_nai")
        iterations: Number of encoding iterations
    
    Returns:
        Path to generated payload file and generation details
    """
    try:
        # Create temporary file for payload
        with tempfile.NamedTemporaryFile(
            suffix=f".{format_type}", 
            delete=False, 
            dir="/tmp"
        ) as temp_file:
            output_file = temp_file.name
        
        # Build msfvenom command with full path
        command = [
            get_binary_path("msfvenom"),
            "-p", payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", format_type,
            "-a", arch,
            "--platform", platform_target,
            "-o", output_file
        ]
        
        if encoder:
            command.extend(["-e", encoder, "-i", str(iterations)])
        
        result = run_command(command, timeout=60)
        
        if not result["success"]:
            # Clean up temp file on failure
            if os.path.exists(output_file):
                os.unlink(output_file)
            raise MetasploitError(f"Payload generation failed: {result['stderr']}")
        
        file_size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
        
        return f"""Payload generated successfully:
File: {output_file}
Size: {file_size} bytes
Payload: {payload}
LHOST: {lhost}
LPORT: {lport}
Format: {format_type}
Architecture: {arch}
Platform: {platform_target}
{f'Encoder: {encoder} ({iterations} iterations)' if encoder else 'No encoding'}

Generation output:
{result['stdout']}"""
        
    except Exception as e:
        return f"Error generating payload: {str(e)}"

@mcp.tool()
def list_payloads(platform_filter: str = "", arch_filter: str = "") -> str:
    """
    List available payloads in Metasploit
    
    Args:
        platform_filter: Filter by platform (windows, linux, android, etc.)
        arch_filter: Filter by architecture (x86, x64, mips, etc.)
    
    Returns:
        List of available payloads
    """
    try:
        command = [get_binary_path("msfvenom"), "--list", "payloads"]
        
        # Add filters if specified
        if platform_filter:
            command.extend(["--platform", platform_filter])
        if arch_filter:
            command.extend(["--arch", arch_filter])
            
        result = run_command(command, timeout=30)
        
        if not result["success"]:
            raise MetasploitError(f"Failed to list payloads: {result['stderr']}")
            
        return result["stdout"]
        
    except Exception as e:
        return f"Error listing payloads: {str(e)}"

@mcp.tool()
def list_encoders(arch_filter: str = "") -> str:
    """
    List available encoders in Metasploit
    
    Args:
        arch_filter: Filter by architecture (x86, x64, etc.)
    
    Returns:
        List of available encoders
    """
    try:
        command = [get_binary_path("msfvenom"), "--list", "encoders"]
        
        if arch_filter:
            command.extend(["--arch", arch_filter])
            
        result = run_command(command, timeout=30)
        
        if not result["success"]:
            raise MetasploitError(f"Failed to list encoders: {result['stderr']}")
            
        return result["stdout"]
        
    except Exception as e:
        return f"Error listing encoders: {str(e)}"

@mcp.tool()
def run_auxiliary_module(
    module_path: str,
    options: Dict[str, str] = None,
    timeout_seconds: int = 120
) -> str:
    """
    Run an auxiliary module (scanner, brute forcer, etc.)
    
    Args:
        module_path: Path to auxiliary module (e.g., "auxiliary/scanner/portscan/tcp")
        options: Dictionary of module options (e.g., {"RHOSTS": "192.168.1.1", "PORTS": "22,80,443"})
        timeout_seconds: Timeout for module execution
    
    Returns:
        Module execution results
    """
    try:
        if options is None:
            options = {}
            
        # Build msfconsole command
        commands = [f"use {module_path}"]
        
        # Set options
        for key, value in options.items():
            commands.append(f"set {key} {value}")
            
        commands.extend(["run", "exit"])
        command_string = "; ".join(commands)
        
        command = [get_binary_path("msfconsole"), "-q", "-x", command_string]
        result = run_command(command, timeout=timeout_seconds)
        
        if not result["success"]:
            raise MetasploitError(f"Auxiliary module execution failed: {result['stderr']}")
            
        return result["stdout"]
        
    except Exception as e:
        return f"Error running auxiliary module: {str(e)}"

@mcp.tool()
def check_msf_status() -> str:
    """
    Check Metasploit Framework installation and database status
    
    Returns:
        Status information about Metasploit installation
    """
    try:
        # Check msfconsole version
        version_result = run_command([get_binary_path("msfconsole"), "--version"], timeout=10)
        
        # Check database status
        db_status = run_command([get_binary_path("msfconsole"), "-q", "-x", "db_status; exit"], timeout=15)
        
        # Check msfvenom with full path
        msfvenom_result = run_command([get_binary_path("msfvenom"), "--help"], timeout=5)
        
        status_info = f"""Metasploit Framework Status:

Version Check:
{version_result['stdout'] if version_result['success'] else f"Error: {version_result['stderr']}"}

Database Status:
{db_status['stdout'] if db_status['success'] else f"Error: {db_status['stderr']}"}

msfconsole available: {version_result['success']}
msfvenom available: {msfvenom_result['success']}
"""
        
        return status_info
        
    except Exception as e:
        return f"Error checking Metasploit status: {str(e)}"

@mcp.tool()
def get_exploit_targets(module_path: str) -> str:
    """
    Get available targets for an exploit module
    
    Args:
        module_path: Path to exploit module
    
    Returns:
        List of available targets
    """
    try:
        command = [get_binary_path("msfconsole"), "-q", "-x", f"use {module_path}; show targets; exit"]
        result = run_command(command, timeout=30)
        
        if not result["success"]:
            raise MetasploitError(f"Failed to get targets: {result['stderr']}")
            
        return result["stdout"]
        
    except Exception as e:
        return f"Error getting exploit targets: {str(e)}"

if __name__ == "__main__":
    import uvicorn
    
    # Run the MCP server
    print("Starting Meta MCP Server...")
    print("Available tools:")
    print("- search_exploits: Search for exploits and modules")
    print("- get_module_info: Get detailed module information")
    print("- generate_payload: Generate payloads with msfvenom")
    print("- list_payloads: List available payloads")
    print("- list_encoders: List available encoders")
    print("- run_auxiliary_module: Execute auxiliary modules")
    print("- check_msf_status: Check Meta installation status")
    print("- get_exploit_targets: Get available targets for exploits")
    
    mcp.run()