## MCP Server (recon-server)

As a proof-of-concept, I am going to be building a simple MCP server that performs *active external reconnaissance* against a *domain name*, using tools such as *dig*, *whois*, *reverse-dns-lookup*, *attempt zone transfer*, *enumerate-dns-record* and also analyses *HTTP headers*.
External reconnaissance is a vital phase in red teaming and penetration testing to collect internet-accessible information against a target that can be leveraged for initial access. (*Academic Reference here, please*)

Anthropic provides SDKs for different programming language to build the servers, which provide the same functionality but follows the idioms and best practices of their language. Our choice is [Python](https://github.com/modelcontextprotocol/python-sdk) for its simplicity.

### How MCP is run :
- An **MCP server** is just a program that uses the MCP protocol (JSON-RPC over stdio).
- When I tell Claude and VS Code how to use the server, it looks up how to run it, defined in the configuration file:
![[main/Screenshot 2025-08-20 at 13.27.33.png]]
**Claude doesn’t directly run the server** —> instead, it calls `uv run`


## Implementation diagram:

![[main/recon-server-Page-2.drawio.png]]

## Libraries and Implementation:

#### The Anthropic guide suggests [uv](https://docs.astral.sh/uv/) as a package manager instead of pip when working with Python. UV is an extremely fast Python package and project manager, written in Rust. 
`uv` is the package/runtime manager that Claude (inside VS Code) uses to run recon-server in a reproducible environment, used by the **MCP ecosystem** to manage servers, dependencies, and runtime environments.

| UV  | When the MCP server is run from Claude/VS Code:<br><br>1. **VS Code / Claude calls `uv run recon-server.py`**  <br>    → This ensures the right Python environment is set up.<br>    <br>2. **`uv` checks dependencies** (from `pyproject.toml` or `requirements.txt`).  <br>    → If needed, it installs them in an isolated virtual environment.<br>    <br>3. **`uv` launches the MCP server** with all dependencies available.  <br>    → So the server runs cleanly, regardless of what Python packages are installed globally on my system. |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

#### Implementation on VS Code: 

| Create a new project folder called *dissertation-mcp-servers* that will contain all the servers used in this project. | `mkdir disseration-mcp-servers` |                                                        |
| --------------------------------------------------------------------------------------------------------------------- | ------------------------------- | ------------------------------------------------------ |
| Enter projectory directory                                                                                            | `cd disseration-mcp-servers`    |                                                        |
| Initialize UV                                                                                                         | `uv init`                       |                                                        |
| Create virtual environment                                                                                            | `uv venv`                       |                                                        |
| Activate virtual environment only for this directory                                                                  | `source .venv/bin/activate`     |                                                        |
| Add MCP to the project dependencies:                                                                                  | `uv add "mcp[cli]"`             |                                                        |
| Running MCP development tools to check it's working                                                                   | `uv run mcp`                    | ![[attachments/Screenshot 2025-08-15 at 17.55.55.png]] |
| Create our server file                                                                                                | `touch recon-server.py`         |                                                        |

#### Libraries:

| httpx      | A Python library that serves as a fully featured HTTP client, offering both synchronous and asynchronous APIs for making HTTP requests                                                                                                                                                                                                 |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FastMCP    | A Python library that handles all the complex protocol details and server management. The FastMCP server is the core interface to the MCP protocol. It handles connection management, protocol compliance, and message routing. In our case, it provides access to the decorators, which will allow us to create the server structure. | FastMCP provides decorators to define:<br>- Resources: exposing data to the AI model, such as files, API responses or databases.<br>- Tools: letting the AI model take actions, such as computations of HTTP requests or command execution.<br>- Prompts: templates that allow you to shape the AI’s reasoning and provide context<br>- Images: imaging handling that can be used as the result of tools or resources<br>- Context: provides progress reporting, logging, resource access and metadata requests. |
| subprocess | The module allows for the spawning of new processes, connecting to their input/output/error pipes, and obtaining their return codes.                                                                                                                                                                                                   |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| os         | The module provides a portable way of using operating system-dependent functionality, such as interacting with the file system and other functions.                                                                                                                                                                                    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

We have two (2) main decorators to consider:

1. **_mcp.prompt()_**
2. **_mcp.tool()_**

| Prompt | Prompts  give the AI model context for the actions we want it to perform. This is like prompt engineering, we define:<br>- What rules or context do we want to implement into the AI model for this agent?<br>- We can also define parameters that we will supply when using the server for the tools.                                                                                                                                                                                                                                                        |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tool   | Commands we’ll need for the tasks:<br><br>- run _dig_ to query DNS records<br>- run _whois_ on each IP address to show who it belongs to<br>- run _dnsrecon_ to discover subdomains<br><br>The tool designates the function as a tool that can be used by the AI model. Next, we’ll create the docs string to describe the tool for both the human user and for the AI model to understand its use and any parameters required. Then we add the code for the actual function we want the model to perform. Here we are giving it access to run an OS command. |
### Transport Mode:
The STDIO transport is the default transport mechanism in MCP Framework. It uses standard input/output streams for communication between the client and server. Check specs [here](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) This is ideal for:
- CLI tools and applications
- Local process communication
- Development and testing scenarios
#### *It implements JSON-RPC 2.0 protocol for message formatting* 
The MCP server uses **`stdio` transport**, so it does **not** open a network socket *(no TCP port )*
Instead, all communication happens through **standard input/standard output pipes** between VS Code (client) and the *recon-server.py* (child process).
That means the JSON “packages” (requests/responses) are just text being written to **stdout** and read from **stdin** of the process.

# Code Explanation:
## Core Infrastructure

### Command Execution Function:
```python
def execute_os_command(command: str) -> str:
```

This is the foundation of the entire toolkit:

- Uses `subprocess.run()` to execute shell commands
- `shell=True`: Allows complex shell commands with pipes and operators
- `check=True`: Raises exception on non-zero exit codes
- `stdout=subprocess.PIPE`: Captures standard output
- `stderr=subprocess.PIPE`: Captures error output
- `text=True`: Returns strings instead of bytes
- **Error Handling**: Returns stderr on failure instead of crashing

## AI Orchestration

### Setup Prompt:
```python
@mcp.prompt()
def setup_prompt(domainname: str) -> str:
```

This creates an AI prompt that:

- **Role Definition**: Sets up the AI as a penetration tester
- **Objective**: Defines the reconnaissance mission
- **Instructions**: Tells the AI to use tools iteratively and report findings
- **Dynamic**: Inserts the target domain name into the prompt

This is essentially giving the AI a "mission briefing" for conducting reconnaissance.
## DNS Reconnaissance Tools:

### Basic DNS Lookup
```python
@mcp.tool()
async def run_dig_lookup(domainname: str) -> str:
```

**Purpose**: Get basic DNS information about a domain

- **Command**: `dig {domainname}`
- **Returns**: All default DNS records (A, NS, etc.)
- **Use Case**: First step to understand the domain's DNS structure
### Reverse DNS Lookup
```python
async def run_reverse_dns_lookup(ip_address: str) -> str:
```

**Purpose**: Find hostnames associated with IP addresses

- **Validation**: Uses `ipaddress.ip_address()` to prevent injection
- **Command**: `dig -x {ip_address}`
- **Process**: Converts IP to PTR query format automatically
- **Use Case**: Identify what services/domains are hosted on discovered IPs

### WHOIS Lookup:
```python
async def run_whois_lookup(ipaddress: str) -> str:
```

**Purpose**: Find ownership information for IP addresses

- **Command**: `whois {ipaddress}`
- **Returns**: Organization, contact details, IP ranges
- **Use Case**: Understand who owns the infrastructure

### Zone Transfer Attempt:
```python
async def attempt_zone_transfer(domainname: str) -> str:
```

**Purpose**: Try to get complete DNS zone data

- **Command**: `dig axfr {domainname}`
- **What it does**: Attempts to download entire DNS database
- **Why dangerous**: If successful, reveals ALL subdomains and records
- **Reality**: Usually fails due to security restrictions

### Subdomain Enumeration:
```python
async def enumerate_subdomains(domainname: str) -> str:
```

**Purpose**: Discover subdomains using standard techniques

- **Tool**: Uses `dnsrecon` (specialized DNS reconnaissance tool)
- **Command**: `dnsrecon -d {domainname} -t std`
- **Method**: Tries common subdomain names and DNS walking techniques

### DNS Records Enumeration:
```python
async def enumerate_dns_records(domainname: str) -> str:
```

**Purpose**: Systematically check all DNS record types

- **Record Types**: A, AAAA, MX, NS, SOA, TXT, SRV
- **Process**: Runs separate `dig` command for each record type
- **Output**: Consolidates all results into single report

**What each record reveals**:

- **A/AAAA**: IPv4/IPv6 addresses
- **MX**: Mail servers
- **NS**: Name servers
- **SOA**: Zone authority info
- **TXT**: Various configurations (SPF, DKIM, etc.)
- **SRV**: Service locations

## Web Application Analysis

### HTTP Headers Analysis
```python
async def analyze_http_headers(domainname: str) -> str:
```

**Purpose**: Examine web server configuration and security headers

- **Tool**: Uses `httpx` (modern HTTP client)
- **Protocol**: Tries HTTPS first
- **Information Gathered**:
    - Server software and versions
    - Security headers (CSP, HSTS, etc.)
    - Caching policies
    - Technology stack indicators
## Overall Workflow

The toolkit follows this reconnaissance methodology:

1. **Initial Discovery**: Basic DNS lookup to find primary IPs
2. **Infrastructure Mapping**: Reverse DNS and WHOIS on discovered IPs
3. **Expansion**: Zone transfer attempt for quick wins
4. **Comprehensive Analysis**: All DNS record types
5. **Service Analysis**: HTTP headers for web services

*This server essentially automates the initial "information gathering" phase of a penetration test, systematically discovering and analysing a target domain's digital footprint.*
