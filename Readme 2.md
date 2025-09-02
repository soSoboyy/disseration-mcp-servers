## MCP Servers (Shodan & Nmap)
#reconnaissance

**Nmap (Network Mapper):**

- **Type**: Active reconnaissance tool
- **Scope**: Direct network interaction with target systems
- **Method**: Sends packets directly to targets and analyses responses
- **Speed**: Real-time scanning, results depend on network latency
- **Detection**: Can be detected by IDS/IPS systems
- **Permission**: Requires explicit authorisation to scan targets

**Shodan:**

- **Type**: Passive reconnaissance tool
- **Scope**: Internet-wide search engine for connected devices
- **Method**: Queries the pre-indexed database of internet scans
- **Speed**: Instant results from cached data
- **Detection**: Completely passive, undetectable by targets
- **Permission**: No direct interaction with targets

| Aspect                   | Nmap                     | Shodan                   |
| ------------------------ | ------------------------ | ------------------------ |
| **Reconnaissance Type**  | Active                   | Passive                  |
| **Data Source**          | Real-time scanning       | Pre-indexed database     |
| **Update Frequency**     | Immediate                | Monthly crawls           |
| **Geographic Scope**     | Local/targeted networks  | Global internet          |
| **Detection Risk**       | High (detectable)        | None (passive)           |
| **Legal Considerations** | Requires authorization   | Public data              |
| **Depth of Information** | Very detailed, current   | Broad, historical        |
| **Speed**                | Slower (active scanning) | Instant (database query) |
| **Network Impact**       | Generates traffic        | No network impact        |
| **Cost**                 | Free                     | API credits required     |
### Reconnaissance Workflow:

1. **Initial Passive Recon (Shodan)**:
    - Search organization assets
    - Identify exposed services
    - Discover IP ranges and domains
2. **Active Verification (Nmap)**:
    - Verify Shodan findings
    - Detailed service enumeration
    - Vulnerability scanning
3. **Deep Dive Analysis**:
    - Combine both data sources
    - Correlate vulnerabilities
    - Create comprehensive report




