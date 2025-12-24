# Network Packet Investigator

**Digital Forensics Tool for Network Traffic Analysis**

---

## Overview

Network Packet Investigator is a Python-based, cross-platform digital forensics tool designed to analyze PCAP files and detect suspicious network activity related to phishing, data exfiltration, and other security threats.

### Key Features

✅ **PCAP File Analysis**
- Load and parse PCAP files
- Support for large files
- Efficient packet extraction

✅ **Comprehensive Network Analysis**
- DNS query analysis
- HTTP request inspection
- TCP session tracking
- Protocol distribution statistics

✅ **Threat Detection**
- Unknown/suspicious domain detection
- Excessive DNS query detection (DNS tunneling)
- Large data transfer identification
- Suspicious IP communication patterns
- Unusual port usage detection
- HTTP POST anomalies
- Phishing indicator detection

✅ **User-Friendly GUI**
- Cross-platform interface using Tkinter
- Multiple analysis tabs
- Interactive charts and graphs
- Real-time progress indicators

✅ **Forensic Reporting**
- **PDF Reports**: Professional reports with charts, case information, and detailed analysis
- **TXT Reports**: Detailed text-based analysis reports
- **CSV Exports**: Data exports for further analysis
- Indicators of Compromise (IOCs)
- Professional forensic documentation

---

## System Requirements

### Supported Operating Systems
- **Windows** 10/11
- **macOS** 10.15 (Catalina) or later
- **Linux** (Ubuntu 20.04+, Debian, Fedora, etc.)

### Prerequisites
- Python 3.8 or higher
- Minimum 4GB RAM (8GB recommended for large PCAP files)
- 500MB free disk space

---

## Installation Instructions

### Windows Installation

1. **Install Python**
   - Download Python from [python.org](https://www.python.org/downloads/)
   - During installation, check "Add Python to PATH"
   - Verify installation:
     ```cmd
     python --version
     ```

2. **Install Dependencies**
   ```cmd
   cd cnc414-project
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Install Npcap (Required for Scapy)**
   - Download from [npcap.com](https://npcap.com/#download)
   - Install with WinPcap compatibility mode enabled

4. **Run the Application**
   ```cmd
   python main.py
   ```

### macOS Installation

1. **Install Python** (if not already installed)
   ```bash
   # Using Homebrew
   brew install python@3.11
   
   # Verify installation
   python3 --version
   ```

2. **Clone or Navigate to Project**
   ```bash
   cd cnc414-project
   ```

3. **Install Dependencies**
   ```bash
   pip3 install -r requirements.txt
   ```

4. **Run the Application**
   ```bash
   python3 main.py
   ```

   **Note:** On macOS, you may need to grant permissions for network access when prompted.

### Linux Installation

#### Ubuntu/Debian

1. **Install Python and Dependencies**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-tk
   ```

2. **Install libpcap**
   ```bash
   sudo apt install libpcap-dev
   ```

3. **Navigate to Project and Install Requirements**
   ```bash
   cd cnc414-project
   pip3 install -r requirements.txt
   ```

4. **Run the Application**
   ```bash
   python3 main.py
   ```

#### Fedora/RHEL/CentOS

1. **Install Python and Dependencies**
   ```bash
   sudo dnf install python3 python3-pip python3-tkinter
   ```

2. **Install libpcap**
   ```bash
   sudo dnf install libpcap-devel
   ```

3. **Navigate to Project and Install Requirements**
   ```bash
   cd cnc414-project
   pip3 install -r requirements.txt
   ```

4. **Run the Application**
   ```bash
   python3 main.py
   ```

---

## Usage Guide

### Quick Start

1. **Launch the Application**
   ```bash
   python main.py
   # or on some systems
   python3 main.py
   ```

2. **Load a PCAP File**
   - Click "Browse" button
   - Select your PCAP file (.pcap or .pcapng)
   - File path will appear in the text field

3. **Start Analysis**
   - Click "Analyze" button
   - Monitor progress bar
   - Wait for analysis to complete

4. **Review Results**
   - Navigate through tabs to view different analyses
   - Check "Security Findings" tab for threats
   - View visualizations in "Charts" tab

5. **Export Reports**
   - Go to File menu
   - Select "Export TXT Report" or "Export CSV Report"
   - Choose save location

### User Interface Guide

#### Overview Tab
- Case information
- High-level statistics
- Executive summary

#### DNS Analysis Tab
- Total DNS queries
- Unique domains queried
- Top queried domains
- Excessive query detection

#### HTTP Analysis Tab
- HTTP request statistics
- Method distribution
- URLs and hosts accessed

#### TCP Sessions Tab
- TCP connection statistics
- Data transfer volumes
- Top connections by traffic

#### Security Findings Tab
- All detected threats
- Severity levels (HIGH, MEDIUM, LOW)
- Detailed descriptions
- Recommendations
- Double-click findings for more details

#### Charts Tab
- Protocol distribution pie chart
- Top DNS queries bar chart
- Findings severity distribution
- HTTP methods distribution

---

## Configuration

### Safe Domains List

Edit `data/safe_domains.txt` to customize which domains are considered trusted:

```bash
# Add your trusted domains
example-corp.com
internal-service.local
```

Domains in this list will not trigger "unknown domain" alerts.

---

## Sample PCAP Files

To test the tool, you can use sample PCAP files from:

- **Wireshark Sample Captures:** https://wiki.wireshark.org/SampleCaptures
- **Malware Traffic Analysis:** https://malware-traffic-analysis.net/
- **PCAP Examples Repository:** https://github.com/kholia/pcap

**For testing purposes, you can create a simple capture:**
```bash
# On Linux/macOS (requires sudo)
sudo tcpdump -i any -w test_capture.pcap -c 1000

# On Windows (using Command Prompt as Administrator)
# Install Wireshark first, then use:
# tshark -i <interface> -w test_capture.pcap -c 1000
```

---

## Forensic Analysis Workflow

### Standard Investigation Process

1. **Evidence Collection**
   - Obtain PCAP file from network tap, IDS, or endpoint
   - Document chain of custody
   - Verify file integrity (hash)

2. **Initial Analysis**
   - Load PCAP into tool
   - Review overview statistics
   - Identify time range of activity

3. **Deep Dive Investigation**
   - Examine DNS queries for unknown domains
   - Review HTTP traffic for suspicious URLs
   - Analyze TCP sessions for large transfers
   - Check security findings

4. **Threat Correlation**
   - Cross-reference detected IOCs with threat intelligence
   - Identify patterns matching known attack techniques
   - Document MITRE ATT&CK tactics if applicable

5. **Report Generation**
   - **Export PDF Report**: Generate professional PDF reports with case information, charts, and comprehensive analysis
   - **Export TXT Report**: Generate detailed text-based analysis reports
   - **Export CSV Data**: Export findings and data for further analysis
   - Document findings and recommendations

6. **Remediation**
   - Block identified malicious IPs/domains
   - Investigate affected systems
   - Implement security controls

---

## Architecture

### Project Structure

```
cnc414-project/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── LICENSE                # License information
│
├── src/                   # Source code modules
│   ├── __init__.py       # Package initialization
│   ├── pcap_parser.py    # PCAP parsing logic
│   ├── analyzer.py       # Network analysis engine
│   ├── detector.py       # Threat detection algorithms
│   ├── reporter.py       # Report generation
│   └── gui.py            # GUI implementation
│
├── data/                  # Configuration data
│   └── safe_domains.txt  # Trusted domains list
│
└── logs/                  # Application logs (created at runtime)
```

### Module Descriptions

**pcap_parser.py**
- Loads PCAP files using Scapy
- Extracts packet information
- Parses DNS, HTTP, TCP, UDP protocols

**analyzer.py**
- Aggregates packet data
- Computes statistics
- Identifies communication patterns

**detector.py**
- Implements threat detection algorithms
- Flags suspicious activities
- Generates indicators of compromise

**reporter.py**
- Creates forensic reports
- Exports to TXT and CSV formats
- Follows forensic documentation standards

**gui.py**
- Cross-platform Tkinter interface
- Multi-tab display
- Interactive charts using Matplotlib

---

## Detection Algorithms

### Implemented Detections

1. **Unknown Domain Detection**
   - Compares against safe domains list
   - Flags domains not in whitelist
   - Severity based on query frequency

2. **Excessive DNS Queries**
   - Detects potential DNS tunneling
   - Threshold-based algorithm
   - Tracks queries per domain

3. **Large Data Transfers**
   - Monitors outbound traffic volume
   - Identifies potential exfiltration
   - Configurable size thresholds

4. **Suspicious IP Patterns**
   - Private-to-public communication analysis
   - Unknown public IP detection
   - Anomalous connection patterns

5. **Unusual Port Detection**
   - Non-standard port usage
   - Potential backdoor identification
   - High-risk port flagging

6. **HTTP POST Anomalies**
   - Multiple POST requests to unknown hosts
   - Potential data exfiltration via HTTP
   - Form submission analysis

7. **Phishing Indicators**
   - Suspicious TLDs (.tk, .ml, etc.)
   - Domain typosquatting patterns
   - Phishing keyword detection

---

## Troubleshooting

### Common Issues

#### Issue: "ModuleNotFoundError: No module named 'scapy'"
**Solution:**
```bash
pip install scapy
# or
pip3 install scapy
```

#### Issue: "Scapy cannot find network interface" (Windows)
**Solution:** Install Npcap from https://npcap.com/

#### Issue: "Permission denied" when reading PCAP
**Solution:** 
- Ensure PCAP file has read permissions
- On Linux/macOS: `chmod 644 your_file.pcap`
- Copy file to a location with appropriate permissions

#### Issue: GUI doesn't appear on Linux
**Solution:** Install tkinter:
```bash
sudo apt install python3-tk
```

#### Issue: "Import error" on macOS
**Solution:** Ensure you're using the correct Python version:
```bash
python3 main.py
```

#### Issue: Analysis crashes on large PCAP files
**Solution:**
- Increase available RAM
- Process smaller time windows
- Use filtering to reduce packet count

---

## Performance Considerations

### Large PCAP Files

For PCAP files larger than 1GB:
- Allow 5-15 minutes for analysis
- Monitor memory usage
- Consider splitting files if needed

### Optimization Tips

1. **Pre-filter PCAP files** to relevant traffic:
   ```bash
   tcpdump -r large.pcap -w filtered.pcap 'tcp or udp or icmp'
   ```

2. **Focus on time windows** of interest

3. **Increase system resources** if available

---

## Development and Customization

### Adding Custom Domains

Edit `data/safe_domains.txt`:
```
your-company.com
internal-service.local
```

### Modifying Detection Thresholds

Edit `src/detector.py` and adjust values:
```python
# Change excessive DNS query threshold
def detect_excessive_dns_queries(self, threshold: int = 20):
    # Increase or decrease as needed
```

### Extending Detection Logic

Add new detection methods to `ThreatDetector` class in `src/detector.py`:
```python
def detect_custom_pattern(self) -> List[Dict[str, Any]]:
    """Your custom detection logic"""
    findings = []
    # Your code here
    return findings
```

---

## Security and Privacy

### Data Handling

- All analysis is performed **locally**
- No data is sent to external services
- PCAP files remain on your system
- Reports are saved locally

### Recommendations

- Store PCAP files securely
- Restrict access to forensic analysis systems
- Follow your organization's data handling policies
- Sanitize reports before sharing externally

---

## Limitations

### Current Limitations

- **No packet reassembly:** Fragmented packets analyzed individually
- **Limited protocol support:** Focus on DNS, HTTP, TCP, UDP, ICMP
- **Memory-intensive:** Large files require significant RAM
- **No real-time capture:** Analysis of pre-captured PCAP files only
- **Basic HTTPS analysis:** Encrypted traffic content not inspected

### Not Included

- Packet payload decryption
- Real-time network monitoring
- Active scanning or probing
- Malware sandbox integration
- Automated incident response

---

## Legal and Ethical Considerations

### Important Notice

⚠️ **This tool is for authorized forensic investigation only.**

- Only analyze network traffic you have permission to capture
- Follow your organization's security policies
- Comply with applicable laws and regulations
- Document chain of custody for evidence
- Respect privacy and data protection laws

### Use Cases

✅ **Appropriate Use:**
- Corporate security investigations
- Incident response activities
- Educational and research purposes
- Security audits with authorization

❌ **Inappropriate Use:**
- Unauthorized network monitoring
- Privacy violations
- Illegal surveillance
- Offensive security without permission

---

## Contributing

This is a forensic tool developed for the CNC414 project. For improvements:

1. Document any issues encountered
2. Suggest detection algorithm enhancements
3. Report false positives/negatives
4. Propose new features

---

## Version History

### Version 1.0.0 (December 23, 2025)
- Initial release
- Cross-platform support (Windows, macOS, Linux)
- GUI implementation with Tkinter
- DNS, HTTP, TCP analysis
- 7 threat detection algorithms
- TXT, CSV, and PDF report generation with professional formatting

---

## License

See LICENSE file for details.

---

## Contact

**Project:** Network Packet Investigator  
**Case:** Suspected Phishing and Data Exfiltration Incident  
**Team:** Digital Forensics Team  
**Course:** CNC414

---

## Acknowledgments

- **Scapy:** For packet manipulation capabilities
- **Matplotlib:** For data visualization
- **Python Community:** For excellent cross-platform support
- **Forensic Community:** For best practices and methodologies

---

## References

### Digital Forensics Standards
- NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
- RFC 3227: Guidelines for Evidence Collection and Archiving
- ISO/IEC 27037: Guidelines for identification, collection, acquisition, and preservation of digital evidence

### Threat Intelligence
- MITRE ATT&CK Framework
- OWASP Top 10
- SANS Internet Storm Center

---

**End of Documentation**

For additional help or questions, refer to the inline code documentation or review the forensic analysis logs in the `logs/` directory.
