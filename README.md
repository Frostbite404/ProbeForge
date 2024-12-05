# ProbeForge

**ProbeForge** is a powerful port and vulnerability scanning tool that integrates RustScan, Nmap, and SearchSploit to identify vulnerabilities on remote hosts. The tool is designed to help security professionals and penetration testers quickly assess the security posture of a target system.

## Features
- Fast port scanning using **RustScan**.
- Detailed vulnerability scanning with **Nmap** and its NSE scripts.
- CVE-based exploit search using **SearchSploit**.

## Requirements
- **Python 3.x**
- **RustScan** (for fast port scanning)
- **Nmap** (for vulnerability scanning)
- **SearchSploit** (for exploit search)

### Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/Frostbite404/ProbeForge.git
    cd ProbeForge
    ```

2. Install the required Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Ensure you have **RustScan**, **Nmap**, and **SearchSploit** installed. Follow the installation guides for these tools if needed.

    - **RustScan**: https://github.com/RustScan/RustScan
    - **Nmap**: https://nmap.org/download.html
    - **SearchSploit**: https://github.com/offensive-security/exploitdb

### Usage
Run the tool with the following command:

```bash
python3 probe_forge.py
