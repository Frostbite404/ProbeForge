import os
import subprocess
import json
from xml.etree import ElementTree
from colorama import Fore, Style
from time import sleep
from tqdm import tqdm

def color_text(text, color):
    return f"{color}{text}{Style.RESET_ALL}"

def display_banner():
    banner = """
    
                                                                                                     
@@@@@@@   @@@@@@@    @@@@@@   @@@@@@@   @@@@@@@@  @@@@@@@@   @@@@@@   @@@@@@@    @@@@@@@@  @@@@@@@@  
@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@@  @@@@@@@@  
@@!  @@@  @@!  @@@  @@!  @@@  @@!  @@@  @@!       @@!       @@!  @@@  @@!  @@@  !@@        @@!       
!@!  @!@  !@!  @!@  !@!  @!@  !@   @!@  !@!       !@!       !@!  @!@  !@!  @!@  !@!        !@!       
@!@@!@!   @!@!!@!   @!@  !@!  @!@!@!@   @!!!:!    @!!!:!    @!@  !@!  @!@!!@!   !@! @!@!@  @!!!:!    
!!@!!!    !!@!@!    !@!  !!!  !!!@!!!!  !!!!!:    !!!!!:    !@!  !!!  !!@!@!    !!! !!@!!  !!!!!:    
!!:       !!: :!!   !!:  !!!  !!:  !!!  !!:       !!:       !!:  !!!  !!: :!!   :!!   !!:  !!:       
:!:       :!:  !:!  :!:  !:!  :!:  !:!  :!:       :!:       :!:  !:!  :!:  !:!  :!:   !::  :!:       
 ::       ::   :::  ::::: ::   :: ::::   :: ::::   ::       ::::: ::  ::   :::   ::: ::::   :: ::::  
 :         :   : :   : :  :   :: : ::   : :: ::    :         : :  :    :   : :   :: :: :   : :: ::   
                                                                                                     

                                                                             
                            Created by Frostbite404
    """
    print(color_text(banner, Fore.MAGENTA))
    print(color_text("Hey Hacker! Ready to uncover some vulnerabilities?", Fore.CYAN))

def run_command(cmd, error_msg, hide_output=False):
    try:
        if hide_output:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(result.stdout)
            
        if result.returncode != 0:
            print(color_text(f"{error_msg} (Error Code: {result.returncode})", Fore.RED))
            if not hide_output:
                print(f"Error Output: {result.stderr}")
            return None
        return result.stdout
    except Exception as e:
        print(color_text(f"[!] Error executing command: {e}", Fore.RED))
        return None

def validate_ports(ports):
    """Validate the list of ports provided by the user."""
    valid_ports = []
    for port in ports:
        if port.isdigit() and 0 < int(port) <= 65535:
            valid_ports.append(port)
        else:
            print(color_text(f"[!] Invalid port: {port}. Must be between 1 and 65535.", Fore.RED))
    return valid_ports

def run_rustscan(target, scan_type="top1000", specific_ports=None):
    print(color_text("[*] Running port discovery...", Fore.CYAN))
    
    # Configure RustScan based on scan type
    if scan_type == "all":
        rustscan_cmd = (
            f"rustscan -a {target} "
            f"--ulimit 5000 "
            f"--batch-size 1000 "
            f"--timeout 2000 "
            f"--tries 2 "
            f"--range 1-65535"
        )
    elif scan_type == "specific" and specific_ports:
        ports_str = ",".join(specific_ports)
        rustscan_cmd = (
            f"rustscan -a {target} "
            f"--ulimit 5000 "
            f"--batch-size 1000 "
            f"--timeout 2000 "
            f"--tries 2 "
            f"-p {ports_str}"
        )
    else:  # top1000
        rustscan_cmd = (
            f"rustscan -a {target} "
            f"--ulimit 5000 "
            f"--batch-size 1000 "
            f"--timeout 2000 "
            f"--tries 2 "
            f"--range 1-1000"  # Explicitly scan only ports 1-1000
        )
    
    with tqdm(total=100, desc="Scanning ports", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
        output = run_command(rustscan_cmd, "[!] RustScan failed", hide_output=True)
        pbar.update(100)
    
    if output:
        port_info = {}
        import re
        
        # Parse port and service information from RustScan output
        port_pattern = r'(?:PORT|port|Found open port)\s*(\d+)(?:/tcp|/udp)?'
        service_pattern = r'(\d+)/tcp\s+(?:open|filtered)\s+(\S+)'
        
        # First pass: collect all open ports
        ports = []
        for match in re.finditer(port_pattern, output, re.IGNORECASE):
            try:
                port = match.group(1)
                if port.isdigit() and 0 <= int(port) <= 65535:
                    ports.append(port)
            except Exception as e:
                print(color_text(f"[!] Error parsing port: {str(e)}", Fore.RED))
                continue
        
        # Second pass: collect service information
        for match in re.finditer(service_pattern, output, re.MULTILINE):
            try:
                port = match.group(1)
                service = match.group(2) if match.group(2) else "unknown"
                if port in ports:
                    port_info[port] = service
            except Exception as e:
                print(color_text(f"[!] Error parsing service: {str(e)}", Fore.RED))
                continue
        
        # Add any ports without service information
        for port in ports:
            if port not in port_info:
                port_info[port] = "unknown"
        
        if port_info:
            print(color_text("\n[+] Open ports found:", Fore.GREEN))
            
            # Sort ports by number
            sorted_ports = sorted(port_info.items(), key=lambda x: int(x[0]))
            
            for port, service in sorted_ports:
                port_num = int(port)
                # Determine the category based on port number
                if port_num in [80, 443, 8080, 8443]:
                    category = "Web Services"
                elif port_num in [1433, 3306, 5432, 27017]:
                    category = "Database"
                elif port_num in [22, 23, 3389]:
                    category = "Remote Access"
                elif port_num in [21, 139, 445]:
                    category = "File Sharing"
                elif port_num in [25, 110, 143, 587, 993]:
                    category = "Mail"
                else:
                    category = "Other"
                
                print(color_text(f"\n    {category}:", Fore.YELLOW))
                print(color_text(f"    ➜ Port {port} - {service}", Fore.CYAN))
            
            print(color_text(f"\n[*] Total open ports found: {len(port_info)}", Fore.YELLOW))
            return port_info
        else:
            print(color_text("\n[!] No open ports found in the scan output.", Fore.RED))
    return None

def select_ports_for_scan(port_info):
    """Allow user to select which ports to scan for vulnerabilities."""
    print(color_text("\nSelect ports to scan:", Fore.YELLOW))
    print("1. All discovered ports")
    print("2. Select specific ports")
    choice = input(color_text("Enter your choice (1/2): ", Fore.GREEN)).strip()
    
    if choice == "1":
        return list(port_info.keys())
    elif choice == "2":
        print(color_text("\nAvailable ports:", Fore.CYAN))
        # Sort ports numerically
        sorted_ports = sorted(port_info.items(), key=lambda x: int(x[0]))
        
        # Display ports with their services
        for i, (port, service) in enumerate(sorted_ports, 1):
            print(f"{i}. Port {port:<6} - {service}")
        
        ports_input = input(color_text("\nEnter port numbers (comma-separated): ", Fore.GREEN)).strip()
        selected_ports = []
        for port_num in ports_input.split(','):
            port_num = port_num.strip()
            if port_num in port_info:
                selected_ports.append(port_num)
            else:
                print(color_text(f"[!] Port {port_num} was not discovered in the scan.", Fore.RED))
        
        if not selected_ports:
            print(color_text("[!] No valid ports selected. Using all discovered ports.", Fore.YELLOW))
            return list(port_info.keys())
        return selected_ports
    else:
        print(color_text("[!] Invalid choice. Using all discovered ports.", Fore.YELLOW))
        return list(port_info.keys())

def run_nmap(target, ports):
    print(color_text(f"\n[*] Starting vulnerability scan on {target}", Fore.CYAN))
    
    output_file = f"output/{target}_nmap.xml"
    total_ports = len(ports)
    
    # Run nmap with all ports at once
    ports_str = ",".join(ports)
    nmap_cmd = f"nmap -sV -sC -p {ports_str} --script=vuln,exploit,auth,default -oX {output_file} {target}"
    
    with tqdm(total=1, desc="Scanning ports", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
        result = run_command(nmap_cmd, "[!] Nmap scan failed", hide_output=True)
        if result is not None:
            pbar.update(1)
        else:
            print(color_text("\n[!] Failed to scan ports.", Fore.RED))

    if os.path.exists(output_file):
        print(color_text("\n[+] Vulnerability scan completed successfully!", Fore.GREEN))
        return output_file
    else:
        print(color_text("\n[!] Scan output file was not created. The scan may have failed.", Fore.RED))
        return None

def parse_nmap_output(xml_file):
    print(color_text("\n[*] Analyzing scan results...", Fore.CYAN))
    try:
        tree = ElementTree.parse(xml_file)
        root = tree.getroot()
        scan_results = []
        
        for host in root.findall("host"):
            status = host.find("status").get("state", "unknown")
            if status != "up":
                print(color_text(f"[!] Host appears to be down or unresponsive", Fore.RED))
                continue
                
            for port in host.findall("ports/port"):
                port_id = port.get("portid")
                protocol = port.get("protocol", "unknown")
                
                service = port.find("service")
                if service is not None:
                    service_name = service.get("name", "unknown")
                    service_product = service.get("product", "")
                    service_version = service.get("version", "")
                else:
                    service_name = "unknown"
                    service_product = ""
                    service_version = ""
                
                vulns = []
                for script in port.findall("script"):
                    script_id = script.get("id", "")
                    output = script.get("output", "").strip()
                    
                    if not output or output.lower() in ["false", "true", "none"]:
                        continue
                        
                    cves = []
                    if "CVE-" in output:
                        import re
                        cves = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                    
                    vulns.append({
                        "type": script_id,
                        "details": output,
                        "cves": cves
                    })
                
                if vulns:
                    scan_results.append({
                        "port": port_id,
                        "protocol": protocol,
                        "service": {
                            "name": service_name,
                            "product": service_product,
                            "version": service_version
                        },
                        "vulnerabilities": vulns
                    })
        
        if scan_results:
            print(color_text("\n[+] Vulnerability analysis complete!", Fore.GREEN))
            for result in scan_results:
                print(color_text(f"\n[+] Port {result['port']} ({result['protocol']})", Fore.GREEN))
                print(color_text(f"    Service: {result['service']['name']}", Fore.CYAN))
                if result['service']['product']:
                    print(color_text(f"    Product: {result['service']['product']} {result['service']['version']}", Fore.CYAN))
                
                print(color_text("\n    Vulnerabilities Found:", Fore.YELLOW))
                for vuln in result['vulnerabilities']:
                    print(color_text(f"\n    → {vuln['type']}", Fore.RED))
                    print(color_text(f"      {vuln['details']}", Fore.WHITE))
                    if vuln['cves']:
                        print(color_text(f"      CVEs: {', '.join(vuln['cves'])}", Fore.RED))
            
            return scan_results
        else:
            print(color_text("\n[*] No vulnerabilities were found in the scan.", Fore.YELLOW))
            return []
            
    except ElementTree.ParseError as e:
        print(color_text(f"\n[!] Failed to parse Nmap XML: {str(e)}", Fore.RED))
        return []
    except Exception as e:
        print(color_text(f"\n[!] Error processing scan results: {str(e)}", Fore.RED))
        return None

def search_exploit(cve):
    print(color_text(f"\n[*] Searching for known exploits for {cve}...", Fore.CYAN))
    
    # First, try searching with the CVE ID
    searchsploit_cmd = f"searchsploit {cve}"
    output = run_command(searchsploit_cmd, "[!] SearchSploit failed", hide_output=True)
    
    if output:
        print(color_text("\n[+] SearchSploit Results:", Fore.GREEN))
        print(output)
        
        # Get the JSON output for structured data
        json_cmd = f"searchsploit --json {cve}"
        json_output = run_command(json_cmd, "[!] Failed to get JSON data", hide_output=True)
        
        if json_output:
            try:
                results = json.loads(json_output)
                if results and "RESULTS_EXPLOIT" in results:
                    exploits = results["RESULTS_EXPLOIT"]
                    if exploits:
                        print(color_text(f"\n[+] Found {len(exploits)} potential exploit(s)!", Fore.GREEN))
                        print(color_text("\n[*] Local Exploit Paths:", Fore.YELLOW))
                        
                        for i, exploit in enumerate(exploits, 1):
                            title = exploit.get('Title', 'Unknown Title')
                            path = exploit.get('Path', 'Path not available')
                            
                            print(color_text(f"\n{i}. {title}", Fore.CYAN))
                            print(color_text(f"   Local Path: /usr/share/exploitdb/{path}", Fore.WHITE))
                            
                            # Try to get the exploit code
                            if path:
                                mirror_cmd = f"searchsploit -m {path}"
                                print(color_text(f"   To copy: {mirror_cmd}", Fore.WHITE))
                        
                        return exploits
            except json.JSONDecodeError:
                print(color_text("[!] Failed to parse SearchSploit JSON output.", Fore.RED))
            except Exception as e:
                print(color_text(f"[!] Error processing SearchSploit results: {str(e)}", Fore.RED))
    
    # Try searching without dashes
    cve_no_dashes = cve.replace("-", "")
    if cve_no_dashes != cve:
        print(color_text(f"\n[*] Trying alternative search format: {cve_no_dashes}", Fore.YELLOW))
        alt_cmd = f"searchsploit {cve_no_dashes}"
        alt_output = run_command(alt_cmd, "[!] Alternative search failed", hide_output=True)
        if alt_output and "Exploit Title" in alt_output:
            print(color_text("\n[+] Additional Results Found:", Fore.GREEN))
            print(alt_output)
    
    return None

def show_scan_options():
    print(color_text("\nSelect scan type:", Fore.YELLOW))
    print("1. Continue with host check")
    print("2. Continue without host check")
    print("0. Exit")
    
    option = input(color_text("Enter your choice: ", Fore.GREEN)).strip()
    
    if option in ["1", "2"]:
        print(color_text("\nSelect port scan range:", Fore.YELLOW))
        print("1. Top 1000 ports")
        print("2. All ports (1-65535)")
        print("3. Specific ports")
        
        scan_range = input(color_text("Enter your choice: ", Fore.GREEN)).strip()
        return option, scan_range
    
    return option, None

def main():
    display_banner()

    target = input(color_text("[?] Enter target IP or domain: ", Fore.GREEN)).strip()
    if not target:
        print(color_text("[!] No target provided. Exiting.", Fore.RED))
        return
    
    while True:
        option, scan_range = show_scan_options()
        
        if option == "0":
            print(color_text("[*] Exiting the script.", Fore.RED))
            break
            
        elif option in ["1", "2"]:
            # Determine scan type
            if scan_range == "1":
                port_info = run_rustscan(target, "top1000")
            elif scan_range == "2":
                port_info = run_rustscan(target, "all")
            elif scan_range == "3":
                ports_input = input(color_text("[?] Enter ports (comma-separated): ", Fore.GREEN)).strip()
                specific_ports = [port.strip() for port in ports_input.split(",") if port.strip().isdigit()]
                if specific_ports:
                    port_info = run_rustscan(target, "specific", specific_ports)
                else:
                    print(color_text("[!] No valid ports provided.", Fore.RED))
                    continue
            else:
                print(color_text("[!] Invalid choice.", Fore.RED))
                continue
            
            if port_info:
                scan = input(color_text("\n[?] Run vulnerability scan? (yes/no): ", Fore.GREEN)).strip().lower()
                if scan == "yes":
                    # Select ports for vulnerability scanning
                    ports_to_scan = select_ports_for_scan(port_info)
                    nmap_output = run_nmap(target, ports_to_scan)
                    if nmap_output:
                        scan_results = parse_nmap_output(nmap_output)
                        if scan_results:
                            for result in scan_results:
                                for vuln in result['vulnerabilities']:
                                    if vuln['cves']:
                                        for cve in vuln['cves']:
                                            print(color_text(f"\n[*] Found CVE: {cve}", Fore.YELLOW))
                                            print(color_text("[*] Details:", Fore.CYAN))
                                            print(color_text(f"    {vuln['details']}", Fore.WHITE))
                                            
                                            search = input(color_text("\n[?] Search for exploits? (yes/no): ", Fore.GREEN)).strip().lower()
                                            if search == "yes":
                                                exploits = search_exploit(cve)
                                                if exploits:
                                                    copy = input(color_text("\n[?] Copy exploit to current directory? (number/no): ", Fore.GREEN)).strip()
                                                    if copy != "no" and copy.isdigit():
                                                        exploit_num = int(copy) - 1
                                                        if 0 <= exploit_num < len(exploits):
                                                            exploit = exploits[exploit_num]
                                                            if 'Path' in exploit:
                                                                mirror_cmd = f"searchsploit -m {exploit['Path']}"
                                                                print(color_text("\n[*] Copying exploit...", Fore.YELLOW))
                                                                run_command(mirror_cmd, "[!] Failed to copy exploit", hide_output=True)
                                                                print(color_text("[+] Exploit copied to current directory", Fore.GREEN))
                            
                            # Only prompt to save after all results are displayed
                            save_output = input(color_text("\n[?] Save scan results to a file? (yes/no): ", Fore.GREEN)).strip().lower()
                            if save_output == "yes":
                                try:
                                    # Create reports directory if it doesn't exist
                                    os.makedirs("reports", exist_ok=True)
                                    
                                    # Get filename from user
                                    filename = input(color_text("[?] Enter filename (without extension): ", Fore.GREEN)).strip()
                                    if not filename:
                                        filename = f"scan_{target}"
                                    
                                    # Add timestamp and ensure .txt extension
                                    from datetime import datetime
                                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                    full_filename = f"reports/{filename}_{timestamp}.txt"
                                    
                                    with open(full_filename, 'w') as f:
                                        f.write("==== ProbeForge Vulnerability Scan Results ====\n\n")
                                        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                                        f.write(f"Target: {target}\n\n")
                                        f.write("=== Open Ports ===\n")
                                        
                                        # Write discovered ports information
                                        for port, service in port_info.items():
                                            f.write(f"\nPort {port} - {service}\n")
                                        
                                        f.write("\n=== Vulnerability Scan Results ===\n")
                                        if nmap_output and os.path.exists(nmap_output):
                                            try:
                                                tree = ElementTree.parse(nmap_output)
                                                root = tree.getroot()
                                                
                                                for host in root.findall("host"):
                                                    for port in host.findall("ports/port"):
                                                        port_id = port.get("portid")
                                                        protocol = port.get("protocol", "unknown")
                                                        
                                                        service = port.find("service")
                                                        if service is not None:
                                                            service_name = service.get("name", "unknown")
                                                            service_product = service.get("product", "")
                                                            service_version = service.get("version", "")
                                                            
                                                            f.write(f"\nPort: {port_id} ({protocol})\n")
                                                            f.write(f"Service: {service_name}\n")
                                                            if service_product or service_version:
                                                                f.write(f"Product: {service_product} {service_version}\n")
                                                        
                                                        scripts = port.findall("script")
                                                        if scripts:
                                                            f.write("\nVulnerabilities Found:\n")
                                                            for script in scripts:
                                                                script_id = script.get("id", "")
                                                                output = script.get("output", "").strip()
                                                                
                                                                if output and output.lower() not in ["false", "true", "none"]:
                                                                    f.write(f"\n  → {script_id}\n")
                                                                    f.write(f"    Details: {output}\n")
                                                                    
                                                                    if "CVE-" in output:
                                                                        cves = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                                                                        if cves:
                                                                            f.write(f"    CVEs: {', '.join(cves)}\n")
                                            except Exception as e:
                                                f.write(f"\nError parsing Nmap results: {str(e)}\n")
                                        else:
                                            f.write("\nNo vulnerability scan results available.\n")
                                    
                                    print(color_text(f"\n[+] Results saved to {full_filename}", Fore.GREEN))
                                except Exception as e:
                                    print(color_text(f"\n[!] Error saving results: {str(e)}", Fore.RED))
        else:
            print(color_text("[!] Invalid choice, please try again.", Fore.RED))

if __name__ == "__main__":
    os.makedirs("output", exist_ok=True)
    main()
