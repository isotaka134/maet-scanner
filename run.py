import requests
import nmap
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def print_banner(message, width=80):
    banner_lines = message.strip().split('\n')
    centered_banner = "\n".join([line.center(width) for line in banner_lines])
    print(centered_banner)
    print("=" * width)  # Add a break line after the banner

def get_real_ip(domain):
    try:
        res = DNSDumpsterAPI().search(domain)
        ip_addresses = [record['ip'] for record in res.get('dns_records', {}).get('host', []) if record.get('ip')]
        return ip_addresses
    except Exception as e:
        print(f"{Fore.RED}Error retrieving DNS information for {domain}: {e}")
        return []

def get_ip_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return response.json()
    except requests.RequestException as e:
        print(f"{Fore.RED}Error fetching location for IP {ip}: {e}")
        return None

def scan_ports(ip, port_range='1-1024'):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, port_range)
        return nm[ip]
    except Exception as e:
        print(f"{Fore.RED}Error scanning ports for IP {ip}: {e}")
        return None

def scan_vulnerabilities(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='--script vuln')
        return nm[ip]
    except Exception as e:
        print(f"{Fore.RED}Error scanning vulnerabilities for IP {ip}: {e}")
        return None

def comprehensive_scan(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-p- -A')
        return nm[ip]
    except Exception as e:
        print(f"{Fore.RED}Error performing comprehensive scan for IP {ip}: {e}")
        return None

if __name__ == "__main__":
    banner = """
			                                                                                                                
					.-./`)    .-'''-.     ,-----.  ,---------.    ____    .--.   .--.     ____     
		\ .-.')  / _     \  .'  .-,  '.\          \ .'  __ `. |  | _/  /    .'  __ `.  
		/ `-' \ (`' )/`--' / ,-.|  \ _ \`--.  ,---'/   '  \  \| (`' ) /    /   '  \  \ 
		 `-'`"`(_ o _).   ;  \  '_ /  | :  |   \   |___|  /  ||(_ ()_)     |___|  /  | 
		 .---.  (_,_). '. |  _`,/ \ _/  |  :_ _:      _.-`   || (_,_)   __    _.-`   | 
		 |   | .---.  \  :: (  '\_/ \   ;  (_I_)   .'   _    ||  |\ \  |  |.'   _    | 
		 |   | \    `-'  | \ `"/  \  ) /  (_(=)_)  |  _( )_  ||  | \ `'   /|  _( )_  | 
		 |   |  \       /   '. \_/``".'    (_I_)   \ (_ o _) /|  |  \    / \ (_ o _) / 
		 '---'   `-...-'      '-----'      '---'    '.(_,_).' `--'   `'-'   '.(_,_).'  
                                                                                                                                                                                                                 	                                             
 	                  Isotaka Nobomaro ====> EL-Hajeb  ======> IG: isotaka.nobomaro
    """
    print_banner(banner)

    domain = input("Enter the domain: ")
    ip_addresses = get_real_ip(domain)
    if ip_addresses:
        print(f"Possible real IP addresses and their locations for {domain}:")
        for ip in ip_addresses:
            location_info = get_ip_location(ip)
            if location_info:
                print(f"{Fore.GREEN}[*] IP: {ip}")
                print(f"{Fore.GREEN}[*] Location: {location_info.get('city')}, {location_info.get('region')}, {location_info.get('country')}")
                print(f"{Fore.GREEN}[*] Organization: {location_info.get('org')}")
                print(f"{Fore.GREEN}[*] Coordinates: {location_info.get('loc')}")
                print("-" * 40)
            else:
                print(f"{Fore.GREEN}[*] IP: {ip}")
                print("Location information not available")
                print("-" * 40)

            while True:
                print(f"Select a scanning option for IP {ip}:")
                print(f"{Fore.BLUE}1. Port Scan (Default: ports 1-1024)")
                print(f"{Fore.BLUE}2. Vulnerability Scan")
                print(f"{Fore.BLUE}3. Comprehensive Scan (All ports, OS detection, service detection, etc.)")
                print(f"{Fore.BLUE}4. Custom Port Range Scan")
                print(f"{Fore.BLUE}5. Exit")
                choice = input("Enter your choice (1-5): ")

                print("=" * 40)  # Print a line before the results

                if choice == '1':
                    print(f"Scanning ports for IP {ip}:")
                    scan_result = scan_ports(ip)
                    if scan_result:
                        for proto in scan_result.all_protocols():
                            for port in scan_result[proto]:
                                details = scan_result[proto][port]
                                state = details['state']
                                name = details['name']
                                product = details.get('product', 'N/A')
                                version = details.get('version', 'N/A')
                                print(f"{Fore.GREEN}[*] Port: {port}\tState: {state}\tService: {name}\tVersion: {product} {version}")
                    else:
                        print(f"{Fore.GREEN}[*] No port information available")
                    print("=" * 40)

                elif choice == '2':
                    print(f"Scanning vulnerabilities for IP {ip}:")
                    vuln_result = scan_vulnerabilities(ip)
                    if vuln_result:
                        for proto in vuln_result.all_protocols():
                            for port in vuln_result[proto]:
                                details = vuln_result[proto][port]
                                state = details['state']
                                name = details['name']
                                script_results = details.get('script', {})
                                print(f"{Fore.GREEN}[*] Port: {port}\tState: {state}\tService: {name}")
                                for script_name, script_output in script_results.items():
                                    print(f"{Fore.GREEN}[VULN] {script_name}: {script_output}")
                    else:
                        print(f"{Fore.GREEN}[*] No vulnerability information available")
                    print("=" * 40)

                elif choice == '3':
                    print(f"Performing comprehensive scan for IP {ip}:")
                    comp_result = comprehensive_scan(ip)
                    if comp_result:
                        for proto in comp_result.all_protocols():
                            for port in comp_result[proto]:
                                details = comp_result[proto][port]
                                state = details['state']
                                name = details['name']
                                product = details.get('product', 'N/A')
                                version = details.get('version', 'N/A')
                                print(f"{Fore.GREEN}[*] Port: {port}\tState: {state}\tService: {name}\tVersion: {product} {version}")
                                script_results = details.get('script', {})
                                for script_name, script_output in script_results.items():
                                    print(f"{Fore.GREEN}[VULN] {script_name}: {script_output}")
                    else:
                        print(f"{Fore.GREEN}[*] No comprehensive information available")
                    print("=" * 40)

                elif choice == '4':
                    port_range = input("Enter custom port range (e.g., 1-1000): ")
                    print(f"Scanning custom port range {port_range} for IP {ip}:")
                    scan_result = scan_ports(ip, port_range)
                    if scan_result:
                        for proto in scan_result.all_protocols():
                            for port in scan_result[proto]:
                                details = scan_result[proto][port]
                                state = details['state']
                                name = details['name']
                                product = details.get('product', 'N/A')
                                version = details.get('version', 'N/A')
                                print(f"{Fore.GREEN}[*] Port: {port}\tState: {state}\tService: {name}\tVersion: {product} {version}")
                    else:
                        print(f"{Fore.GREEN}[*] No port information available")
                    print("=" * 40)

                elif choice == '5':
                    break

                else:
                    print(f"{Fore.RED}Invalid choice. Please select a valid option.")
                    print("=" * 40)  # Line for clarity

    else:
        print(f"No IP addresses found for {domain}")
