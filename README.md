ma'et Scanner

## Overview

The ma'et Scanner is a Python script designed for various network scanning tasks. It can perform domain-to-IP resolution, IP location lookups, port scanning, 
vulnerability scanning, and comprehensive network analysis.

## Features

- Domain to IP Resolution: Find real IP addresses associated with a domain.
- IP Location Lookup: Get geographic and organizational information about IP addresses.
- Port Scanning: Scan specified port ranges on an IP address.
- Vulnerability Scanning: Identify known vulnerabilities on the scanned IP.
- Comprehensive Scan: Perform an in-depth scan including all ports, OS detection, and service detection.
- Custom Port Range: Allows custom port range specification for scanning.

## Prerequisites

Ensure you have Python 3 installed. The script also requires several Python libraries. You can install them using the provided `requirements.txt` file.

## Setup

1. Clone the repository (or download the script):
   
   git clone https://github.com/isotaka134/maet-scanner.git

   cd maet-scanner

3. Installation
 
   * Install the required libraries:
	
 python install_requirements.py
    
   * You can manually install the required libraries with:
	
 pip install -r requirements.txt

3. Run the script

    python run.py

   
## Usage

Once you have set up the environment and installed the required libraries, you can run the `maet` scanner script using the following steps:

1. Run the Script:

   Open a terminal or command prompt, navigate to the directory containing the `run.py` script, and execute:

   
   python run.py
  

2. Follow the Prompts:

   The script will prompt you for a domain and then present you with several scanning options. Here’s an example of the interactive session:
 
```	
		 .-./`)    .-'''-.     ,-----.  ,---------.    ____    .--.   .--.     ____
                \ .-.')  / _     \  .'  .-,  '.\          \ .'  __ `. |  | _/  /    .'  __ `.
                / `-' \ (`' )/`--' / ,-.|  \ _ \`--.  ,---'/   '  \  \| (`' ) /    /   '  \  \
                 `-'`"`(_ o _).   ;  \  '_ /  | :  |   \   |___|  /  ||(_ ()_)     |___|  /  |
                 .---.  (_,_). '. |  _`,/ \ _/  |  :_ _:      _.-`   || (_,_)   __    _.-`   |
                 |   | .---.  \  :: (  '\_/ \   ;  (_I_)   .'   _    ||  |\ \  |  |.'   _    |
                 |   | \    `-'  | \ `"/  \  ) /  (_(=)_)  |  _( )_  ||  | \ `'   /|  _( )_  |
                 |   |  \       /   '. \_/``".'    (_I_)   \ (_ o _) /|  |  \    / \ (_ o _) /
                 '---'   `-...-'      '-----'      '---'    '.(_,_).' `--'   `'-'   '.(_,_).'

                                                                                                                                                                                                     
                        Isotaka Nobomaro ====> MA ======> IG: isotaka.nobomaro

   Enter the domain: example.com

   Possible real IP addresses and their locations for example.com:
   [*] IP: 93.184.216.34
   [*] Location: Los Angeles, California, US
   [*] Organization: Example Organization
   [*] Coordinates: 34.0522,-118.2437
   ----------------------------------------

   Select a scanning option for IP 93.184.216.34:
   1. Port Scan (Default: ports 1-1024)
   2. Vulnerability Scan
   3. Comprehensive Scan (All ports, OS detection, service detection, etc.)
   4. Custom Port Range Scan
   5. Exit

   Enter your choice (1-5): 1

   Scanning ports for IP 93.184.216.34:
   [*] Port: 80    State: open    Service: http    Version: Apache 2.4.41
   [*] Port: 443   State: open    Service: https   Version: Apache 2.4.41
   ========================================

   Select a scanning option for IP 93.184.216.34:
   1. Port Scan (Default: ports 1-1024)
   2. Vulnerability Scan
   3. Comprehensive Scan (All ports, OS detection, service detection, etc.)
   4. Custom Port Range Scan
   5. Exit

   Enter your choice (1-5): 5
```

## Explanation:

1. Run the Script: Execute the script using Python. Make sure you're in the directory where `run.py` is located.

2. Enter Domain : You will be prompted to enter the domain you want to scan.

3. View IP Details: The script will display IP addresses associated with the domain along with their geographical location and organization details.

4. Choose Scanning Option: You can select from the following options:
   - Port Scan: Scan default ports (1-1024).
   - Vulnerability Scan: Check for known vulnerabilities.
   - Comprehensive Scan: Perform a detailed scan including all ports and service detection.
   - Custom Port Range Scan: Specify a custom range of ports to scan (e.g., 1-1000).
   - Exit: Exit to the second IP / Exit the script.

5. View Results: Based on your choice, the script will perform the selected scan and display the results.


