ma'et Scanner

Overview

The ma'et Scanner is a Python script designed for various network scanning tasks. It can perform domain-to-IP resolution, IP location lookups, port scanning, 
vulnerability scanning, and comprehensive network analysis.

Features

- Domain to IP Resolution: Find real IP addresses associated with a domain.
- IP Location Lookup: Get geographic and organizational information about IP addresses.
- Port Scanning: Scan specified port ranges on an IP address.
- Vulnerability Scanning: Identify known vulnerabilities on the scanned IP.
- Comprehensive Scan: Perform an in-depth scan including all ports, OS detection, and service detection.
- Custom Port Range: Allows custom port range specification for scanning.

Prerequisites

Ensure you have Python 3 installed. The script also requires several Python libraries. You can install them using the provided `requirements.txt` file.

Setup

1. Clone the repository (or download the script):
   
   git clone https://github.com/isotaka134/maet-scanner.git
   cd maet-scanner

2. Installation
 
   * Install the required libraries:
	python install_requirements.py
    
   * You can manually install the required libraries with:
	pip install -r requirements.txt

3. Run the script

    python scanner.py	
