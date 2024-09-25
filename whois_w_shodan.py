#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
__author__ = "SQS"

Extract domain names from SSL certificate
"""

import socket
import ssl
import sys
import shodan
import re

# Constants
SHODAN_API_KEY = "paste_here"  # Get free API from https://shodan.io
api = shodan.Shodan(SHODAN_API_KEY)


def extract(domainname):
    """Extracts subdomains from the SSL certificate of the provided domain"""
    cont = ssl.create_default_context()
    conn = cont.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domainname)
    
    try:
        conn.connect((domainname, 443))
        cert = conn.getpeercert()
        conn.close()  # Always close the socket
    except (ssl.CertificateError, ssl.SSLError, socket.gaierror, ConnectionRefusedError) as e:
        print(f"Error while connecting to {domainname}: {e}")
        sys.exit()

    if 'subjectAltName' not in cert:
        print(f"No subjectAltName found in certificate for {domainname}")
        return []

    subdomains = cert['subjectAltName']
    dmn = []

    for i, domain in subdomains:
        if "*" in domain:  # Handle wildcard domains
            cleaned_domain = domain.replace("*.", "")
            if cleaned_domain not in dmn:
                dmn.append(cleaned_domain)
        elif domain not in dmn:
            dmn.append(domain)

    return dmn


def axtar(keysoz):
    """Queries Shodan for information related to the IP address"""
    esas = {
        'country_name': 'Ölkə :',
        'city': 'Şəhər :',
        'hostname': 'Hostname :',
        'org': 'Təşkilat :',
        'isp': 'ISP :',
        'ip_str': 'IP :'
    }

    try:
        c = api.host(keysoz)
        for key in esas:
            if key in c:
                print(f"{esas[key]} {c[key]}")
        
        # Check for open ports and transport details
        if 'data' in c and 'ports' in c:
            print("Açıq portlar:")
            for ind, port_info in enumerate(c['data']):
                print(f"{port_info['port']} : {port_info['transport']}")
            print("-------------------------------")
    except shodan.APIError as e:
        print(f'Shodan API Error: {e}')


def resolver(domain):
    """Resolves the domain name to its corresponding IP address"""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        print(f"Failed to resolve {domain}")
        return None


def main():
    soz = sys.argv[1] if len(sys.argv) > 1 else None
    if not soz:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit()

    for sdomain in extract(soz):
        print(f"\nDomain: {sdomain}\n")
        ipaddr = resolver(sdomain)

        if ipaddr:
            print(f"Resolved IP: {ipaddr}")
            axtar(ipaddr)
        else:
            print(f"Could not resolve domain: {sdomain}")


if __name__ == '__main__':
    main()
