#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
__author__ = "SQS"

extract domain names  from ssl certificate
"""

import socket
import ssl
import sys
import shodan
import re
global SHODAN_API_KEY
global api
SHODAN_API_KEY="api" #Get free API from https://shodan.io
api=shodan.Shodan(SHODAN_API_KEY)


def extract(domainname):
    cont = ssl.create_default_context()
    conn = cont.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domainname)
    try:
        conn.connect((domainname, 443))
    except  (ssl.CertificateError,ssl.SSLError,socket.gaierror) as e:
            print("Error :", e)
            sys.exit()
    cert = conn.getpeercert()
    subdomains = (cert['subjectAltName'])
    dmn=[]
    for i, domain in subdomains:
        if "*" in domain:
            wstar = (re.split(r'[*]', domain))
            lstar=str(wstar[1])
            dmn.append(lstar[1:])
        elif domain in dmn:
            pass
        else:
            dmn.append(domain)
    return dmn




def axtar(keysoz):
    esas={'country_name':'Ölkə :', 'city':'Şəhər :', 'hostname':'Hostname :', 'org':'Təşkilat :', 'isp':'ISP :', 'ip_str':'IP :'}

    try:

        c=api.host(keysoz)
        for key in c:
            if key in esas:
                print(esas[key], c[key])

            elif key =='data':
                print( "Açıq portlar:")
                for  ind in range(len(c['ports'])):
                    print( c[key][ind]['port'],":", c[key][ind]['transport'])
                print ("-------------------------------")
    except shodan.APIError as e:
        print('Error:', e)





def resolver(domain):
    try:
        ip=socket.gethostbyname(domain)
        return ip
    except:
        pass





def main():
    for sdomain in extract(soz):

        ipaddr=resolver(sdomain)
        print("\n"+sdomain+"\n")
        if ipaddr is None:
            pass
        else:
            b=(axtar(ipaddr))
            if b != None:
                 print(b)
try:
    soz=sys.argv[1]
except:
    print("Usage: "+sys.argv[0]+" example.com")
    sys.exit()
