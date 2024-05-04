import json
import argparse
import os
import requests
import sys
from bs4 import BeautifulSoup
import csv

SHODAN_API_URL="https://internetdb.shodan.io"
NIST_URL="https://nvd.nist.gov/vuln/detail"
EXCLUDES_FILE="excludes.csv"

def get_help_Message():
    return "python3 shodan_grepper.py <file_containing_ips>"

parser = argparse.ArgumentParser(description="Shodan Grepper")
parser.add_argument("file_containing_ips", help="You have to add a file containing IPs to check")
parser.add_argument('--showcpe', action='store_true', help='Show CPE findings if existent')

args = parser.parse_args()

ips_to_exclude=''
if os.path.exists(EXCLUDES_FILE):
    with open(EXCLUDES_FILE, newline='\n') as f:
        reader = csv.reader(f)
        ips_to_exclude = [row for row in reader]

file_name = sys.argv[1]
if not os.path.isfile(file_name):
    print(f"The file {file_name} is not existent")
else:
    with open(file_name,'r') as f:
        for line in f:
            ip_to_read = line.strip()
            url = f'{SHODAN_API_URL}/{ip_to_read}'
            response = requests.get(url)
            data = response.json()
            ip=hostnames=ports=cpes=vulns=''
            if 'ip' in data:
                ip=data['ip']
            if 'hostnames' in data:
                hostnames=data['hostnames']
            if 'ports' in data:
                ports=data['ports']
            if 'cpes' in data and len(data['cpes'])!=0 or 'vulns' in data and len(data['vulns'])!=0:
                # Check if IP is not in the list of IPs to exclude and if so extract the CVEs to exclude
                exclude_IP = [sublist for sublist in ips_to_exclude if ip in sublist]
                toprint="\n"
                toprint=toprint + f"IP: {ip}:{ports} - Hostname(s): {hostnames}\n"
                if args.showcpe is not False and 'cpes' in data:
                    cpes=data['cpes']
                    toprint=toprint+f"CPEs: {cpes}\n"
                    print(toprint,end='')
                    toprint=""
                if 'vulns' in data:
                    vulns=data['vulns']
                    toprint=toprint+f"Vulns: {vulns}\n"
                    for vuln_nr in vulns:
                        if bool(exclude_IP) and vuln_nr in exclude_IP[0]:
                            continue
                        cve_infos_url= f'{NIST_URL}/{vuln_nr}'
                        nist_html = requests.get(cve_infos_url)
                        nist_soup = BeautifulSoup(nist_html.content,'html.parser')
                        tag = nist_soup.find('a', {'id':'Cvss3NistCalculatorAnchor'})
                        base_score = str(tag.decode_contents())
                        colorstart=''
                        colorend=''
                        if 'CRITICAL' in base_score:
                            colorstart='\033[36m'
                        if 'HIGH' in base_score:
                            colorstart='\033[31m'
                        if 'MEDIUM' in base_score:
                            colorstart='\033[33m'
                        if 'LOW' in base_score:
                            colorstart='\033[34m'
                        if bool(colorstart):
                            colorend='\033[0m'
                        toprint=toprint+f"{colorstart}{vuln_nr}:{base_score}{colorend}\n"
                        toprint=toprint+f"{cve_infos_url}\n"
                        print(toprint,end='')
                        toprint=""

