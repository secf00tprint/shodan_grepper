import json
import os
import requests
import sys
from bs4 import BeautifulSoup

shodan_api_url="https://internetdb.shodan.io"
nist_url="https://nvd.nist.gov/vuln/detail"

if len(sys.argv) < 2:
    print("You have to add a file containing IPs")
else:
    file_name = sys.argv[1]
    if os.path.isfile(file_name):
        with open(file_name,'r') as f:
            for line in f:
                ip_to_read = line.strip()
                url = f'{shodan_api_url}/{ip_to_read}'
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
                    print()
                    print(f'IP: {ip}:{ports} - Hostname(s): {hostnames}')
                    if 'cpes' in data:
                        cpes=data['cpes']
                        print(f'CPEs: {cpes}')
                    if 'vulns' in data:
                        vulns=data['vulns']
                        print(f'Vulns: {vulns}')
                        for vuln_nr in vulns:
                            cve_infos_url= f'{nist_url}/{vuln_nr}'
                            nist_html = requests.get(cve_infos_url)
                            nist_soup = BeautifulSoup(nist_html.content,'html.parser')
                            tag = nist_soup.find('a', {'id':'Cvss3NistCalculatorAnchor'})
                            base_score = str(tag.decode_contents())
                            colorstart=''
                            colorend=''
                            if 'HIGH' in base_score:
                                colorstart='\033[31m'
                                colorend='\033[0m'
                            print(f'{colorstart}{vuln_nr}:{base_score}{colorend}')
                            print(cve_infos_url)

    else:
        print(f"The file {file_name} is not existent")
