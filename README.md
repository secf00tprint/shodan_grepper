![python3](https://img.shields.io/badge/python-3)

# shodan_grepper

Tool to search Shodan API for vulnerabilities in IPs

Install needed dependencies before usage:

```
pip3 install -r requirements.txt
```

Syntax:

```
python3 shodan_grepper.py <ip_file>
```

Add a files `excludes.csv` in the same directory
format:

```
<ip1>,<cve11>,<cve12>,...
<ip2>,<cve21>
<ip3>
<ip4>,<cve41>
```

to exclude CVEs from output. For example if you fixed it but Shodan delivers another result.

Add flag `--showcpe` to additionally output found CPEs.
