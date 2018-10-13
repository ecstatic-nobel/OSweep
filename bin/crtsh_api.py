#!/opt/splunk/bin/python
"""
Use crt.sh to discover certificates by searching all of the publicly known 
Certificate Transparency (CT) logs.
"""

import json
import requests


def search(domain, wildcard=True):
    """Search crt.sh for the given domain."""
    if wildcard:
        domain = "%25.{}".format(domain)

    base_url  = "https://crt.sh/?q={}&output=json"
    url       = base_url.format(domain)
    uagent    = 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'
    resp      = requests.get(url, headers={'User-Agent': uagent})
    crt_dicts = []

    if resp.status_code == 200:
        content      = resp.content.decode('UTF-8')
        cert_history = json.loads("[{}]".format(content.replace('}{', '},{')))

        for cert in cert_history:
            ndata   = {}
            ndata["Issuer CA ID"]        = cert["issuer_ca_id"]
            ndata["Issuer Name"]         = cert["issuer_name"]
            ndata["Name Value"]          = cert["name_value"]
            ndata["Min Cert ID"]         = cert["min_cert_id"]
            ndata["Min Entry Timestamp"] = cert["min_entry_timestamp"]
            ndata["Not Before"]          = cert["not_before"]
            ndata["Not After"]           = cert["not_after"]
            ndata["Invalid"]             = "N/A"
            crt_dicts.append(ndata)
    return crt_dicts

def invalid_dict(provided_ioc):
    """Return a dictionary for the invalid IOC."""
    invalid_ioc = {}
    invalid_ioc["Issuer CA ID"]        = "N/A"
    invalid_ioc["Issuer Name"]         = "N/A"
    invalid_ioc["Name Value"]          = "N/A"
    invalid_ioc["Min Cert ID"]         = "N/A"
    invalid_ioc["Min Entry Timestamp"] = "N/A"
    invalid_ioc["Not Before"]          = "N/A"
    invalid_ioc["Not After"]           = "N/A"
    invalid_ioc["Invalid"]             = provided_ioc
    return invalid_ioc
