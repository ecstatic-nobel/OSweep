#!/opt/splunk/bin/python
"""
Use crt.sh to discover certificates by searching all of the publicly known 
Certificate Transparency (CT) logs.
"""

import json
import sys

import requests
import validators


def process_iocs(provided_iocs):
    """Return data formatted for Splunk from crt.sh."""
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        if validators.domain(provided_ioc):
            crt_dicts = search_crtsh(provided_ioc)
        else:
            invalid_ioc = invalid_dict(provided_ioc)
            splunk_table.append(invalid_ioc)
            continue

        if len(crt_dicts) == 0:
            invalid_ioc = invalid_dict(provided_ioc)
            splunk_table.append(invalid_ioc)
            continue

        for crt_dict in crt_dicts:
            crt_dict["Invalid"] = None
            splunk_table.append(crt_dict)
    return splunk_table

def search_crtsh(provided_ioc):
    """Search crt.sh for the given domain."""
    if sys.argv[1] == "wildcard":
        provided_ioc = "%25.{}".format(provided_ioc) # provided_ioc -> domain

    base_url  = "https://crt.sh/?q={}&output=json"
    url       = base_url.format(provided_ioc)
    uagent    = 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'
    resp      = requests.get(url, headers={'User-Agent': uagent})
    crt_dicts = []

    if resp.status_code == 200:
        content      = resp.content.decode('UTF-8')
        cert_history = json.loads("[{}]".format(content.replace('}{', '},{')))

        for cert in cert_history:
            ncert = {}
            ncert["Issuer CA ID"]        = cert.get("issuer_ca_id", None)
            ncert["Issuer Name"]         = cert.get("issuer_name", None)
            ncert["Name Value"]          = cert.get("name_value", None)
            ncert["Min Cert ID"]         = cert.get("min_cert_id", None)
            ncert["Min Entry Timestamp"] = cert.get("min_entry_timestamp", None)
            ncert["Not Before"]          = cert.get("not_before", None)
            ncert["Not After"]           = cert.get("not_after", None)
            ncert["Invalid"]             = None
            crt_dicts.append(ncert)
    return crt_dicts

def invalid_dict(provided_ioc):
    """Return a dictionary for the invalid IOC."""
    invalid_ioc = {}
    invalid_ioc["Issuer CA ID"]        = None
    invalid_ioc["Issuer Name"]         = None
    invalid_ioc["Name Value"]          = None
    invalid_ioc["Min Cert ID"]         = None
    invalid_ioc["Min Entry Timestamp"] = None
    invalid_ioc["Not Before"]          = None
    invalid_ioc["Not After"]           = None
    invalid_ioc["Invalid"]             = provided_ioc
    return invalid_ioc
