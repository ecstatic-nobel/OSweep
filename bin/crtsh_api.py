#!/opt/splunk/bin/python
"""
Use crt.sh to discover certificates by searching all of the publicly known 
Certificate Transparency (CT) logs.
"""

import json
import os
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import requests
import validators


def process_iocs(provided_iocs):
    """Return data formatted for Splunk from crt.sh."""
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace("[.]", ".")
        provided_ioc = provided_ioc.replace("[d]", ".")
        provided_ioc = provided_ioc.replace("[D]", ".")

        if validators.domain(provided_ioc) and validators.ipv4(provided_ioc):
            crt_dicts = query_crtsh(provided_ioc)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        for crt_dict in crt_dicts:
            splunk_table.append(crt_dict)
    return splunk_table

def query_crtsh(provided_ioc):
    """Search crt.sh for the given domain."""
    if sys.argv[1] == "wildcard":
        provided_ioc = "%25.{}".format(provided_ioc)

    base_url  = "https://crt.sh/?q={}&output=json"
    url       = base_url.format(provided_ioc)
    uagent    = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
    resp      = requests.get(url, headers={"User-Agent": uagent})
    crt_dicts = []

    if resp.status_code == 200 and resp.content != "":
        content      = resp.content.decode("UTF-8")
        cert_history = json.loads("[{}]".format(content.replace("}{", "},{")))

        for cert in cert_history:
            cert = lower_keys(cert)
            crt_dicts.append(cert)
    else:
        provided_ioc = provided_ioc.replace("%25.", "")
        crt_dicts.append({"no data": provided_ioc})
    return crt_dicts

def lower_keys(target):
    """Return a string or dictionary with the first character capitalized."""
    if isinstance(target, str) or isinstance(target, unicode):
        words = target.encode("UTF-8").split("_")
        return " ".join(words).lower()

    if isinstance(target, dict):
        dictionary = {}
        for key, value in target.iteritems():
            words = key.encode("UTF-8").split("_")
            key   = " ".join(words).lower()
            dictionary[key] = value
        return dictionary
