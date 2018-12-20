#!/opt/splunk/bin/python
"""
Description: Use crt.sh to discover certificates by searching all of the publicly 
known Certificate Transparency (CT) logs. The script accepts a list of strings 
(domains or IPs):
    | crtsh $ioc$

or input from the pipeline (any field where the value is a domain or IP). The 
first argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | crtsh <IOC_FIELD>

Source: https://github.com/PaulSec/crt.sh

Instructions:
1. Switch to the Certificate Search dashboard in the OSweep app.
2. Add the list of IOCs to the "Domain, IP (+)" textbox.
3. Select "Yes" or "No" from the "Wildcard" dropdown to search for subdomains.
4. Click "Submit".

Rate Limit: None

Results Limit: None

Notes: Search for subdomains by passing "wildcard" as the first argument:
    | crtsh wildcard $domain$

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import json
import os
import sys

app_home   = "{}/etc/apps/osweep".format(os.environ['SPLUNK_HOME'])
tp_modules = "{}/bin/_tp_modules".format(app_home)
sys.path.insert(0, tp_modules)
import validators

import commons


def process_iocs(results):
    """Return data formatted for Splunk from crt.sh."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    elif sys.argv[1] != "subdomain" and sys.argv[1] != "wildcard":
        if len(sys.argv) > 1:
            provided_iocs = sys.argv[1:]
    elif sys.argv[1] == "subdomain" or sys.argv[1] == "wildcard":
        if len(sys.argv) > 2:
            provided_iocs = sys.argv[2:]

    session      = commons.create_session()
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = commons.deobfuscate_url(provided_ioc)

        if validators.domain(provided_ioc) or validators.ipv4(provided_ioc):
            crt_dicts = query_crtsh(provided_ioc, session)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        for crt_dict in crt_dicts:
            splunk_table.append(crt_dict)

    session.close()
    return splunk_table

def query_crtsh(provided_ioc, session):
    """Search crt.sh for the given domain."""
    if sys.argv[1] == "subdomain":
        provided_ioc = "%25.{}".format(provided_ioc)
    elif sys.argv[1] == "wildcard":
        provided_ioc = "%25{}".format(provided_ioc)

    base_url  = "https://crt.sh/?q={}&output=json"
    url       = base_url.format(provided_ioc)
    resp      = session.get(url, timeout=180)
    crt_dicts = []

    if resp.status_code == 200 and resp.content != "":
        content      = resp.content.decode("UTF-8")
        cert_history = json.loads("[{}]".format(content.replace("}{", "},{")))

        for cert in cert_history:
            cert = commons.lower_keys(cert)
            crt_dicts.append(cert)
    else:
        provided_ioc = provided_ioc.replace("%25.", "").replace("%25", "")
        crt_dicts.append({"no data": provided_ioc})
    return crt_dicts

if __name__ == "__main__":
    current_module = sys.modules[__name__]
    commons.return_results(current_module)
