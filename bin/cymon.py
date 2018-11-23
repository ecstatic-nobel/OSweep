#!/opt/splunk/bin/python
"""
Description: Use Cymon to search open-source security reports about phishing, 
malware, botnets and other malicious activities. The script accepts a list of 
strings (domain, IP, MD5, and/or SHA256):
    | cymon $ioc$

or input from the pipeline (any field where the value is a domain, IP, and/or 
SHA256). The first argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | cymon <IOC_FIELD>

Source: http://docs.cymon.io/

Instructions:
1. Switch to the Cymon dashboard in the OSweep app.
2. Add the list of IOCs to the "Domain, IP, MD5, SHA256 (+)" textbox.
3. Select whether the results will be grouped and how from the dropdowns.
4. Click "Submit".

Rate Limit: None

Results Limit: 10

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import os
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import validators

import commons


def process_iocs(results):
    """Return data formatted for Splunk from Cymon."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

    session      = commons.create_session()
    splunk_table = []

    for provided_ioc in provided_iocs:
        provided_ioc = commons.deobfuscate_url(provided_ioc)

        if validators.ipv4(provided_ioc):
            ioc_type = "ip"
        elif validators.domain(provided_ioc):
            ioc_type = "domain"
        elif validators.md5(provided_ioc):
            ioc_type = "md5"
        elif validators.sha256(provided_ioc):
            ioc_type = "sha256"
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        ioc_dicts = query_cymon(ioc_type, session, provided_ioc)

        if isinstance(ioc_dicts, dict):
            splunk_table.append(ioc_dicts)
            continue

        for ioc_dict in ioc_dicts:
            ioc_dict = commons.lower_keys(ioc_dict)
            splunk_table.append(ioc_dict)

    session.close()
    return splunk_table

def query_cymon(ioc_type, session, provided_ioc):
    """ """
    ioc_list = []
    base_url = "https://api.cymon.io/v2/ioc/search/{}/{}"
    resp     = session.get(base_url.format(ioc_type, provided_ioc))

    if resp.status_code == 200 and len(resp.json()["hits"]) > 0:
        hits = resp.json()["hits"]
    else:
        return {"no data": provided_ioc}

    for hit in hits:
        ioc_list.append(build_dict(hit))
    return ioc_list

def build_dict(hit):
    """Return a dictionary without nested parts."""
    ioc_dict = {}

    for key, value in hit.iteritems():
        if isinstance(value, list):
            ioc_dict[key] = "|".join(value)
        elif isinstance(value, str) or isinstance(value, unicode):
            ioc_dict[key] = value
        elif isinstance(value, dict):
            for k, v in value.iteritems():
                if isinstance(v, dict):
                    ioc_dict.update(v)
                else:
                    ioc_dict[k] = v
    return ioc_dict

if __name__ == "__main__":
    current_module = sys.modules[__name__]
    commons.return_results(current_module)
