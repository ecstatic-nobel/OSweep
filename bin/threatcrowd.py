#!/opt/splunk/bin/python
"""
Description: Use ThreatCrowd to quickly identify related infrastructure and 
malware. The script accepts a list of strings (domains, IPs, or email addresses):
    | threatcrowd <IOCs>

or input from the pipeline (any field where the value is a domain, IP, and/or 
email address). The first argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | threatcrowd <IOC_FIELD>

Output: List of dictionaries

Source: https://www.threatcrowd.org/index.php

Instructions:
1. Switch to the ThreatCrowd dashboard in the OSweep app.
2. Add the list of IOCs to the "IP, Domain, or Email (+)" textbox.
3. Select the IOC type.
4. Click "Submit".

Rate Limit: 1 request/10s

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import os
import sys
from time import sleep

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import validators

import commons


api = "http://www.threatcrowd.org/searchApi/v2/{}/report/?{}={}"

def process_iocs(results):
    """Return data formatted for Splunk from ThreatCrowd."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

    session = commons.create_session()
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace("[.]", ".")
        provided_ioc = provided_ioc.replace("[d]", ".")
        provided_ioc = provided_ioc.replace("[D]", ".")

        if validators.ipv4(provided_ioc):
            ioc_type = "ip"
        elif validators.domain(provided_ioc):
            ioc_type = "domain"
        elif validators.email(provided_ioc):
            ioc_type = "email"

        if validators.ipv4(provided_ioc) or validators.domain(provided_ioc):
            ioc_dicts = query_threatcrowd(provided_ioc, ioc_type, session)
        elif validators.email(provided_ioc):
            ioc_dicts = query_threatcrowd(provided_ioc, ioc_type, session)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        for ioc_dict in ioc_dicts:
            splunk_table.append(ioc_dict)

        if len(provided_iocs) > 1:
            sleep(10)

    session.close()
    return splunk_table

def query_threatcrowd(provided_ioc, ioc_type, session):
    """Pivot off an IP or domain and return data as an dictonary."""
    ioc_dicts = []
    resp      = session.get(api.format(ioc_type, ioc_type, provided_ioc))

    if resp.status_code == 200 and "permalink" in resp.json().keys() and \
       provided_ioc in resp.json()["permalink"]:
        for key in resp.json().keys():
            if key == "votes" or key == "permalink" or key == "response_code":
                continue
            elif key == "resolutions":
                for res in resp.json()[key]:
                    res = commons.lower_keys(res)
                    ioc_dicts.append(res)
            else:
                for value in resp.json()[key]:
                    key = commons.lower_keys(key)
                    ioc_dicts.append({key: value})
    else:
        ioc_dicts.append({"no data": provided_ioc})
    return ioc_dicts

if __name__ == "__main__":
    current_module = sys.modules[__name__]
    commons.return_results(current_module)
