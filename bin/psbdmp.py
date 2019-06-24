#!/opt/splunk/bin/python
"""
Description: Use crt.sh to discover certificates by searching all of the publicly 
known Certificate Transparency (CT) logs. The script accepts a list of strings 
(domains or IPs):
    | psbdmp search $string$

or input from the pipeline (any field where the value is a domain or IP). The 
first argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | psbdmp <IOC_FIELD>

Source: https://psbdmp.ws/api

Instructions:
1. Switch to the Certificate Search dashboard in the OSweep app.
2. Add the list of IOCs to the "Domain, IP (+)" textbox.
3. Select "Yes" or "No" from the "Wildcard" dropdown to search for subdomains.
4. Click "Submit".

Rate Limit: None

Results Limit: None

Notes: Search for subdomains by passing "wildcard" as the first argument:
    | psbdmp search $string$

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import json
import os
import sys

app_home   = "{}/etc/apps/OSweep".format(os.environ['SPLUNK_HOME'])
tp_modules = "{}/bin/_tp_modules".format(app_home)
sys.path.insert(0, tp_modules)
import validators

import commons


def process_iocs(results):
    """Return data formatted for Splunk from psbdmp."""
    if sys.argv[1] == "search" or sys.argv[1] == "dump":
        endpoint      = sys.argv[1]
        provided_iocs = sys.argv[2:]

    session      = commons.create_session()
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = commons.deobfuscate_string(provided_ioc)

        if endpoint == "search":
            psbdmp_dicts = psbdmp_search(provided_ioc, session)
        elif endpoint == "dump":
            psbdmp_dicts = psbdmp_dump(provided_ioc, session)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        for psbdmp_dict in psbdmp_dicts:
            splunk_table.append(psbdmp_dict)

    session.close()
    return splunk_table

def psbdmp_search(provided_ioc, session):
    """ """
    base_url  = "https://psbdmp.ws/api/search/{}"
    url       = base_url.format(provided_ioc)
    resp      = session.get(url, timeout=180)
    psd_dicts = []

    if resp.status_code == 200 and resp.json()["error"] != 1 and len(resp.json()["data"]) > 0:
        data = resp.json()["data"]

        for result in data:
            result = commons.lower_keys(result)
            result.update({"provided_ioc": provided_ioc})
            psd_dicts.append(result)
    else:
        psd_dicts.append({"no data": provided_ioc})
    return psd_dicts

def psbdmp_dump(provided_ioc, session):
    """ """
    # psbdmp.ws does not have an endpoint to the archive
    # base_url  = "https://psbdmp.ws/api/dump/get/{}"
    base_url  = "https://pastebin.com/raw/{}"
    url       = base_url.format(provided_ioc)
    resp      = session.get(url, timeout=180)
    psd_dicts = []

    # psbdmp.ws does not have an endpoint to the archive
    # if resp.status_code == 200 and resp.json()["error"] != 1:
    #     dump = resp.json()
    #     psd_dicts.append(dump)
    if resp.status_code == 200 and resp.content != "":
        dump = {"id":provided_ioc, "data":resp.content}
        psd_dicts.append(dump)
    else:
        psd_dicts.append({"no data": provided_ioc})
    return psd_dicts

if __name__ == "__main__":
    current_module = sys.modules[__name__]
    commons.return_results(current_module)
