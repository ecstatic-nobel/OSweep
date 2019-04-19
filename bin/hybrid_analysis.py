#!/opt/splunk/bin/python
"""
Description: Use Malshare to gather hashes of potentially malicious files. The 
script accepts a list of strings (domains, IPs, MD5, or SHA256):
    | malshare $ioc$

or input from the pipeline (any field where the value is a domain, IP, MD5 or 
SHA256). The first argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | malshare <IOC_FIELD>

Source: https://malshare.com/

Instructions:
1. Switch to the Hybrid Analysis dashboard in the OSweep app.
2. Add the list of IOCs to the "Domain, IP, MD5, SHA256 (+)" textbox.
4. Click "Submit".

Rate Limit: None

Results Limit: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import os
import re
import sys

app_home   = "{}/etc/apps/OSweep".format(os.environ['SPLUNK_HOME'])
tp_modules = "{}/bin/_tp_modules".format(app_home)
sys.path.insert(0, tp_modules)
import validators

import commons


api = "https://www.hybrid-analysis.com/api/v2/search/{}".lower()

def process_iocs(results):
    """Return data formatted for Splunk from Hybrid-Analysis."""
    params = [
        'authentihash', 
        'av_detect', 
        'context', 
        'country', 
        'domain', 
        'env_id', 
        'filename', 
        'filetype_desc', 
        'filetype', 
        'hash', 
        'host', 
        'imp_hash', 
        'port', 
        'similar_to', 
        'ssdeep', 
        'tag', 
        'url', 
        'verdict', 
        'vx_family'
    ]

    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    elif sys.argv[1] == "terms" and sys.argv[2] in params:
        if len(sys.argv) > 2:
            endpoint = sys.argv[1]
            param = sys.argv[2]
            provided_iocs = sys.argv[3:]
    elif sys.argv[1] == "hash" and sys.argv[2] == "hash":
        if len(sys.argv) > 2:
            endpoint = sys.argv[1]
            param = sys.argv[2]
            provided_iocs = sys.argv[3:]

    session = commons.create_session()
    api_key = commons.get_apikey("hybrid-analysis")
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = commons.deobfuscate_string(provided_ioc)
        provided_ioc = provided_ioc.lower()

        ioc_dicts = query_hybridanalysis(endpoint, param, provided_ioc, api_key, session)

        for ioc_dict in ioc_dicts:
            splunk_table.append(ioc_dict)

    session.close()
    return splunk_table

def query_hybridanalysis(endpoint, param, provided_ioc, api_key, session):
    """ """
    ioc_dicts = []

    session.headers.update({
        "api-key":api_key,
        "Accept":"application/json", 
        "User-Agent":"Falcon Sandbox"
    })
    resp = session.post(api.format(endpoint), data={param:provided_ioc}, timeout=180)

    if resp.status_code == 200 and resp.content != '':
        results = resp.json()
    else:
        ioc_dicts.append({"no data": provided_ioc})
        return ioc_dicts

    if isinstance(results, dict):
        if "result" in results.keys() and len(results["result"]) > 0:
            results = results["result"]
        else:
            ioc_dicts.append({"no data": provided_ioc})
            return ioc_dicts

    for result in results:
        ioc_dict = {}
        ioc_dict["type"] = result.get("type", None)
        ioc_dict["target_url"] = result.get("target_url", None)
        ioc_dict["submit_name"] = result.get("submit_name", None)
        ioc_dict["md5"] = result.get("md5", None)
        ioc_dict["sha256"] = result.get("sha256", None)
        ioc_dict["ssdeep"] = result.get("ssdeep", None)
        ioc_dict["imphash"] = result.get("imphash", None)
        ioc_dict["av_detect"] = result.get("av_detect", None)
        ioc_dict["analysis_start_time"] = result.get("analysis_start_time", None)
        ioc_dict["threat_score"] = result.get("threat_score", None)
        ioc_dict["interesting"] = result.get("interesting", None)
        ioc_dict["threat_level"] = result.get("threat_level", None)
        ioc_dict["verdict"] = result.get("verdict", None)
        ioc_dict["domains"] = result.get("domains", None)
        if ioc_dict["domains"] != None:
            ioc_dict["domains"] = "\n".join(ioc_dict["domains"])
        ioc_dict["classification_tags"] = result.get("classification_tags", None)
        if ioc_dict["classification_tags"] != None:
            ioc_dict["classification_tags"] = "\n".join(ioc_dict["classification_tags"])
        ioc_dict["compromised_hosts"]   = result.get("compromised_hosts", None)
        if ioc_dict["compromised_hosts"] != None:
            ioc_dict["compromised_hosts"] = "\n".join(ioc_dict["compromised_hosts"])
        ioc_dict["hosts"] = result.get("hosts", None)
        if ioc_dict["hosts"] != None:
            ioc_dict["hosts"] = "\n".join(ioc_dict["hosts"])
        ioc_dict["total_network_connections"] = result.get("total_network_connections", None)
        ioc_dict["total_processes"] = result.get("total_processes", None)
        ioc_dict["extracted_files"] = result.get("extracted_files", None)
        if ioc_dict["extracted_files"] != None:
            ioc_dict["extracted_files"] = "\n".join(ioc_dict["extracted_files"])
        ioc_dict["processes"] = result.get("processes", None)
        if ioc_dict["processes"] != None:
            ioc_dict["processes"] = "\n".join(ioc_dict["processes"])
        ioc_dict["tags"] = result.get("tags", None)
        if ioc_dict["tags"] != None:
            ioc_dict["tags"] = "\n".join(ioc_dict["tags"])
        ioc_dicts.append(ioc_dict)
    return ioc_dicts

if __name__ == "__main__":
    current_module = sys.modules[__name__]
    commons.return_results(current_module)
