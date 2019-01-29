#!/opt/splunk/bin/python
"""
Author: Javier Bautista Rosell
Date: 15/01/2019

---

Modified by: ecstatic-nobel
Date: 2019/01/16

---

Description: Use ThreatMiner to carry out tasks, from reading reports to pivoting 
and data enrichment. The script accepts a list of strings (domains, IPs, hashes
(MD5, SHA256, Imp, SSdeep, SSL), email addresses, APT group names, malware names):
    | threatminer <IOCs>

or input from the pipeline (any field where the value is a domain, IP, and/or 
email address). The first argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | threatminer <IOC_FIELD>

Output: List of dictionaries

Source: https://www.threatminer.org

Instructions:
1. Switch to the ThreatMiner dashboard in the OSweep app.
2. Add the list of IOCs to the "IOC (+)" textbox.
3. Select the IOC type.
4. Click "Submit".

Rate Limit: 10 requests/m

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import json
import os
import re
import sys
from time import sleep

script_path  =  os.path.dirname(os.path.realpath(__file__))+ "/_tp_modules"
sys.path.insert(0, script_path)
sys.path.insert(0, tp_modules)
import validators

import commons


api = "https://api.threatminer.org/v2/{}.php?rt={}&q={}"

def process_iocs(results):
    """ """
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

    session = commons.create_session()
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = commons.deobfuscate_url(provided_ioc)

        if validators.domain(provided_ioc):
            script_type = "domain"
        elif validators.email(provided_ioc):
            script_type = "email"
        elif validators.ipv4(provided_ioc):
            script_type = "host"
        elif re.match("^[a-f\d]{32}$", provided_ioc) or re.match("^[a-f\d]{64}$", provided_ioc):
            script_type = "sample"
        else:
            script_type = "catchall"

        try:
            if script_type == "catchall":
                splunk_table.append(catchall(provided_ioc))
            else:
                splunk_table.append(check_ioc(provided_ioc, script_type))
        except:
            splunk_table.append({"invalid": provided_ioc})
            continue

        if len(provided_iocs) > 1:
            sleep(6)

    session.close()
    return splunk_table

def catchall(provided_ioc):
    script_types = ["av", "imphash", "report", "reports", "ssdeep", "ssl"]
    splunk_table = {"initial": provided_ioc}

    for script_type in script_types:
        splunk_table.update(check_ioc(provided_ioc, script_type))
    return splunk_table

def check_ioc(provided_ioc, script_type):
    initial = {"initial": provided_ioc}
    tm_dict = threatminer_dict(script_type)
    results = return_results(tm_dict, script_type, provided_ioc)
    results.update(initial)
    return results

def threatminer_dict(option):
    options = {
        "av" : {
            "samples" : "-"
        },
        "domain" : {
            "whois"           : "-",
            "passive_dns"     : "-",
            "query_uri"       : "-",
            "related_samples" : "-",
            "subdomains"      : "-",
            "report_tagging"  : "-"
        },
        "email" : {
            "domains" : "-"
        },
        "host" : {
            "whois"            : "-",
            "passive_dns"      : "-",
            "query_uri"        : "-",
            "related_samples"  : "-",
            "ssl_certificates" : "-"
        },
        "imphash" : {
            "samples" : "-"
        },
        "report" : {
            "domains"         : "-",
            "hosts"           : "-",
            "email_addresses" : "-",
            "samples"         : "-"
        },
        "reports" : {
            "text"        : "-",
            "rep_by_year" : "-"
        },
        "sample" : {
            "metadata"     : "-",
            "http_traffic" : "-",
            "hosts"        : "-",
            "mutants"      : "-"
        },
        "ssdeep" : {
            "samples" : "-"
        },
        "ssl" : {
            "hosts" : "-"
        }
    }
    return options[option]

def return_results(dict_info, script_type, provided_ioc):
    for flag in range(len(dict_info)):
        resp = requests.get(api.format(script_type, flag, provided_ioc))

        if resp.status_code != 200:
            continue

        results = resp.json()["results"]

        if len(results) == 0:
            continue

        dict_value = dict_info.keys()[flag]
        dict_info[dict_value] = results
    return dict_info

if __name__ == '__main__':
    current_module = sys.modules[__name__]
    commons.return_results(current_module)
