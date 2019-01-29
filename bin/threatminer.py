#!/usr/bin/python
"""
Author: Javier Bautista Rosell
Date: 15/01/2019

Modified by: ecstatic-nobel
Date: 2019/01/16
"""

import json
import os
import re
import sys

script_path  =  os.path.dirname(os.path.realpath(__file__))+ "/_tp_modules"
sys.path.insert(0, script_path)
import requests
import validators


threatminer = "https://api.threatminer.org/v2/{}.php?rt={}&q={}"

def process_iocs():
    provided_iocs = sys.argv[1:]
    splunk_table  = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.lower()

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

        if script_type == "catchall":
            splunk_table.append(catchall(provided_ioc))
        else:
            splunk_table.append(check_ioc(provided_ioc, script_type))
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
        resp = requests.get(threatminer.format(script_type, flag, provided_ioc))

        if resp.status_code != 200:
            continue

        results = resp.json()["results"]

        if len(results) == 0:
            continue

        dict_value = dict_info.keys()[flag]
        dict_info[dict_value] = results
    return dict_info

if __name__ == '__main__':
    splunk_table = process_iocs()
    print(json.dumps(splunk_table))
