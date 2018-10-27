#!/bin/usr/python
"""
Search open-source security reports about phishing, malware, botnets and other 
malicious activities. 
"""

import os
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import requests
import validators


def process_iocs(provided_iocs):
    """Return data formatted for Splunk from Cymon."""
    splunk_table = []

    for provided_ioc in provided_iocs:
        provided_ioc = provided_ioc.replace("[.]", ".")
        provided_ioc = provided_ioc.replace("[d]", ".")
        provided_ioc = provided_ioc.replace("[D]", ".")

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

        ioc_dicts = query_cymon(ioc_type, provided_ioc)

        if isinstance(ioc_dicts, dict):
            splunk_table.append(ioc_dicts)
            continue

        for ioc_dict in ioc_dicts:
            ioc_dict = lower_keys(ioc_dict)
            splunk_table.append(ioc_dict)
    return splunk_table

def query_cymon(ioc_type, provided_ioc):
    """ """
    ioc_list = []
    base_url = "https://api.cymon.io/v2/ioc/search/{}/{}"
    resp     = requests.get(base_url.format(ioc_type, provided_ioc))

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
