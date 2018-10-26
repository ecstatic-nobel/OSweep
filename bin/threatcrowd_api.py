#!/opt/splunk/bin/python
"""
Use ThreatCrowd to quickly identify related infrastructure and malware.
"""

import os
import sys
from time import sleep

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import requests
import validators


api       = "http://www.threatcrowd.org/searchApi/v2/{}/report/?{}={}"
useragent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

def process_iocs(provided_iocs):
    """Return data formatted for Splunk from ThreatCrowd."""
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace("[.]", ".")
        provided_ioc = provided_ioc.replace("[d]", ".")
        provided_ioc = provided_ioc.replace("[D]", ".")

        if validators.ipv4(provided_ioc) or validators.domain(provided_ioc):
            ioc_dicts = process_host(provided_ioc)
        elif validators.email(provided_ioc):
            ioc_dicts = process_email(provided_ioc)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        for ioc_dict in ioc_dicts:
            splunk_table.append(ioc_dict)

        if len(provided_iocs) > 1:
            sleep(10)
    return splunk_table

def process_host(provided_ioc):
    """Pivot off an IP or domain and return data as an dictonary."""
    if validators.ipv4(provided_ioc):
        ioc_type = "ip"
    else:
        ioc_type = "domain"

    ioc_dicts = []
    resp      = requests.get(api.format(ioc_type, ioc_type, provided_ioc),
                            headers={"User-Agent": useragent})

    if resp.status_code == 200 and "permalink" in resp.json().keys() and \
       provided_ioc in resp.json()["permalink"]:
        for key in resp.json().keys():
            if key == "votes" or key == "permalink" or key == "response_code":
                pass
            elif key == "resolutions":
                for res in resp.json()[key]:
                    res = lower_keys(res)
                    ioc_dicts.append(res)
            else:
                for value in resp.json()[key]:
                    key = lower_keys(key)
                    ioc_dicts.append({key: value})
    else:
        ioc_dicts.append({"no data": provided_ioc})
    return ioc_dicts
    
def process_email(provided_ioc):
    """Pivot off an email and return data as an dictonary."""
    ioc_dicts = []

    resp = requests.get(api.format("email", "email", provided_ioc),
                        headers={"User-Agent": useragent})

    if resp.status_code == 200 and "permalink" in resp.json().keys() and \
       provided_ioc in resp.json()["permalink"]:
        for key in resp.json().keys():
            if key == "permalink" or key == "response_code":
                continue
            else:
                for value in resp.json()[key]:
                    key = lower_keys(key)
                    ioc_dicts.append({key: value})
    else:
        ioc_dicts.append({"no data": provided_ioc})
    return ioc_dicts

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
