#!/opt/splunk/bin/python
"""
Use ThreatCrowd to quickly identify related infrastructure and malware.
"""

import sys
from time import sleep

import requests
import validators


api = 'http://www.threatcrowd.org/searchApi/v2/{}/report/?{}={}'
useragent = 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'

def process_iocs(provided_iocs):
    """Return data formatted for Splunk from ThreatCrowd."""
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        if validators.ipv4(provided_ioc) or validators.domain(provided_ioc):
            threatcrowd_dicts = process_host(provided_ioc)
        elif validators.email(provided_ioc):
            threatcrowd_dicts = process_email(provided_ioc)
        else:
            splunk_table.append({"Invalid": provided_ioc})
            continue

        if len(threatcrowd_dicts) == 0:
            splunk_table.append({"Invalid": provided_ioc})
            continue

        for threatcrowd_dict in threatcrowd_dicts:
            splunk_table.append(threatcrowd_dict)

        if len(provided_iocs) > 1:
            sleep(10)
    return splunk_table

def process_host(provided_ioc):
    """Pivot off an IP or domain and return data as an dictonary."""
    if validators.ipv4(provided_ioc):
        ioc_type = "ip"
    else:
        ioc_type = "domain"

    ioc_dict = []
    resp     = requests.get(api.format(ioc_type, ioc_type, provided_ioc),
                            headers={"User-Agent": useragent})

    if resp.status_code == 200:
        for key in resp.json().keys():
            if key == "votes" or key == "permalink" or key == "response_code":
                pass
            elif key == "resolutions":
                if len(resp.json()[key]) == 0:
                    ioc_dict.append({key: ""})
                elif len(resp.json()[key]) > 0:
                    for res in resp.json()[key]:
                        ioc_dict.append(res)
            else:
                if len(resp.json()[key]) == 0:
                    ioc_dict.append({key: ""})
                else:
                    for value in resp.json()[key]:
                        ioc_dict.append({key: value})
    return ioc_dict
    
def process_email(provided_ioc):
    """Pivot off an email and return data as an dictonary."""
    ioc_dict = []

    resp = requests.get(api.format("email", "email", provided_ioc),
                        headers={"User-Agent": useragent})

    if resp.status_code == 200:
        for key in resp.json().keys():
            if key == "permalink" or key == "response_code":
                pass
            else:
                if len(resp.json()[key]) == 0:
                    ioc_dict.append({key: ""})
                else:
                    for value in resp.json()[key]:
                        ioc_dict.append({key: value})
    return ioc_dict
