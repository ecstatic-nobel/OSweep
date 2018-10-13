#!/opt/splunk/bin/python
"""
Use ThreatCrowd to quickly identify related infrastructure and malware.
"""

import sys

import requests
import validators


api = 'http://www.threatcrowd.org/searchApi/v2/{}/report/?{}={}'
useragent = 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'

def process_host(provided_ioc):
    """ """
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
    
def process_domain(provided_ioc):
    """ """
    ioc_type = "domain"
    ioc_dict = []

    resp = requests.get(api.format(ioc_type, ioc_type, provided_ioc),
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
    """ """
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
