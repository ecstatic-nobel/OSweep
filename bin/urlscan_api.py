#!/opt/splunk/bin/python
"""
Use urlscan.io to pivot off an IOC and present in Splunk.
"""

import os
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import requests
import validators


def process_iocs(provided_iocs):
    """Return data formatted for Splunk from urlscan.io."""
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace("[.]", ".")
        provided_ioc = provided_ioc.replace("[d]", ".")
        provided_ioc = provided_ioc.replace("[D]", ".")

        if provided_ioc == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
            splunk_table.append({"no data": provided_ioc})

        if validators.domain(provided_ioc) or validators.ipv4(provided_ioc) or \
           validators.md5(provided_ioc) or validators.sha256(provided_ioc):
            ioc_dicts = query_urlscan(provided_ioc)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        for ioc_dict in ioc_dicts:
            splunk_table.append(ioc_dict)
    return splunk_table

def query_urlscan(provided_ioc):
    """ """
    api    = "https://urlscan.io/api/v1/search/?size=10000&q="
    uagent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
    resp   = requests.get("{}{}".format(api, provided_ioc),
                          headers={"User-Agent": uagent})

    if resp.status_code == 200 and "results" in resp.json().keys() and \
       len(resp.json()["results"]) > 0:
        results = resp.json()["results"]
        return rename_dicts(results)
    return {"no data": provided_ioc}

def rename_dicts(results):
    """Rename the keys in of the returned dictionaries from urlscan.io API."""
    ioc_dicts = []

    for result in results:
        page = result.get("page", "")

        if "task" in result.keys() and "time" in result["task"].keys():
            page["analysis time"] = result["task"]["time"]
        else:
            ioc_dicts.append({"no data": provided_ioc})
            continue

        files = result.get("files", "")

        if files == "":
            ioc_dict = merge_dict(page, {})
            ioc_dicts.append(ioc_dict)
        else:
            for download in files:
                ioc_dict = merge_dict(page, download)
                ioc_dicts.append(ioc_dict)
    return ioc_dicts

def merge_dict(page, download):
    """Return a dictionary containing both page and download data."""
    merged_dict = {}
    merged_dict.update(lower_keys(page))
    merged_dict.update(lower_keys(download))
    return merged_dict

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
