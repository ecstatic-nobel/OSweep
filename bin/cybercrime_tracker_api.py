#!/opt/splunk/bin/python
"""
Use cybercrime-tracker.net to better understand the type of malware a site is 
hosting.
"""

from collections import OrderedDict
import os
import re
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
from bs4 import BeautifulSoup
import requests
import validators



uagent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

def get_feed():
    """Return the latest report summaries from the feed."""
    api  = "http://cybercrime-tracker.net/all.php"
    resp = requests.get(api, headers={"User-Agent": uagent})

    if resp.status_code == 200 and resp.text != "":
        data    = resp.text.splitlines()
        header  = "url"
        data_feed = []

        for line in data:
            data_feed.append({"url": line})
        return data_feed
    return

def write_file(data_feed, file_path):
    """Write data to a file."""
    with open(file_path, "w") as open_file:
        keys   = data_feed[0].keys()
        header = ",".join(keys)

        open_file.write("{}\n".format(header))

        for data in data_feed:
            data_string = ",".join(data.values())
            open_file.write("{}\n".format(data_string.encode("UTF-8")))
    return

def process_iocs(provided_iocs):
    """Return data formatted for Splunk from CyberCrime Tracker."""
    lookup_path = "/opt/splunk/etc/apps/osweep/lookups"
    open_file   = open("{}/cybercrime_tracker_feed.csv".format(lookup_path), "r")
    contents    = open_file.read().splitlines()
    open_file.close()
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace("[.]", ".")
        provided_ioc = provided_ioc.replace("[d]", ".")
        provided_ioc = provided_ioc.replace("[D]", ".")

        if provided_ioc not in contents:
            splunk_table.append({"no data": provided_ioc})
            continue

        if validators.domain(provided_ioc) or validators.ipv4(provided_ioc):
            cct_dicts = query_cct(provided_ioc)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        for cct_dict in cct_dicts:
            splunk_table.append(cct_dict)
    return splunk_table

def query_cct(provided_ioc):
    """Search cybercrime-tracker.net for specific information about panels."""
    api       = "http://cybercrime-tracker.net/index.php?search={}&s=0&m=10000"
    vt_latest = "https://www.virustotal.com/latest-scan/http://{}"
    vt_ip     = "https://www.virustotal.com/en/ip-address/{}/information/"
    base_url  = api.format(provided_ioc)
    resp      = requests.get(url=base_url, headers={"User-Agent": uagent})
    cct_dicts = []

    if resp.status_code == 200:
        soup  = BeautifulSoup(resp.content, "html.parser")
        table = soup.findAll("table", attrs={"class": "ExploitTable"})[0]
        rows  = table.find_all(["tr"])[1:]

        if len(rows) == 0:
            cct_dicts.append({"no data": provided_ioc})

        for row in rows:
            cells = row.find_all("td", limit=5)

            if len(cells) > 0:
                tmp = {
                    "date": cells[0].text,
                    "url": cells[1].text,
                    "ip": cells[2].text,
                    "type": cells[3].text,
                    "vt latest scan": vt_latest.format(cells[1].text),
                    "vt ip info": None
                }

                if tmp["ip"] != "":
                    tmp["vt ip info"] = vt_ip.format(tmp["ip"])

                if tmp not in cct_dicts:
                    cct_dicts.append(tmp)
    else:
        cct_dicts.append({"no data": provided_ioc})
    return cct_dicts
