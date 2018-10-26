#!/opt/splunk/bin/python
"""
Use cybercrime-tracker.net to better understand the type of malware a site is 
hosting.
"""

import os
import re
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
from bs4 import BeautifulSoup
import requests
import validators


def process_iocs(provided_iocs):
    """Return data formatted for Splunk from CyberCrime Tracker."""
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace("[.]", ".")
        provided_ioc = provided_ioc.replace("[d]", ".")
        provided_ioc = provided_ioc.replace("[D]", ".")

        if validators.domain(provided_ioc):
            cct_dicts = query_cct(provided_ioc)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        for cct_dict in cct_dicts:
            splunk_table.append(cct_dict)
    return splunk_table

def query_cct(provided_ioc, offset=0, limit=10000):
    """Search cybercrime-tracker.net for specific information about panels."""
    api       = "http://cybercrime-tracker.net/index.php?search={}&s={}&m={}"
    vt_latest = "https://www.virustotal.com/latest-scan/http://{}"
    vt_ip     = "https://www.virustotal.com/en/ip-address/{}/information/"
    useragent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
    base_url  = api.format(provided_ioc, offset, limit)
    resp      = requests.get(url=base_url, headers={"User-Agent": useragent})
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
                    "vt latest scan": vt_latest.format(cells[1].text)
                }

                if tmp["ip"] != "":
                    tmp["vt ip info"] = vt_ip.format(tmp["ip"])

                if tmp not in cct_dicts:
                    cct_dicts.append(tmp)
    else:
        cct_dicts.append({"no data": provided_ioc})
    return cct_dicts
