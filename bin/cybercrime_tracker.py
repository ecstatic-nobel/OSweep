#!/opt/splunk/bin/python
"""
Description: Use cybercrime-tracker.net to better understand the type of malware 
a site is hosting. The script accepts a list of strings (domain or IP):
    | cybercrimeTracker <IOCs>

or input from the pipeline (any field where the value is a domain). The first 
argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | cybercrimeTracker <IOC_FIELD>

Source: https://github.com/PaulSec/cybercrime-tracker.net

Instructions:
1. Switch to the CyberCrime Tracker dashboard in the OSweep app.
2. Add the list of IOCs to the "Domain, IP (+)" textbox.
3. Select whether the results will be grouped and how from the dropdowns.
4. Click "Submit".

Rate Limit: None

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

from collections import OrderedDict
import os
import re
import sys

app_home   = "{}/etc/apps/osweep".format(os.environ['SPLUNK_HOME'])
tp_modules = "{}/bin/_tp_modules".format(app_home)
sys.path.insert(0, tp_modules)
from bs4 import BeautifulSoup
import validators

import commons


def get_feed():
    """Return OSINT data feed."""
    api     = "http://cybercrime-tracker.net/all.php"
    session = commons.create_session()
    resp    = session.get(api, timeout=180)
    session.close()

    if resp.status_code == 200 and resp.text != "":
        data      = resp.text.splitlines()
        header    = "url"
        data_feed = []

        for line in data:
            data_feed.append({"url": line})
        return data_feed
    return

def write_file(data_feed, file_path):
    """Write data to a file."""
    if data_feed == None:
        return

    with open(file_path, "w") as open_file:
        keys   = data_feed[0].keys()
        header = ",".join(keys)

        open_file.write("{}\n".format(header))

        for data in data_feed:
            data_string = ",".join(data.values())
            open_file.write("{}\n".format(data_string.encode("UTF-8")))
    return

def process_iocs(results):
    """Return data formatted for Splunk from CyberCrime Tracker."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

    session      = commons.create_session()
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = commons.deobfuscate_url(provided_ioc)

        if validators.domain(provided_ioc) or validators.ipv4(provided_ioc):
            cct_dicts = query_cct(provided_ioc, session)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        for cct_dict in cct_dicts:
            splunk_table.append(cct_dict)

    session.close()
    return splunk_table

def query_cct(provided_ioc, session):
    """Search cybercrime-tracker.net for specific information about panels."""
    api       = "http://cybercrime-tracker.net/index.php?search={}&s=0&m=10000"
    vt_latest = "https://www.virustotal.com/latest-scan/http://{}"
    vt_ip     = "https://www.virustotal.com/en/ip-address/{}/information/"
    base_url  = api.format(provided_ioc)
    resp      = session.get(base_url, timeout=180)
    cct_dicts = []

    if resp.status_code == 200:
        soup  = BeautifulSoup(resp.content, "html.parser")
        table = soup.findAll("table", attrs={"class": "ExploitTable"})[0]
        rows  = table.find_all(["tr"])[1:]

        if len(rows) == 0:
            cct_dicts.append({"no data": provided_ioc})
            return cct_dicts

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

if __name__ == "__main__":
    if sys.argv[1].lower() == "feed":
        data_feed   = get_feed()
        lookup_path = "{}/lookups".format(app_home)
        file_path   = "{}/cybercrime_tracker_feed.csv".format(lookup_path)
        write_file(data_feed, file_path)
        exit(0)

    current_module = sys.modules[__name__]
    commons.return_results(current_module)
