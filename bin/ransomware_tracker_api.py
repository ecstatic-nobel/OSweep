#!/opt/splunk/bin/python
"""
Use Ransomware Tracker to distinguish threats between ransomware botnet 
Command & Control servers (C&Cs), ransomware payment sites, and ransomware 
distribution sites.
"""

from collections import OrderedDict
import os
import re
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
from HTMLParser import HTMLParser
import requests
import validators


def get_feed():
    """Return the latest report summaries from the feed."""
    api    = "https://ransomwaretracker.abuse.ch/feeds/csv/"
    uagent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
    resp   = requests.get(api, headers={"User-Agent": uagent})

    if resp.status_code == 200 and resp.text != "":
        data    = resp.text.splitlines()
        data    = data[8:-1]
        data[0] = data[0][2:]
        header  = data[0].split(",")
        data_feed = []

        for line in data[1:]:
            line = line.replace('","', "^^")
            line = line.replace(",", " ")
            line = line.replace("^^", ",")
            line = line.replace('"', " ")
            ransomware_data = line.split(",")
            ransomware_dict = OrderedDict(zip(header, ransomware_data))
            data_feed.append(ransomware_dict)
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
    """Return data formatted for Splunk from Ransomware Tracker."""
    splunk_table = []
    lookup_path  = "/opt/splunk/etc/apps/osweep/lookups"
    open_file    = open("{}/ransomware_tracker_feed.csv".format(lookup_path), "r")
    data_feed    = open_file.read().splitlines()
    header       = data_feed[0].lower().split(",")
    open_file.close()

    open_file = open("{}/ransomware_tracker_malware.csv".format(lookup_path), "r")
    malware   = set(open_file.read().splitlines()[1:])
    malware   = [x.lower() for x in malware]
    open_file.close()

    open_file = open("{}/ransomware_tracker_threats.csv".format(lookup_path), "r")
    threats   = set(open_file.read().splitlines()[1:])
    threats   = [x.lower() for x in threats]
    open_file.close()

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace("htxp", "http")
        provided_ioc = provided_ioc.replace("hxtp", "http")
        provided_ioc = provided_ioc.replace("hxxp", "http")
        provided_ioc = provided_ioc.replace("[.]", ".")
        provided_ioc = provided_ioc.replace("[d]", ".")
        provided_ioc = provided_ioc.replace("[D]", ".")

        if not validators.domain(provided_ioc) and \
           not validators.ipv4(provided_ioc) and \
           not validators.url(provided_ioc) and \
           provided_ioc.lower() not in malware and \
           provided_ioc.lower() not in threats:
           splunk_table.append({"invalid": provided_ioc})
           continue

        line_found = False
        for line in data_feed:
            if provided_ioc.lower() in line.lower():
                line_found      = True
                ransomware_data = line.split(",")
                ransomware_dict = OrderedDict(zip(header, ransomware_data))
                splunk_table.append(ransomware_dict)
        
        if line_found == False:
            splunk_table.append({"no data": provided_ioc})
    return splunk_table
