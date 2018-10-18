#!/opt/splunk/bin/python
"""
Use Ransomware Tracker to distinguish threats between ransomware botnet 
Command & Control servers (C&Cs), ransomware payment sites, and ransomware 
distribution sites.
"""

from collections import OrderedDict
import re

from HTMLParser import HTMLParser
import requests
import validators


uagent = 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'

def get_feed():
    """Return the latest report summaries from the feed."""
    api  = 'https://ransomwaretracker.abuse.ch/feeds/csv/'
    resp = requests.get(api, headers={"User-Agent": uagent}).text
    return resp.splitlines()

def write_file(data_feed, file_path):
    """Write data to a file."""
    with open(file_path, 'w') as open_file:
        for line in data_feed:
            open_file.write('{}\n'.format(line))
    return

def process_iocs(provided_iocs):
    """Return data formatted for Splunk from Ransomware Tracker."""
    splunk_table = []
    lookup_path  = '/opt/splunk/etc/apps/osweep/lookups'
    open_file    = open('{}/ransomware_tracker_feed.csv'.format(lookup_path), 'r')
    data_feed    = open_file.read().splitlines()
    open_file.close()

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace('htxp', 'http')
        provided_ioc = provided_ioc.replace('hxtp', 'http')
        provided_ioc = provided_ioc.replace('hxxp', 'http')
        provided_ioc = provided_ioc.replace('[.]', '.')
        provided_ioc = provided_ioc.replace('[d]', '.')
        provided_ioc = provided_ioc.replace('[D]', '.')

        if len(provided_ioc) < 2:
            splunk_table.append(invalid_dict(provided_ioc))
            continue

        line_found = False
        for line in data_feed:
            if provided_ioc.lower() in line.lower():
                line_found = True
                splunk_table.append(create_dict(line))
        
        if line_found == False:
            splunk_table.append(invalid_dict(provided_ioc))
    return splunk_table

def create_dict(line):
    """Return an ordered dictionary."""
    splunk_headers = [
        "Firstseen (UTC)",
        "Threat",
        "Malware",
        "Host",
        "URL",
        "Status",
        "Registrar",
        "IP Address(es)",
        "ASN(s)",
        "Country",
        "Invalid"
    ]
    splunk_values = line.replace('","', '^^').replace('"', '').split('^^')
    splunk_values.append(None)
    return OrderedDict(zip(splunk_headers, splunk_values))

def invalid_dict(provided_ioc):
    """Return a dictionary for the invalid IOC."""
    invalid_ioc = {}
    invalid_ioc["Firstseen (UTC)"] = None
    invalid_ioc["Threat"]          = None
    invalid_ioc["Malware"]         = None
    invalid_ioc["Host"]            = None
    invalid_ioc["URL"]             = None
    invalid_ioc["Status"]          = None
    invalid_ioc["Registrar"]       = None
    invalid_ioc["IP Address(es)"]  = None
    invalid_ioc["ASN(s)"]          = None
    invalid_ioc["Country"]         = None
    invalid_ioc["Invalid"]         = provided_ioc
    return invalid_ioc
