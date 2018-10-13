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
    """Return a list of matching strings."""
    lookup_path = '/opt/splunk/etc/apps/osweep/lookups'
    open_file   = open('{}/ransomware_tracker_feed.csv'.format(lookup_path), 'r')
    global data_feed
    data_feed   = open_file.read().splitlines()
    open_file.close()

    ioc_list = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace('hxxp', 'http')
        provided_ioc = provided_ioc.replace('hxtp', 'http')
        provided_ioc = provided_ioc.replace('[.]', '.')
        provided_ioc = provided_ioc.replace('[d]', '.')
        provided_ioc = provided_ioc.replace('[D]', '.')

        if len(provided_ioc) < 2:
            ioc_list.append('N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,{}'.format(provided_ioc))
            continue

        for line in data_feed:
            if provided_ioc.lower() in line.lower():
                ioc_list.append(line)
    return ioc_list

def create_dict(ioc_strs):
    """Return dictionary to feed to Splunk."""
    splunk_dicts   = []
    splunk_headers = [
        'Firstseen (UTC)',
        'Threat',
        'Malware',
        'Host',
        'URL',
        'Status',
        'Registrar',
        'IP Address(es)',
        'ASN(s)',
        'Country',
        'Invalid'
    ]

    for ioc_str in ioc_strs:
        splunk_values = ioc_str.replace('","', '^^').replace('"', '').split('^^')
        splunk_values.append('N/A')
        splunk_dicts.append(OrderedDict(zip(splunk_headers, splunk_values)))
    return splunk_dicts
