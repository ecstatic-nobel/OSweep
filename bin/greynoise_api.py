#!/opt/splunk/bin/python
"""
Use GreyNoise to analyze data on Internet-wide scanners (benign scanners such as 
Shodan.io and malicious actors like SSH and telnet worms).
"""

from collections import OrderedDict

import requests
import validators


api         = 'http://api.greynoise.io:8888/v1/query'
uagent      = 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'
lookup_path = '/opt/splunk/etc/apps/osweep/lookups'
file_path   = '{}/greynoise_feed.csv'.format(lookup_path)

def get_feed():
    """Return the latest report summaries from the feed."""
    tag_list  = query_list()
    return query_tags(tag_list)

def query_list():
    """ """
    resp = requests.get('{}/list'.format(api), headers={"User-Agent": uagent})

    if resp.status_code == 200:
        return resp.json()["tags"]

def query_tags(tags):
    """ """
    session = requests.Session()
    session.headers.update({"User-Agent": uagent})
    data_feed = []

    for tag in tags:
        resp = session.post('{}/tag'.format(api), data={"tag": tag})

        if resp.status_code == 200:
            records = resp.json()["records"]

            for record in records:
                tag_info = OrderedDict()
                tag_info["Category"]     = record.get("category", "")
                tag_info["Confidence"]   = record.get("confidence", "")
                tag_info["Last Updated"] = record.get("last_updated", "")
                tag_info["Name"]         = record.get("name", "")
                tag_info["IP"]           = record.get("ip", "")
                tag_info["Intention"]    = record.get("intention", "")
                tag_info["First Seen"]   = record.get("first_seen", "")
                tag_info["Datacenter"]   = record["metadata"].get("datacenter", "")
                tag_info["Tor"]          = str(record["metadata"].get("tor", ""))
                tag_info["RDNS Parent"]  = record["metadata"].get("rdns_parent", "")
                tag_info["Link"]         = record["metadata"].get("link", "")
                tag_info["Org"]          = record["metadata"].get("org", "")
                tag_info["OS"]           = record["metadata"].get("os", "")
                tag_info["ASN"]          = record["metadata"].get("asn", "")
                tag_info["RDNS"]         = record["metadata"].get("rdns", "")
                tag_info["Invalid"]      = ""
                data_feed.append(tag_info)

    session.close()
    return data_feed

def write_file(data_feed, file_path):
    """Write data to a file."""
    with open(file_path, 'w') as open_file:
        keys   = data_feed[0].keys()
        header = ','.join(keys)

        open_file.write('{}\n'.format(header))

        for data in data_feed:
            data_string = '^^'.join(data.values())
            data_string = data_string.replace(',', '')
            data_string = data_string.replace('^^', ',')
            data_string = data_string.replace('"', '')
            open_file.write('{}\n'.format(data_string.encode("UTF-8")))
    return

def process_iocs(provided_iocs):
    """Return data formatted for Splunk from GreyNoise."""
    splunk_table = []
    lookup_path  = '/opt/splunk/etc/apps/osweep/lookups'
    open_file    = open('{}/greynoise_feed.csv'.format(lookup_path), 'r')
    data_feed    = open_file.read().splitlines()
    open_file.close()

    open_file = open('{}/greynoise_scanners.csv'.format(lookup_path), 'r')
    scanners  = set(open_file.read().splitlines()[1:])
    scanners  = [x.lower() for x in scanners]
    open_file.close()

    for provided_ioc in set(provided_iocs):
        if not validators.ipv4(provided_ioc) and \
           not validators.domain(provided_ioc) and \
           provided_ioc.lower() not in scanners:
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
        "Category",
        "Confidence",
        "Last Updated",
        "Name",
        "IP",
        "Intention",
        "First Seen",
        "Datacenter",
        "Tor",
        "RDNS Parent",
        "Link",
        "Org",
        "OS",
        "ASN",
        "RDNS",
        "Invalid"
    ]
    splunk_values = line.split(',')
    splunk_values.append(None)
    return OrderedDict(zip(splunk_headers, splunk_values))

def invalid_dict(provided_ioc):
    """Return a dictionary for the invalid IOC."""
    invalid_ioc = {}
    invalid_ioc["Category"]     = ""
    invalid_ioc["Confidence"]   = ""
    invalid_ioc["Last Updated"] = ""
    invalid_ioc["Name"]         = ""
    invalid_ioc["IP"]           = ""
    invalid_ioc["Intention"]    = ""
    invalid_ioc["First Seen"]   = ""
    invalid_ioc["Datacenter"]   = ""
    invalid_ioc["Tor"]          = ""
    invalid_ioc["RDNS Parent"]  = ""
    invalid_ioc["Link"]         = ""
    invalid_ioc["Org"]          = ""
    invalid_ioc["OS"]           = ""
    invalid_ioc["ASN"]          = ""
    invalid_ioc["RDNS"]         = ""
    invalid_ioc["Invalid"]      = provided_ioc
    return invalid_ioc
