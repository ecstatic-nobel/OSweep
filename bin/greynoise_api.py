#!/opt/splunk/bin/python
"""
Use GreyNoise to analyze data on Internet-wide scanners (benign scanners such as 
Shodan.io and malicious actors like SSH and telnet worms).
"""

from collections import OrderedDict
import os
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import requests
import validators


api         = "https://api.greynoise.io/v1/query"
uagent      = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

def get_feed():
    """Return the latest report summaries from the feed."""
    tags = query_list()

    if len(tags) == 0:
        return
    return query_tags(tags)

def query_list():
    """Return a list of tags."""
    resp = requests.get("{}/list".format(api), headers={"User-Agent": uagent})

    if resp.status_code == 200 and "tags" in resp.json().keys():
        return resp.json()["tags"]
    return []

def query_tags(tags):
    """Return dictionaries containing information about a tag."""
    session = requests.Session()
    session.headers.update({"User-Agent": uagent})
    data_feed = []

    for tag in tags:
        resp = session.post("{}/tag".format(api), data={"tag": tag})

        if resp.status_code == 200 and "records" in resp.json().keys() and \
           len(resp.json()["records"]):
            records = resp.json()["records"]

            for record in records:
                record["datacenter"]  = record["metadata"].get("datacenter", "")
                record["tor"]         = str(record["metadata"].get("tor", ""))
                record["rdns_parent"] = record["metadata"].get("rdns_parent", "")
                record["link"]        = record["metadata"].get("link", "")
                record["org"]         = record["metadata"].get("org", "")
                record["os"]          = record["metadata"].get("os", "")
                record["asn"]         = record["metadata"].get("asn", "")
                record["rdns"]        = record["metadata"].get("rdns", "")
                record.pop("metadata")
                data_feed.append(record)

    session.close()
    return data_feed

def write_file(data_feed, file_path):
    """Write data to a file."""
    with open(file_path, "w") as open_file:
        keys   = data_feed[0].keys()
        header = ",".join(keys)

        open_file.write("{}\n".format(header))

        for data in data_feed:
            data_string = "^^".join(data.values())
            data_string = data_string.replace(",", "")
            data_string = data_string.replace("^^", ",")
            data_string = data_string.replace('"', "")
            open_file.write("{}\n".format(data_string.encode("UTF-8")))
    return

def process_iocs(provided_iocs):
    """Return data formatted for Splunk from GreyNoise."""
    splunk_table = []
    lookup_path  = "/opt/splunk/etc/apps/osweep/lookups"
    open_file    = open("{}/greynoise_feed.csv".format(lookup_path), "r")
    data_feed    = open_file.read().splitlines()
    header       = data_feed[0].split(",")
    open_file.close()

    open_file = open("{}/greynoise_scanners.csv".format(lookup_path), "r")
    scanners  = set(open_file.read().splitlines()[1:])
    scanners  = [x.lower() for x in scanners]
    open_file.close()

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace("[.]", ".")
        provided_ioc = provided_ioc.replace("[d]", ".")
        provided_ioc = provided_ioc.replace("[D]", ".")

        if not validators.ipv4(provided_ioc) and \
           not validators.domain(provided_ioc) and \
           provided_ioc.lower() not in scanners:
           splunk_table.append({"invalid": provided_ioc})
           continue

        line_found = False

        for line in data_feed:
            if provided_ioc.lower() in line.lower():
                line_found   = True
                scanner_data = line.split(",")
                scanner_dict = OrderedDict(zip(header, scanner_data))
                scanner_dict = lower_keys(scanner_dict)
                splunk_table.append(scanner_dict)
        
        if line_found == False:
            splunk_table.append({"no data": provided_ioc})
    return splunk_table

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
