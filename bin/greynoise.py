#!/opt/splunk/bin/python
"""
Description: Use GreyNoise to analyze data on Internet-wide scanners (benign 
scanners such as Shodan.io and malicious actors like SSH and telnet worms). The 
script accepts a list of strings (domain, IP, and/or scanner name):
    | greyNoise <IOCs>

or input from the pipeline (any field where the value is a domain, IP, scanner 
name). The first argument is the name of one field:
    <search>
    | fields <FIELD>
    | greyNoise <FIELD>

Source: https://viz.greynoise.io/table

Instructions:
1. Manually download the data feed (one-time)  
```
| greyNoise feed
```
2. Switch to the **GreyNoise** dashboard in the OSweep app.  
3. Add the list of IOCs to the "Domain, IP, Scanner Name (+)" textbox.  
4. Select whether the results will be grouped and how from the dropdowns.  
5. Click "Submit". 

Rate Limit: None

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

from collections import OrderedDict
import os
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import validators

import commons


api = "https://api.greynoise.io/v1/query"

def get_feed():
    """Return the latest report summaries from the feed."""
    session = commons.create_session()
    api_key = commons.get_apikey("greynoise")
    tags    = query_list(session)

    if tags == None:
        return
    
    if api_key != None:
        session.params = {"key": api_key}
    return query_tags(tags, session)

def query_list(session):
    """Return a list of tags."""
    resp = session.get("{}/list".format(api))

    if resp.status_code == 200 and "tags" in resp.json().keys():
        return resp.json()["tags"]
    return

def query_tags(tags, session):
    """Return dictionaries containing information about a tag."""
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

    if len(data_feed) == 0:
        return
    return data_feed

def write_file(data_feed, file_path):
    """Write data to a file."""
    if data_feed == None:
        return

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

def process_iocs(results):
    """Return data formatted for Splunk from GreyNoise."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

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
        provided_ioc = commons.deobfuscate_url(provided_ioc)

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
                scanner_dict = commons.lower_keys(scanner_dict)
                splunk_table.append(scanner_dict)

        if line_found == False:
            splunk_table.append({"no data": provided_ioc})
    return splunk_table

if __name__ == "__main__":
    if sys.argv[1].lower() == "feed":
        data_feed    = get_feed()
        lookup_path  = "/opt/splunk/etc/apps/osweep/lookups"
        scanner_list = "{}/greynoise_scanners.csv".format(lookup_path)
        file_path    = "{}/greynoise_feed.csv".format(lookup_path)

        with open(scanner_list, "w") as sfile:
            sfile.write("scanner\n")

            scanners = []
            for data in data_feed:
                scanner = data["name"].encode("UTF-8")

                if scanner not in scanners:
                    sfile.write("{}\n".format(scanner.lower()))

        write_file(data_feed, file_path)
        exit(0)

    current_module = sys.modules[__name__]
    commons.return_results(current_module)
