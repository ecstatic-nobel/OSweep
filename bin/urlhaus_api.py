#!/opt/splunk/bin/python
"""
Use URLHaus to pivot off a list of IOCs (URL and/or payload) and present in 
Splunk.
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


uagent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

def get_feed():
    """Return the latest report summaries from the feed."""
    api  = "https://urlhaus.abuse.ch/downloads"
    resp = requests.get("{}/csv/".format(api),
                        headers={"User-Agent": uagent})

    if resp.status_code == 200 and resp.text != "":
        data    = resp.text.splitlines()
        data    = data[8:]
        data[0] = data[0][2:]
        header  = data[0].split(",")
        data_feed = []

        for line in data[1:]:
            line = line.replace('","', "^^")
            line = line.replace(",", " ")
            line = line.replace("^^", ",")
            line = line.replace('"', "")
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
    """Return data formatted for Splunk from URLhaus."""
    lookup_path = "/opt/splunk/etc/apps/osweep/lookups"
    open_file   = open("{}/urlhaus_url_feed.csv".format(lookup_path), "r")
    contents    = open_file.read().splitlines()
    open_file.close()

    header = contents[0].split(",")
    global data_feed
    data_feed = []

    for line in contents:
        line = line.split(",")
        ioc_dict = OrderedDict(zip(header, line))
        data_feed.append(ioc_dict)
    
    global parser
    parser = ParserHTML()

    empty_files  = ["d41d8cd98f00b204e9800998ecf8427e",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace("htxp", "http")
        provided_ioc = provided_ioc.replace("hxtp", "http")
        provided_ioc = provided_ioc.replace("hxxp", "http")
        provided_ioc = provided_ioc.replace("[.]", ".")
        provided_ioc = provided_ioc.replace("[d]", ".")
        provided_ioc = provided_ioc.replace("[D]", ".")

        if provided_ioc in empty_files:
            splunk_table.append({"invalid": provided_ioc})
            continue

        if validators.url(provided_ioc) or validators.domain(provided_ioc):
            analysis_dicts = get_analysis(provided_ioc)

            if isinstance(analysis_dicts, dict) or analysis_dicts == None:
                splunk_table.append({"invalid": provided_ioc})
                continue

            ioc_dicts = get_payloads(analysis_dicts)
        elif validators.md5(provided_ioc) or validators.sha256(provided_ioc):
            ioc_dicts = get_urls(provided_ioc)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue
        
        for ioc_dict in ioc_dicts:
            ioc_dict = lower_keys(ioc_dict)
            splunk_table.append(ioc_dict)
    return splunk_table

def get_analysis(provided_ioc):
    """Return a list of dicts from the URL dump that match the provided IOC."""
    urlhaus_match   = re.compile(r"^h..ps?:\/\/urlhaus\.abuse\.ch")
    analysis_dicts = []

    if provided_ioc.endswith("/"):
        provided_ioc = provided_ioc[:-1]

    if urlhaus_match.match(provided_ioc):
        return {"invalid": provided_ioc}
    
    ioc_found = False

    for ioc_dict in data_feed:
        ioc_csv = ",".join(ioc_dict.values())

        if provided_ioc.lower() in ioc_csv.lower():
            ioc_found    = True
            ioc_dict["provided_ioc"] = provided_ioc
            analysis_dicts.append(ioc_dict)

    if ioc_found == False:
        return {"no data": provided_ioc}
    return analysis_dicts

def get_payloads(analysis_dicts):
    """Return a list of dicts from the URLHaus analysis page containing payloads 
    found related to the URL in question."""
    ioc_dicts = []

    for analysis_dict in analysis_dicts:
        provided_ioc = analysis_dict["provided_ioc"]
        url          = analysis_dict["url"]
        urlhaus_link = analysis_dict["urlhaus_link"]
        resp         = requests.get(urlhaus_link, headers={"User-Agent": uagent})

        if resp.status_code == 200:
            parser.reload()
            parser.feed(resp.text)
            parser.close()
        
        if len(parser.parsed_payloads) > 0:
            for payload in parser.parsed_payloads:
                analysis_dict["payload"] = payload
                ioc_dicts.append(analysis_dict)
        else:
            ioc_dicts.append({"no data": provided_ioc})
    return ioc_dicts

def get_urls(provided_ioc):
    """Return a list of dicts from the URLHaus Browse page containing URLs 
    found related to the URL in question."""
    page       = 0
    uh_browser = "https://urlhaus.abuse.ch/browse.php?search="
    ioc_dicts   = []

    while True:
        browse_urlhaus(provided_ioc, page)

        if len(parser.parsed_urls) == 0 and page > 0:
            break

        if len(parser.parsed_urls) == 0 and page == 0:
            ioc_dicts.append({"no data": provided_ioc})
            break

        for parsed_url in parser.parsed_urls:
            ioc_dict = {}
            ioc_dict["id"] = None
            ioc_dict["dateadded"] = None
            ioc_dict["url_status"] = None
            ioc_dict["threat"] = None
            ioc_dict["tags"] = None
            ioc_dict["url"] = parsed_url
            ioc_dict["payload"] = provided_ioc
            ioc_dict["provided_ioc"] = provided_ioc
            ioc_dict["urlhaus_link"] = "{}{}".format(uh_browser, provided_ioc)
            ioc_dicts.append(ioc_dict)

        page += 1
    return ioc_dicts

def browse_urlhaus(provided_ioc, page):
    """Request data from the URLHaus Browse page and feed to the HTML parser."""
    uh_browser = "https://urlhaus.abuse.ch/browse.php?search="
    resp       = requests.get("{}{}&page={}".format(uh_browser,
                                                    provided_ioc,
                                                    page),
                              headers={"User-Agent": uagent})
    parser.reload()
            
    if resp.status_code == 200:
        if "Get more information about this malware URL" in resp.text:
            parser.feed(resp.text)
    return

class ParserHTML(HTMLParser):
    """HTML parser class"""
    url_match = re.compile(r"^https?:\/\/.+")

    def reload(self):
        """Empty the list of URLs and payloads."""
        self.parsed_urls     = []
        self.parsed_payloads = []
        return

    def handle_data(self, data):
        """Feed source code to parser and extract URLs and hashes."""
        if self.url_match.match(data):
            self.parsed_urls.append(data)

        if validators.sha256(data):
            self.parsed_payloads.append(data)
        return

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
