#!/opt/splunk/bin/python
"""
Description: Use URLHaus to get insights, browse the URLhaus database and find 
most recent additions. The script accepts a list of strings (domain, IP, MD5, 
SHA256, and/or URL):
    | urlhaus <IOCs>

or input from the pipeline (any field where the value is a domain, MD5, SHA256, 
and/or URL). The first argument is the name of one field:
    <search>
    | fields <FIELD>
    | urlhaus <FIELD>

Source: https://urlhaus.abuse.ch/api/

Instructions:
1. Manually download URL dump (one-time)  
```
| urlhaus feed
```
2. Switch to the URLHaus dashboard in the OSweep app.
3. Add the list of IOCs to the "Domain, IP, MD5, SHA256, URL (+)" textbox.
4. Select whether the results will be grouped and how from the dropdowns.
5. Click "Submit".

Rate Limit: 1 request/2s

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

from collections import OrderedDict
import os
import re
import sys
import time

app_home   = "{}/etc/apps/osweep".format(os.environ['SPLUNK_HOME'])
tp_modules = "{}/bin/_tp_modules".format(app_home)
sys.path.insert(0, tp_modules)
from HTMLParser import HTMLParser
import validators

import commons


def get_feed():
    """Return the latest report summaries from the feed."""
    api     = "https://urlhaus.abuse.ch/downloads"
    session = commons.create_session()
    resp    = session.get("{}/csv/".format(api), timeout=180)
    session.close()

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
    """Return data formatted for Splunk from URLhaus."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

    session     = commons.create_session()
    lookup_path = "{}/lookups".format(app_home)
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

    empty_files   = ["d41d8cd98f00b204e9800998ecf8427e",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    urlhaus_match = re.compile(r"^h..ps?:\/\/urlhaus\.abuse\.ch")
    splunk_table  = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = commons.deobfuscate_url(provided_ioc)

        if provided_ioc in empty_files:
            splunk_table.append({"invalid": provided_ioc})
            continue

        if urlhaus_match.match(provided_ioc):
            splunk_table.append({"invalid": provided_ioc})
            continue

        if validators.url(provided_ioc) or validators.domain(provided_ioc) or \
           validators.ipv4(provided_ioc):
            analysis_dicts = get_analysis(provided_ioc)

            if isinstance(analysis_dicts, dict):
                splunk_table.append(analysis_dicts)
                continue

            ioc_dicts = get_payloads(analysis_dicts, session)
        elif validators.md5(provided_ioc) or validators.sha256(provided_ioc):
            ioc_dicts = get_urls(session, provided_ioc)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue
        
        for ioc_dict in ioc_dicts:
            ioc_dict = commons.lower_keys(ioc_dict)
            splunk_table.append(ioc_dict)

    session.close()
    return splunk_table

def get_analysis(provided_ioc):
    """Return a list of dicts from the URL dump that match the provided IOC."""
    analysis_dicts = []

    if provided_ioc.endswith("/"):
        provided_ioc = provided_ioc[:-1]

    ioc_found = False

    for ioc_dict in data_feed:
        ioc_csv = ",".join(ioc_dict.values())

        if provided_ioc.lower() in ioc_csv.lower():
            ioc_found = True
            ioc_dict["provided_ioc"] = provided_ioc
            analysis_dicts.append(ioc_dict)

    if ioc_found == False:
        return {"no data": provided_ioc}
    return analysis_dicts

def get_payloads(analysis_dicts, session):
    """Return a list of dicts from the URLHaus analysis page containing payloads
    found related to the URL in question."""
    ioc_dicts = []

    for analysis_dict in analysis_dicts:
        provided_ioc = analysis_dict["provided_ioc"]
        url          = analysis_dict["url"]
        urlhaus_link = analysis_dict["urlhaus_link"]
        resp         = session.get(urlhaus_link, timeout=180)

        if resp.status_code == 200:
            parser.reload()
            parser.feed(resp.text)
            parser.close()
        
        if len(parser.parsed_payloads) > 0:
            for payload in parser.parsed_payloads:
                analysis_dict["payload"] = payload
                ioc_dicts.append(analysis_dict)
        elif len([x for x in ioc_dicts if provided_ioc in " ".join(x.values())]) == 0:
            ioc_dicts.append({"no data": provided_ioc})

        time.sleep(2)
    return ioc_dicts

def get_urls(session, provided_ioc):
    """Return a list of dicts from the URLHaus Browse page containing URLs
    found related to the URL in question."""
    page       = 0
    uh_browser = "https://urlhaus.abuse.ch/browse.php?search="
    ioc_dicts  = []

    while True:
        browse_urlhaus(session, provided_ioc, page)

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
        time.sleep(2)
    return ioc_dicts

def browse_urlhaus(session, provided_ioc, page):
    """Request data from the URLHaus Browse page and feed to the HTML parser."""
    uh_browser = "https://urlhaus.abuse.ch/browse.php?search="
    resp       = session.get("{}{}&page={}".format(uh_browser,
                                                    provided_ioc,
                                                    page), timeout=180)
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

if __name__ == "__main__":
    if sys.argv[1].lower() == "feed":
        data_feed   = get_feed()
        lookup_path = "{}/lookups".format(app_home)
        file_path   = "{}/urlhaus_url_feed.csv".format(lookup_path)

        write_file(data_feed, file_path)
        exit(0)

    current_module = sys.modules[__name__]
    commons.return_results(current_module)
