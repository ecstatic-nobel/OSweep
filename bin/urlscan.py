#!/opt/splunk/bin/python
"""
Description: Use urlscan.io to get a look at what a particular website is 
requesting in the background. The script accepts a list of strings (domain, IP, 
and/or SHA256):
    | urlscanio $ioc$

or input from the pipeline (any field where the value is a domain, IP, and/or 
SHA256). The first argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | urlscanio <IOC_FIELD>

Source: https://urlscan.io/about-api/, https://github.com/ninoseki/miteru

Instructions:
1. Switch to the urlscan.io dashboard in the OSweep app.
2. Add the list of IOCs to the "Domain, IP, SHA256 (+)" textbox.
3. Select whether the results will be grouped and how from the dropdowns.
4. Click "Submit".

Rate Limit: None

Results Limit: 10k

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

from datetime import datetime
from datetime import timedelta
import os
import sys

app_home   = "{}/etc/apps/osweep".format(os.environ['SPLUNK_HOME'])
tp_modules = "{}/bin/_tp_modules".format(app_home)
sys.path.insert(0, tp_modules)
import validators

import commons
import urlscan_file_search as usfs


def process_iocs(results):
    """Return data formatted for Splunk from urlscan.io."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    elif sys.argv[1] in usfs.queries.keys():
        if len(sys.argv[1:]) < 3:
            return [{"error": "3 positional args needed. {} given.".format(str(len(sys.argv[1:])))}]
        provided_iocs = sys.argv[3:]
    else:
        provided_iocs = sys.argv[1:]

    session      = commons.create_session()
    splunk_table = []        

    for provided_ioc in set(provided_iocs):
        provided_ioc = commons.deobfuscate_url(provided_ioc)

        if provided_ioc == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
            splunk_table.append({"no data": provided_ioc})
            continue

        if provided_ioc.lower() in usfs.extensions.keys():
            ioc_dicts = query_urlscan_file(session, provided_ioc)
        elif validators.domain(provided_ioc) or validators.ipv4(provided_ioc) or \
           validators.sha256(provided_ioc) or "certstream-suspicious" in provided_ioc:
            ioc_dicts = query_urlscan(session, provided_ioc)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        for ioc_dict in ioc_dicts:
            splunk_table.append(ioc_dict)

    session.close()
    return splunk_table

def query_urlscan_file(session, provided_ioc):
    """Return data from urlscan about a particular file type."""
    qtype = sys.argv[1].lower()
    ext   = provided_ioc.lower()
    today = datetime.now()

    try:
        delta = int(sys.argv[2])
    except ValueError as err:
        return [{"invalid": err}]

    try:
        timespan = datetime.strftime(today - timedelta(delta),
                                     "%a, %d %b %Y 05:00:00")
    except ValueError as err:
        return [{"invalid": err}]

    timespan  = datetime.strptime(timespan, "%a, %d %b %Y %H:%M:%S")
    api       = "https://urlscan.io/api/v1/search/?q={}%20AND%20filename:.{}&size=10000"
    resp      = session.get(api.format(usfs.queries[qtype], ext), timeout=180)
    ioc_dicts = []

    if resp.status_code == 200 and "results" in resp.json().keys() and \
       len(resp.json()["results"]) > 0:
        results = resp.json()["results"]

        for result in results:
            if "files" not in result.keys():
                continue

            analysis_time = datetime.strptime(result["task"]["time"],
                                              "%Y-%m-%dT%H:%M:%S.%fZ")

            if analysis_time < timespan:
                break

            for payload in result["files"]:
                if result["page"]["url"].endswith(ext) or \
                   payload["mimeType"].startswith(usfs.extensions[ext]):
                    ioc_dict = {}
                    ioc_dict["analysis time"] = result["task"]["time"]
                    ioc_dict["url"]           = result["page"]["url"]
                    ioc_dict["domain"]        = result["page"]["domain"]
                    ioc_dict["ip"]            = result["page"]["ip"]
                    ioc_dict["country"]       = result["page"]["country"]
                    ioc_dict["filename"]      = payload["filename"]
                    ioc_dict["mimetype"]      = payload["mimeType"]
                    ioc_dict["sha256"]        = payload["sha256"]
                    ioc_dicts.append(ioc_dict)
    
    if len(ioc_dicts) == 0:
        return [{"no data": "{}, {}, {}".format(qtype, delta, ext)}]
    return ioc_dicts

def query_urlscan(session, provided_ioc):
    """Return data from urlscan about the provided IOC."""
    query_type = sys.argv[1]
    api    = "https://urlscan.io/api/v1/search/?size=10000&q="
    resp   = session.get("{}{}".format(api, provided_ioc), timeout=180)

    if resp.status_code == 200 and "results" in resp.json().keys() and \
       len(resp.json()["results"]) > 0:
        results = resp.json()["results"]
        return rename_dicts(results, provided_ioc)
    return [{"no data": provided_ioc}]

def rename_dicts(results, provided_ioc):
    """Rename the keys in of the returned dictionaries from urlscan.io API."""
    ioc_dicts = []

    for result in results:
        page = result.get("page", "")

        if "task" in result.keys() and "time" in result["task"].keys():
            page["analysis time"] = result["task"]["time"]
        else:
            ioc_dicts.append({"no data": provided_ioc})
            continue

        files = result.get("files", "")

        if files == "":
            download = {}
            download["filename"] = ""
            download["filesize"] = ""
            download["mimetype"] = ""
            download["sha256"]   = ""
            ioc_dict = commons.merge_dict(page, download)
            ioc_dicts.append(ioc_dict)
        else:
            for download in files:
                ioc_dict = commons.merge_dict(page, download)
                ioc_dicts.append(ioc_dict)
    return ioc_dicts

if __name__ == "__main__":
    current_module = sys.modules[__name__]
    commons.return_results(current_module)
