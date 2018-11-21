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

Source: https://urlscan.io/about-api/

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

import os
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import validators

import commons


def process_iocs(results):
    """Return data formatted for Splunk from urlscan.io."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

    session      = commons.create_session()
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = commons.deobfuscate_url(provided_ioc)

        if provided_ioc == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
            splunk_table.append({"no data": provided_ioc})

        if validators.domain(provided_ioc) or validators.ipv4(provided_ioc) or \
           validators.sha256(provided_ioc) or "certstream-suspicious" in provided_ioc:
            ioc_dicts = query_urlscan(session, provided_ioc)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        for ioc_dict in ioc_dicts:
            splunk_table.append(ioc_dict)

    session.close()
    return splunk_table

def query_urlscan(session, provided_ioc):
    """ """
    api    = "https://urlscan.io/api/v1/search/?size=10000&q="
    resp   = session.get("{}{}".format(api, provided_ioc))

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
