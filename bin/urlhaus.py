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

app_home   = "{}/etc/apps/OSweep".format(os.environ['SPLUNK_HOME'])
tp_modules = "{}/bin/_tp_modules".format(app_home)
sys.path.insert(0, tp_modules)
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

    session       = commons.create_session()
    empty_files   = ["d41d8cd98f00b204e9800998ecf8427e",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    urlhaus_match = re.compile(r"^h..ps?:\/\/urlhaus\.abuse\.ch")
    splunk_table  = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = commons.deobfuscate_string(provided_ioc)

        if provided_ioc in empty_files:
            splunk_table.append({"invalid": provided_ioc})
            continue

        if urlhaus_match.match(provided_ioc):
            splunk_table.append({"invalid": provided_ioc})
            continue

        if validators.domain(provided_ioc) or validators.ipv4(provided_ioc):
            ioc_type = "host"
        elif validators.url(provided_ioc):
            ioc_type = "url"
        elif re.match("^[a-f\d]{32}$", provided_ioc):
            ioc_type = "md5_hash"
        elif re.match("^[a-f\d]{64}$", provided_ioc):
            ioc_type = "sha256_hash"
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        ioc_dicts = query_urlhaus(session, provided_ioc, ioc_type)
        
        for ioc_dict in ioc_dicts:
            ioc_dict = commons.lower_keys(ioc_dict)
            splunk_table.append(ioc_dict)

    session.close()
    return splunk_table

def query_urlhaus(session, provided_ioc, ioc_type):
    """ """
    uri_dir = ioc_type
    if ioc_type in ["md5_hash", "sha256_hash"]:
        uri_dir = "payload"    

    api  = "https://urlhaus-api.abuse.ch/v1/{}/"
    resp = session.post(api.format(uri_dir), timeout=180, data={ioc_type: provided_ioc})
    ioc_dicts = []

    if resp.status_code == 200 and resp.text != "":
        resp_content = resp.json()

        if ioc_type == "host":
            if "urls" not in resp_content.keys() or len(resp_content["urls"]) == 0:
                ioc_dicts.append({"no data": provided_ioc})
                return ioc_dicts

            for url in resp_content["urls"]:
                ioc_dict = {
                    "provided_ioc": provided_ioc,
                    "host": resp_content.get("host", None),
                    "firstseen (host)": resp_content.get("firstseen", None),
                    "urlhaus_reference (host)": resp_content.get("urlhaus_reference", None),
                    "url": url.get("url", None),
                    "url_status": url.get("url_status", None),
                    "date_added (url)": url.get("date_added", None),
                    "urlhaus_reference (url)": url.get("urlhaus_reference", None)
                }

                if url["tags"] != None:
                    ioc_dict.update({
                        "tags (url)": ",".join(url.get("tags", None))
                    })

                ioc_dicts.append(ioc_dict)
        elif ioc_type == "url":
            if "payloads" not in resp_content.keys() or len(resp_content["payloads"]) == 0:
                ioc_dicts.append({"invalid": provided_ioc})
                return ioc_dicts

            for payload in resp_content["payloads"]:
                ioc_dict = {
                    "provided_ioc": provided_ioc,
                    "host": resp_content.get("host", None),
                    "url": resp_content.get("url", None),
                    "url_status": resp_content.get("url_status", None),
                    "date_added (url)": resp_content.get("date_added", None),
                    "urlhaus_reference (url)": resp_content.get("urlhaus_reference", None),
                    "filename (payload)": payload.get("filename", None),
                    "content_type (payload)": payload.get("content_type", None),
                    "response_size (payload)": payload.get("response_size", None),
                    "md5_hash (payload)": payload.get("response_md5", None),
                    "sha256_hash (payload)": payload.get("response_sha256", None),
                    "firstseen (payload)": payload.get("firstseen", None),
                    "signature (payload)": payload.get("signature", None)
                }

                if resp_content["tags"] != None:
                    ioc_dict.update({
                        "tags (url)": ",".join(resp_content.get("tags", None))
                    })

                if payload["virustotal"] != None:
                    ioc_dict.update({
                        "vt_result (payload)": payload["virustotal"].get("result", None),
                        "vt_link (payload)": payload["virustotal"].get("link", None)
                    })

                ioc_dicts.append(ioc_dict)
        elif ioc_type in ["md5_hash", "sha256_hash"]:
            if len(resp_content["urls"]) == 0:
                ioc_dicts.append({"invalid": provided_ioc})
                return ioc_dicts

            for url in resp_content["urls"]:
                ioc_dict = {
                    "provided_ioc": provided_ioc,
                    "content_type (payload)": resp_content.get("content_type", None),
                    "file_size (payload)": resp_content.get("file_size", None),
                    "md5_hash (payload)": resp_content.get("md5_hash", None),
                    "sha256_hash (payload)": resp_content.get("sha256_hash", None),
                    "firstseen (payload)": resp_content.get("firstseen", None),
                    "lastseen (payload)": resp_content.get("lastseen", None),
                    "signature (payload)": resp_content.get("signature", None),
                    "url": url.get("url", None),
                    "url_status": url.get("url_status", None),
                    "filename (url)": url.get("filename", None),
                    "firstseen (url)": url.get("firstseen", None),
                    "lastseen (url)": url.get("lastseen", None),
                    "urlhaus_reference (url)": url.get("urlhaus_reference", None)
                }

                if resp_content["virustotal"] != None:
                    ioc_dict.update({
                        "vt_result (payload)": resp_content["virustotal"].get("result", None),
                        "vt_link (payload)": resp_content["virustotal"].get("link", None)
                    })
                ioc_dicts.append(ioc_dict)
        return ioc_dicts
    return [{"invalid": provided_ioc}]

if __name__ == "__main__":
    if sys.argv[1].lower() == "feed":
        data_feed   = get_feed()
        lookup_path = "{}/lookups".format(app_home)
        file_path   = "{}/urlhaus_url_feed.csv".format(lookup_path)

        write_file(data_feed, file_path)
        exit(0)

    current_module = sys.modules[__name__]
    commons.return_results(current_module)
