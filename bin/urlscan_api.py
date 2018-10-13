#!/opt/splunk/bin/python
"""
Use urlscan.io to pivot off an IOC and present in Splunk.
"""

import requests


def invalid_dict(provided_ioc):
    """Return a dictionary for the invalid IOC."""
    invalid_ioc = {}
    invalid_ioc["URL"]       = "N/A"
    invalid_ioc["Domain"]    = "N/A"
    invalid_ioc["IP"]        = "N/A"
    invalid_ioc["PTR"]       = "N/A"
    invalid_ioc["Server"]    = "N/A"
    invalid_ioc["City"]      = "N/A"
    invalid_ioc["Country"]   = "N/A"
    invalid_ioc["ASN"]       = "N/A"
    invalid_ioc["ASN Name"]  = "N/A"
    invalid_ioc["Filename"]  = "N/A"
    invalid_ioc["File Size"] = "N/A"
    invalid_ioc["SHA256"]    = "N/A"
    invalid_ioc["MIME Type"] = "N/A"
    invalid_ioc["Invalid"]   = provided_ioc
    return invalid_ioc

def search_urlscan(provided_ioc):
    """Return data from urlscan.io API."""
    api        = 'https://urlscan.io/api/v1/search/?size=10000&q='
    uagent     = 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'
    resp       = requests.get('{}{}'.format(api, provided_ioc),
                              headers={"User-Agent": uagent})
    resp_dicts = create_iocdicts(resp.json()["results"])
    return resp_dicts

def create_iocdicts(results):
    """Return string containing data ('') from urlscan.io API."""
    ioc_dicts = []

    for result in results:
        page                 = result["page"]
        new_page             = {}
        new_page["URL"]      = page["url"]
        new_page["Domain"]   = page["domain"]
        new_page["IP"]       = page["ip"]
        new_page["PTR"]      = page["ptr"]
        new_page["Server"]   = page["server"]
        new_page["City"]     = page["city"]
        new_page["Country"]  = page["country"]
        new_page["ASN"]      = page["asn"]
        new_page["ASN Name"] = page["asnname"]

        if 'files' not in result.keys():
            download = {}
            download["Filename"]  = "No download"
            download["File Size"] = "No download"
            download["MIME Type"] = "No download"
            download["SHA256"]    = "No download"
            download["Invalid"]   = "No"
            ioc_dict              = merge_dict(new_page, download)
            
            ioc_dicts.append(ioc_dict)
        else:
            files_dict = result["files"]

            for dl_file in files_dict:
                download = {}
                download["Filename"]  = dl_file["filename"]
                download["File Size"] = dl_file["filesize"]
                download["MIME Type"] = dl_file["mimeType"]
                download["SHA256"]    = dl_file["sha256"]
                download["Invalid"]   = "No"
                ioc_dict              = merge_dict(new_page, download)
                
                ioc_dicts.append(ioc_dict)
    return ioc_dicts

def merge_dict(page, download):
    """Return a dictionary containing both page and download data."""
    merged_dict = {}
    merged_dict.update(page)
    merged_dict.update(download)
    return merged_dict
