#!/opt/splunk/bin/python
"""
Description: Tracking threat actor emails in phishing kits. 

Source: https://github.com/neonprimetime/PhishingKitTracker

Instructions: None

Rate Limit: None

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

from collections import OrderedDict
import os
import sys

app_home   = "{}/etc/apps/osweep".format(os.environ['SPLUNK_HOME'])
tp_modules = "{}/bin/_tp_modules".format(app_home)
sys.path.insert(0, tp_modules)
import validators

import commons


csv = "https://raw.githubusercontent.com/neonprimetime/PhishingKitTracker/master/PhishingKitTracker.csv"

def get_feed():
    """Return the latest report summaries from the feed."""
    session   = commons.create_session()
    data_feed = check_project(session)

    if data_feed == None:
        return
    return data_feed

def check_project(session):
    """Return a list of tags."""
    resp = session.get(csv, timeout=180)

    if resp.status_code == 200 and resp.content != '':
        return resp.content.splitlines()
    return

def write_file(data_feed, file_path):
    """Write data to a file."""
    if data_feed == None:
        return

    with open(file_path, "w") as open_file:
        header = data_feed[0]

        open_file.write("{}\n".format(header))

        for data in data_feed[1:]:
            open_file.write("{}\n".format(data.encode("UTF-8")))
    return

if __name__ == "__main__":
    if sys.argv[1].lower() == "feed":
        data_feed    = get_feed()
        lookup_path  = "{}/lookups".format(app_home)
        file_path    = "{}/phishing_kit_tracker.csv".format(lookup_path)

        write_file(data_feed, file_path)
