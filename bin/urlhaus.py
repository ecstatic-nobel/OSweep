#!/opt/splunk/bin/python
"""
Description: Use URLHaus to get insights, browse the URLhaus database and find 
most recent additions. The script accepts a list of strings (domain, MD5, SHA256, 
and/or URL):
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
3. Add the list of IOCs to the "Domain, MD5, SHA256, URL (+)" textbox.
4. Select whether the results will be grouped and how from the dropdowns.
5. Click "Submit".

Rate Limit: None

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import sys
import traceback

import splunk.Intersplunk as InterSplunk

import urlhaus_api as urlhaus


def process_master(results):
    """Process input (results or arguments) from Splunk."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]
    return urlhaus.process_iocs(provided_iocs)

def main():
    if sys.argv[1].lower() == "feed":
        lookup_path = "/opt/splunk/etc/apps/osweep/lookups"
        file_path   = "{}/urlhaus_url_feed.csv".format(lookup_path)
        data_feed   = urlhaus.get_feed()
        
        if data_feed == None:
            exit(0)

        urlhaus.write_file(data_feed, file_path)
        exit(0)

    try:
        results, dummy_results, settings = InterSplunk.getOrganizedResults()
        
        if isinstance(results, list) and len(results) > 0:
            new_results = process_master(results)
        elif len(sys.argv) > 1:
            new_results = process_master(None)
    except:
        stack = traceback.format_exc()
        new_results = InterSplunk.generateErrorResults("Error: " + str(stack))

    InterSplunk.outputResults(new_results)
    return

if __name__ == "__main__":
    main()
