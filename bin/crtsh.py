#!/opt/splunk/bin/python
"""
Description: Use crt.sh to discover certificates by searching all of the publicly 
known Certificate Transparency (CT) logs. The script accepts a list of strings 
(domains):
    | crtsh $domain$

or input from the pipeline (any field where the value is a domain). The first 
argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | crtsh <IOC_FIELD>

Source: https://github.com/PaulSec/crt.sh

Instructions:
1. Switch to the crt.sh dashboard in the OSweep app.
2. Add the list of domains to the "Domain (+)" textbox.
3. Select "Yes" or "No" from the "Wildcard" dropdown to search for subdomains.
4. Click "Submit".

Rate Limit: None

Results Limit: None

Notes: Search for subdomains by passing "wildcard" as the first argument:
    | crtsh wildcard $domain$

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import sys
import traceback

import splunk.Intersplunk as InterSplunk

import crtsh_api as crtsh


def process_master(results):
    """Process input (results or arguments) from Splunk."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    elif sys.argv[1] != "wildcard" and len(sys.argv) > 1:
        provided_iocs = sys.argv[1:]
    elif sys.argv[1] == "wildcard" and len(sys.argv) > 2:
        provided_iocs = sys.argv[2:]
    return crtsh.process_iocs(provided_iocs)

def main():
    try:
        results, dummy_results, settings = InterSplunk.getOrganizedResults()

        if isinstance(results, list) and len(results) > 0:
            new_results = process_master(results)
        elif len(sys.argv) > 1:
            new_results = process_master(None)
    except:
        stack = traceback.format_exc()
        new_results = InterSplunk.generateErrorResults("Err: " + str(stack))

    InterSplunk.outputResults(new_results)
    return

if __name__ == "__main__":
    main()
