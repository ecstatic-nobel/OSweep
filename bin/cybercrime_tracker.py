#!/opt/splunk/bin/python
"""
Description: Use cybercrime-tracker.net to better understand the type of malware 
a site is hosting. The script accepts a list of strings (domains):
    | cybercrimeTracker <DOMAINS>

or input from the pipeline (any field where the value is a domain). The first 
argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | cybercrimeTracker <IOC_FIELD>

Source: https://github.com/PaulSec/cybercrime-tracker.net

Instructions:
1. Switch to the CyberCrime Tracker dashboard in the OSweep app.
2. Add the list of domains to the "Domain (+)" textbox.
3. Select whether the results will be grouped and how from the dropdowns.
4. Click "Submit".

Rate Limit: None

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import sys
import traceback

import splunk.Intersplunk as InterSplunk

import cybercrime_tracker_api as cybercrime_tracker


def process_master(results):
    """Process input (results or arguments) from Splunk."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]
    return cybercrime_tracker.process_iocs(provided_iocs)

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
