#!/opt/splunk/bin/python
"""
Description: Use ThreatCrowd to quickly identify related infrastructure and 
malware. The script accepts a list of strings (domains, IPs, or email addresses):
    | threatcrowd <IOCs>

or input from the pipeline (any field where the value is a domain, IP, and/or 
email address). The first argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | threatcrowd <IOC_FIELD>

Output: List of dictionaries

Source: https://www.threatcrowd.org/index.php

Instructions:
1. Switch to the ThreatCrowd dashboard in the OSweep app.
2. Add the list of IOCs to the "IP, Domain, or Email (+)" textbox.
3. Select the IOC type.
4. Click "Submit".

Rate Limit: 1 request/10s

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import sys
import traceback

import splunk.Intersplunk as InterSplunk

import threatcrowd_api as threatcrowd


def process_master(results):
    """Process input (results or arguments) from Splunk."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]            
    return threatcrowd.process_iocs(provided_iocs)

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
