#!/opt/splunk/bin/python
"""
Description: Use Cymon to search open-source security reports about phishing, 
malware, botnets and other malicious activities. The script accepts a list of 
strings (domain, IP, MD5, and/or SHA256):
    | cymon $ioc$

or input from the pipeline (any field where the value is a domain, IP, and/or 
SHA256). The first argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | cymon <IOC_FIELD>

Source: http://docs.cymon.io/

Instructions:
1. Switch to the Cymon dashboard in the OSweep app.
2. Add the list of IOCs to the "Domain, IP, MD5, SHA256 (+)" textbox.
3. Select whether the results will be grouped and how from the dropdowns.
4. Click "Submit".

Rate Limit: None

Results Limit: 10

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import sys
import traceback

import splunk.Intersplunk as InterSplunk

import cymon_api as cymon


def process_master(results):
    """Process input (results or arguments) from Splunk."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

    return cymon.process_iocs(provided_iocs)

def main():
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
