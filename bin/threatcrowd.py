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
2. Add the list of IOCs to the 'IP, Domain, or Email (+)' textbox.
3. Select the IOC type.
4. Click 'Submit'.

Rate Limit: 1 request/10s

Results Limit: None

Notes:
1. Keys need to be renamed to uppercase
2. "Invalid" key needs to be added to the objects
3. Initial IOC needs to be added to the objects

Debugger: open("/tmp/splunk_script.txt", "a").write('{}: <MSG>\n'.format(<VAR>))
"""

import sys
from time import sleep
import traceback

import splunk.Intersplunk as InterSplunk
import validators

import threatcrowd_api as threatcrowd


def process_master(results):
    """Return dictionary containing data returned from the (unofficial) 
    CryberCrime Tracker API."""
    splunk_dict = []

    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

    for provided_ioc in set(provided_iocs):
        if validators.ipv4(provided_ioc) or validators.domain(provided_ioc):
            threatcrowd_dicts = threatcrowd.process_host(provided_ioc)
        elif validators.email(provided_ioc):
            threatcrowd_dicts = threatcrowd.process_email(provided_ioc)
        else:
            splunk_dict.append({"Invalid": provided_ioc})
            continue

        if len(threatcrowd_dicts) == 0:
            splunk_dict.append({"Invalid": provided_ioc})
            continue

        for threatcrowd_dict in threatcrowd_dicts:
            splunk_dict.append(threatcrowd_dict)

        if len(provided_iocs) > 1:
            sleep(10)
            
    return splunk_dict

def main():
    """ """
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

if __name__ == '__main__':
    main()
