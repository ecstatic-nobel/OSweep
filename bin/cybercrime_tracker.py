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
2. Add the list of domains to the 'Domain (+)' textbox.
3. Select whether the results will be grouped and how from the dropdowns.
4. Click 'Submit'.

Rate Limit: None

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write('{}: <MSG>\n'.format(<VAR>))
"""

import sys
import traceback

import splunk.Intersplunk as InterSplunk
import validators

import cybercrime_tracker_api as cybercrime_tracker


def process_master(results):
    """Return dictionary containing data returned from the (unofficial) 
    CryberCrime Tracker API."""
    splunk_dict = []

    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    elif len(sys.argv) > 1:
        provided_iocs = sys.argv[1:]

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace('hxxp', 'http')
        provided_ioc = provided_ioc.replace('hxtp', 'http')
        provided_ioc = provided_ioc.replace('[.]', '.')
        provided_ioc = provided_ioc.replace('[d]', '.')
        provided_ioc = provided_ioc.replace('[D]', '.')

        if validators.domain(provided_ioc):
            cct_dicts = cybercrime_tracker.search(provided_ioc)
        else:
            invalid_ioc = cybercrime_tracker.invalid_dict(provided_ioc)
            splunk_dict.append(invalid_ioc)
            continue

        if len(cct_dicts) == 0:
            invalid_ioc = cybercrime_tracker.invalid_dict(provided_ioc)
            splunk_dict.append(invalid_ioc)
            continue

        for cct_dict in cct_dicts:
            cct_dict["Invalid"] = "N/A"
            splunk_dict.append(cct_dict)
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
