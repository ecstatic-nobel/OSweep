#!/opt/splunk/bin/python
"""
Description: Use urlscan.io to get a look at what a particular website is 
requesting in the background. The script accepts a list of strings (domain, IP, 
and/or SHA256):
    | urlscanio $ioc$

or input from the pipeline (any field where the value is a domain, IP, and/or 
SHA256). The first argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | urlscanio <IOC_FIELD>

Source: https://urlscan.io/about-api/

Instructions:
1. Switch to the urlscan.io dashboard in the OSweep app.
2. Add the list of IOCs to the 'Domain, IP, SHA256 (+)' textbox.
3. Select whether the results will be grouped and how from the dropdowns.
4. Click 'Submit'.

Rate Limit: None

Results Limit: 10k

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write('{}: <MSG>\n'.format(<VAR>))
"""

import sys
import traceback

import splunk.Intersplunk as InterSplunk
import validators

import urlscan_api as urlscan


def process_master(results):
    """Return dictionary containing data returned from urlscan.io API."""
    splunk_dict = []

    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

    for provided_ioc in set(provided_iocs):
        if validators.domain(provided_ioc) or validators.ipv4(provided_ioc) or \
           validators.md5(provided_ioc) or validators.sha256(provided_ioc):
            resp_dicts = urlscan.search_urlscan(provided_ioc)
            
            for resp_dict in resp_dicts:
                splunk_dict.append(resp_dict)
        else:
            invalid_ioc = urlscan.invalid_dict(provided_ioc)
            splunk_dict.append(invalid_ioc)
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
        new_results = InterSplunk.generateErrorResults("Error: " + str(stack))

    InterSplunk.outputResults(new_results)
    return

if __name__ == '__main__':
    main()
