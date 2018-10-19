#!/opt/splunk/bin/python
"""
Description: Use Ransomware Tracker to distinguish threats between ransomware 
botnet Command & Control servers (C&Cs), ransomware payment sites, and ransomware 
distribution sites. The script accepts a list of strings (domain, IP, malware
family, site status, threat type, and/or URL):
    | ransomwareTracker <IOCs>

or input from the pipeline (any field where the value is a domain, IP, malware
family, site status, threat type, and/or URL). The first argument is the name of 
one field:
    <search>
    | fields <FIELD>
    | ransomwareTracker <FIELD>

Source: https://ransomwaretracker.abuse.ch/tracker/

Instructions:
1. Add the following cron jobs to the 'splunk' user's cron schedule:
    */5 * * * * /opt/splunk/etc/apps/osweep/bin/ransomware_tracker.py feed
2. Manually download URL dump
    | ransomwareTracker feed
3. Switch to the Ransomware Tracker dashboard in the OSweep app.
4. Add the list of IOCs to the 'Domain, IP, Malware, Status, Threat, URL (+)' 
textbox.
5. Select whether the results will be grouped and how from the dropdowns.
6. Click 'Submit'.

Rate Limit: None

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write('{}: <MSG>\n'.format(<VAR>))
"""

import sys
import traceback

import splunk.Intersplunk as InterSplunk

import ransomware_tracker_api as ransomware_tracker


def process_master(results):
    """Process input (results or arguments) from Splunk."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]
    return ransomware_tracker.process_iocs(provided_iocs)

def main():
    if sys.argv[1].lower() == 'feed':
        lookup_path  = '/opt/splunk/etc/apps/osweep/lookups'
        file_path    = '{}/ransomware_tracker_feed.csv'.format(lookup_path)
        malware_list = '{}/ransomware_tracker_malware.csv'.format(lookup_path)
        threat_list  = '{}/ransomware_tracker_threats.csv'.format(lookup_path)
        data_feed    = ransomware_tracker.get_feed()

        ransomware_tracker.write_file(data_feed, file_path)

        open_file = open(file_path, 'r')
        data_feed = open_file.read().splitlines()
        open_file.close()

        with open(malware_list, 'w') as mfile, open(threat_list, 'w') as tfile:
            mfile.write('Malware\n')
            tfile.write('Threat\n')

            for data in data_feed[1:]:
                malware = data.split(',')[2]
                threat  = data.split(',')[1]
                mfile.write('{}\n'.format(malware.encode("UTF-8")))
                tfile.write('{}\n'.format(threat.encode("UTF-8")))
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

if __name__ == '__main__':
    main()
