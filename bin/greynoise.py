#!/opt/splunk/bin/python
"""
Description: Use GreyNoise to analyze data on Internet-wide scanners (benign 
scanners such as Shodan.io and malicious actors like SSH and telnet worms). The 
script accepts a list of strings (domain, IP, and/or scanner name):
    | greyNoise <IOCs>

or input from the pipeline (any field where the value is a domain, IP, scanner 
name). The first argument is the name of one field:
    <search>
    | fields <FIELD>
    | greyNoise <FIELD>

Source: https://viz.greynoise.io/table

Instructions:
1. Add the following cron job to the crontab of the user running Splunk:  
```bash
*/5 * * * * /opt/splunk/bin/python /opt/splunk/etc/apps/osweep/bin/greynoise.py feed
```
2. Manually download the data feed  
```
| greyNoise feed
```
3. Switch to the **GreyNoise** dashboard in the OSweep app.  
4. Add the list of IOCs to the 'Domain, IP, Scanner Name (+)' textbox.  
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

import greynoise_api as greynoise


def process_master(results):
    """Process input (results or arguments) from Splunk."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]
    return greynoise.process_iocs(provided_iocs)

def main():
    if sys.argv[1].lower() == 'feed':
        lookup_path  = '/opt/splunk/etc/apps/osweep/lookups'
        file_path    = '{}/greynoise_feed.csv'.format(lookup_path)
        scanner_list = '{}/greynoise_scanners.csv'.format(lookup_path)
        data_feed    = greynoise.get_feed()

        greynoise.write_file(data_feed, file_path)

        open_file = open(file_path, 'r')
        data_feed = open_file.read().splitlines()
        open_file.close()

        with open(scanner_list, 'w') as sfile:
            sfile.write('Scanner\n')

            for data in data_feed[1:]:
                scanner = data.split(',')[3]
                sfile.write('{}\n'.format(scanner.encode("UTF-8")))
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
