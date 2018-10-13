#!/opt/splunk/bin/python
"""
Use cybercrime-tracker.net to better understand the type of malware a site is 
hosting.
"""

import re
from bs4 import BeautifulSoup
import requests


def search(query, offset=0, limit=10000):
    """Search cybercrime-tracker.net for specific information about panels."""
    results   = []
    api       = "http://cybercrime-tracker.net/index.php?search={}&s={}&m={}"
    vt_latest = 'https://www.virustotal.com/latest-scan/http://{}'
    vt_ip     = 'https://www.virustotal.com/en/ip-address/{}/information/'
    useragent = 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'
    base_url  = api.format(query, offset, limit)
    resp      = requests.get(url=base_url, headers={'User-Agent': useragent})

    if resp.status_code == 200:
        soup  = BeautifulSoup(resp.content, 'html.parser')
        table = soup.findAll('table', attrs={'class': 'ExploitTable'})[0]
        rows  = table.find_all(['tr'])[1:]

        for row in rows:
            cells = row.find_all('td', limit=5)

            if len(cells) > 0:
                tmp = {
                    'Date': cells[0].text,
                    'URL': cells[1].text,
                    'IP': cells[2].text,
                    'Type': cells[3].text,
                    'VT Latest Scan': vt_latest.format(cells[1].text)
                }

                if tmp['IP'] != '':
                    tmp['VT IP Info'] = vt_ip.format(tmp['IP'])

                if tmp not in results:
                    results.append(tmp)
    return results

def invalid_dict(provided_ioc):
    """Return a dictionary for the invalid IOC."""
    invalid_ioc = {}
    invalid_ioc["URL"]            = "N/A"
    invalid_ioc["IP"]             = "N/A"
    invalid_ioc["VT Latest Scan"] = "N/A"
    invalid_ioc["VT IP Info"]     = "N/A"
    invalid_ioc["Date"]           = "N/A"
    invalid_ioc["Type"]           = "N/A"
    invalid_ioc["Invalid"]        = provided_ioc
    return invalid_ioc
