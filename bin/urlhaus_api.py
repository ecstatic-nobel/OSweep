#!/opt/splunk/bin/python
"""
Use URLHaus to pivot off a list of IOCs (URL and/or payload) and present in 
Splunk.
"""

from collections import OrderedDict
import re

from HTMLParser import HTMLParser
import requests
import validators


uagent = 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'

def get_feed():
    """Return the latest report summaries from the feed."""
    api  = 'https://urlhaus.abuse.ch/downloads'
    resp = requests.get('{}/csv/'.format(api),
                        headers={"User-Agent": uagent}).text
    return resp.splitlines()

def write_file(data_feed, file_path):
    """Write data to a file."""
    with open(file_path, 'w') as open_file:
        for line in data_feed:
            open_file.write('{}\n'.format(line))
    return

def process_iocs(provided_iocs):
    """Return data formatted for Splunk from URLhaus."""
    lookup_path = '/opt/splunk/etc/apps/osweep/lookups'
    open_file   = open('{}/urlhaus_url_feed.csv'.format(lookup_path), 'r')
    global data_feed
    data_feed   = open_file.read().splitlines()
    open_file.close()

    empty_files = ['d41d8cd98f00b204e9800998ecf8427e',
                   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
    ioc_list    = []
    # is_url      = re.compile(r'^h..ps?:\/\/.+\.\w{2,}')
    
    global parser
    parser = ParserHTML()

    for provided_ioc in set(provided_iocs):
        provided_ioc = provided_ioc.replace('htxp', 'http')
        provided_ioc = provided_ioc.replace('hxtp', 'http')
        provided_ioc = provided_ioc.replace('hxxp', 'http')
        provided_ioc = provided_ioc.replace('[.]', '.')
        provided_ioc = provided_ioc.replace('[d]', '.')
        provided_ioc = provided_ioc.replace('[D]', '.')

        if provided_ioc in empty_files:
            invalid_str = 'N/A,N/A,{},{}'.format(provided_ioc, provided_ioc)
            ioc_list.append(invalid_str)
            continue

        if validators.url(provided_ioc) or validators.domain(provided_ioc): #is_url.match was here
            analysis_strs = get_analysis(provided_ioc)
            ioc_strs      = get_payloads(analysis_strs)
        elif validators.md5(provided_ioc) or validators.sha256(provided_ioc):
            ioc_strs = get_urls(provided_ioc)
        else:
            invalid_str = 'N/A,N/A,N/A,{}'.format(provided_ioc)
            ioc_list.append(invalid_str)
            continue
        
        for ioc_str in ioc_strs:
            ioc_list.append(ioc_str)

    splunk_table = create_dict(ioc_list)
    return splunk_table

def get_analysis(provided_ioc):
    """Return a list of strings ('URL, URLHaus Link') from the URL dump."""
    urlhaus_match   = re.compile(r'^h..ps?:\/\/urlhaus\.abuse\.ch')
    # amazon_bmatch   = re.compile(r'.+\.amazonaws\.\w{2,3}')
    # amazon_gmatch   = re.compile(r'.+\.amazonaws\.\w{2,3}\/.+')
    # google_bmatch   = re.compile(r'.+\.google\.\w{2,3}')
    # google_gmatch   = re.compile(r'.+\.google\.\w{2,3}\/.+')
    # onedrive_bmatch = re.compile(r'.+\.onedrive\.live\.\w{2,3}\/download\?cid=')
    # onedrive_gmatch = re.compile(r'.+\.onedrive\.live\.\w{2,3}\/download\?cid=.+')
    analysis_strs = []

    if provided_ioc.endswith('/'):
        provided_ioc = provided_ioc[:-1]

    if urlhaus_match.match(provided_ioc):
        return ['{},N/A'.format(provided_ioc)]

    # if amazon_bmatch.match(provided_ioc) and \
    #    not amazon_gmatch.match(provided_ioc):
    #     return ['{},N/A'.format(provided_ioc)]

    # if google_bmatch.match(provided_ioc) and \
    #    not google_gmatch.match(provided_ioc):
    #     return ['{},N/A'.format(provided_ioc)]

    # if onedrive_bmatch.match(provided_ioc) and \
    #    not onedrive_gmatch.match(provided_ioc):
    #     return ['{},N/A'.format(provided_ioc)]
    
    line_found = False

    for line in data_feed:
        if provided_ioc.lower() in line.lower() and not line.startswith('#'):
            line_found   = True
            ioc_link     = line.split(',')[2].replace('"', '')
            urlhaus_link = line.split(',')[-1].replace('"', '')
            analysis_str = '{},{}'.format(ioc_link, urlhaus_link)
            analysis_strs.append(analysis_str)

    if line_found == False:
        analysis_strs.append('{},N/A'.format(provided_ioc))
    return analysis_strs

def get_payloads(analysis_strs):
    """Return a list of strings ('URL, URLHaus Link, Payload, Invalid') from the 
    URLHaus analysis page."""
    urlhaus_gmatch = re.compile(r'.+,h..ps?:\/\/urlhaus\.abuse\.ch\/url\/\d+')
    ioc_strs = []

    for analysis_str in analysis_strs:
        url          = analysis_str.split(',')[0]
        urlhaus_link = analysis_str.split(',')[1]

        if analysis_str.endswith(',N/A'):
            ioc_strs.append('N/A,N/A,N/A,{}'.format(url))
            continue

        if urlhaus_gmatch.match(analysis_str):
            resp = requests.get(urlhaus_link, headers={"User-Agent": uagent})

            if resp.status_code == 200:
                parser.reload()
                parser.feed(resp.text)
                parser.close()
            
            if len(parser.parsed_payloads) > 0:
                for payload in parser.parsed_payloads:
                    ioc_strs.append('{},{},N/A'.format(analysis_str, payload))
            else:
                ioc_strs.append('{},N/A,No Payloads,N/A'.format(url))
        else:
            ioc_strs.append('N/A,N/A,N/A,{}'.format(url))
    return ioc_strs

def get_urls(provided_payload):
    """Return a list of strings ('URL, URLHaus Link, Payload, Invalid') from the 
    URLHaus Browse page."""
    page       = 0
    uh_browser = 'https://urlhaus.abuse.ch/browse.php?search='
    url_list   = []

    while True:
        browse_urlhaus(provided_payload, page)

        if len(parser.parsed_urls) == 0 and page > 0:
            break

        if len(parser.parsed_urls) == 0 and page == 0:
            url_list.append('N/A,N/A,N/A,{}'.format(provided_payload))
            break

        for parsed_url in parser.parsed_urls:
            url_list.append('{},{}{},{},N/A'.format(parsed_url,
                                                    uh_browser,
                                                    provided_payload,
                                                    provided_payload))

        page += 1
    return url_list

def browse_urlhaus(provided_payload, page):
    """Request data from the URLHaus Browse page and feed to the HTML parser."""
    uh_browser = 'https://urlhaus.abuse.ch/browse.php?search='
    resp       = requests.get('{}{}&page={}'.format(uh_browser,
                                                    provided_payload,
                                                    page),
                              headers={"User-Agent": uagent})
    parser.reload()
            
    if resp.status_code == 200:
        if 'Get more information about this malware URL' in resp.text:
            parser.feed(resp.text)
    return

class ParserHTML(HTMLParser):
    """HTML parser class"""
    url_match = re.compile(r'^https?:\/\/.+')

    def reload(self):
        """Empty the list of URLs and payloads."""
        self.parsed_urls     = []
        self.parsed_payloads = []
        return

    def handle_data(self, data):
        """Feed source code to parser and extract URLs and hashes."""
        if self.url_match.match(data):
            self.parsed_urls.append(data)

        if validators.sha256(data):
            self.parsed_payloads.append(data)
        return

def create_dict(ioc_list):
    """Return dictionary to feed to Splunk."""
    splunk_dicts   = []
    splunk_headers = ['URL', 'Payload', 'URLhaus Link', 'Invalid']

    for data in ioc_list:
        splunk_values = []
        url     = data.split(',')[0]
        urlhaus = data.split(',')[1]
        payload = data.split(',')[2]
        invalid = data.split(',')[3]

        splunk_values.append(url)
        splunk_values.append(payload)
        splunk_values.append(urlhaus)
        splunk_values.append(invalid)

        ordered_dict = OrderedDict(zip(splunk_headers, splunk_values))
        splunk_dicts.append(ordered_dict)
    return splunk_dicts
