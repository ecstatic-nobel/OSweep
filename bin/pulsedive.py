#!/opt/splunk/bin/python
"""

"""

import itertools
import os
import sys
import time

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import validators

import commons
try:
    import pulsedive_names
except:
    pass


info_api   = "https://pulsedive.com/api/info.php"
search_api = "https://pulsedive.com/api/search.php"
api_key    = commons.get_apikey("pulsedive")
session    = commons.create_session()
data_feed  = []

def get_names():
    """Return the latest feed and threat names as a list."""
    session  = commons.create_session()
    fquery   = "?search=feed&category=all"
    tquery   = "?category[]=general&category[]=abuse&category[]=apt&\
               category[]=attack&category[]=botnet&category[]=crime&\
               category[]=exploitkit&category[]=fraud&category[]=group&\
               category[]=malware&category[]=proxy&category[]=pup&\
               category[]=reconnaissance&category[]=spam&category[]=phishing&\
               category[]=terrorism&category[]=vulnerability&risk[]=unknown&\
               risk[]=low&risk[]=medium&risk[]=high&risk[]=critical&search=threat"
    queries  = {"feeds": fquery, "threats": tquery}
    names    = []

    for key, value in queries.iteritems():
        resp = session.get("{}{}".format(search_api, value))
        if resp.status_code == 200 and len(resp.json()["results"]) > 0:
            names.append("{} = [\n".format(key))

            for x in resp.json()["results"]:
                names.append('\t"{}",\n'.format(x["name"].encode("UTF-8")))
            names.append("]\n\n")

    time.sleep(4)
    return names

def get_feed():
    """Return the latest report summaries from the feed."""
    session    = commons.create_session()
    feed_dicts = query_list(session)

    if feed_dicts == None:
        return

    feeds   = query_feeds(feed_dicts, session)
    threats = query_threats(session)
    return feeds, threats

def query_list(session):
    """Return a list of feed IDs."""
    feed_dicts = []

    for feed in pulsedive_names.feeds:
        data = {
        "feed": str(feed),
        "key": api_key
        }
        resp = session.get(info_api, params=data)

        if resp.status_code != 200 or "error" in resp.json().keys():
            continue

        parse_resp = resp.json()
        feed_dict = {}
        feed_dict["source"]         = "feeds"
        feed_dict["fid"]            = str(parse_resp.get("fid", ""))
        feed_dict["feed"]           = parse_resp.get("feed", "")
        feed_dict["category"]       = parse_resp.get("category", "")
        feed_dict["organization"]   = parse_resp.get("organization", "")
        feed_dict["website"]        = parse_resp.get("website", "")
        feed_dict["schedule"]       = parse_resp.get("schedule", "")
        feed_dict["stamp added"]    = parse_resp.get("stamp_added", "")
        feed_dict["stamp updated"]  = parse_resp.get("stamp_updated", "")
        feed_dict["stamp pulled"]   = parse_resp.get("stamp_pulled", "")
        feed_dict["stamp modified"] = parse_resp.get("stamp_modified", "")

        for key, value in feed_dict.iteritems():
            if value == None:
                feed_dict[key] = ""

        feed_dicts.append(feed_dict)
        time.sleep(2)

    if len(feed_dicts) > 0:
        return feed_dicts
    return

def query_feeds(feed_dicts, session):
    """Return data from each feed."""
    data_feed = []

    for fd in feed_dicts:
        data = {
            "fid": str(fd["fid"]),
            "key": api_key,
            "get": "links"
        }
        resp = session.get(info_api, params=data)

        if resp.status_code != 200 or "error" in resp.json().keys():
            continue
            
        parsed_resp = resp.json()["results"]

        for pr in parsed_resp:
            fdl = {}
            fdl["indicator"]    = pr.get("indicator", "")
            fdl["type"]         = pr.get("type", "")
            fdl["risk"]         = pr.get("risk", "")
            fdl["stamp linked"] = pr.get("stamp_linked", "")
            feed_dict = commons.merge_dict(fd, fdl)

            for key, value in feed_dict.iteritems():
                if value == None:
                    feed_dict[key] = ""

            data_feed.append(feed_dict)
        time.sleep(2)

    if len(data_feed) == 0:
        return
    return data_feed

def query_threats(session):
    """Return data about each threat."""
    threat_dicts = []

    for threat in pulsedive_names.threats:
        data = {
        "threat": str(threat),
        "key": api_key
        }
        resp = session.get(info_api, params=data)

        if resp.status_code != 200 or "error" in resp.json().keys():
            continue

        parse_resp  = resp.json()
        threat_dict = {}
        threat_dict["source"]              = "threats"
        threat_dict["tid"]                 = str(parse_resp.get("tid", ""))
        threat_dict["threat"]              = parse_resp.get("threat", "")
        threat_dict["category"]            = parse_resp.get("category", "")
        threat_dict["risk"]                = parse_resp.get("risk", "")
        threat_dict["description"]         = parse_resp.get("description", "")
        threat_dict["wiki summary"]        = parse_resp.get("wikisummary", "")
        threat_dict["wiki reference"]      = parse_resp.get("wikireference", "")
        threat_dict["retired"]             = parse_resp.get("retired", "")
        threat_dict["stamp added"]         = parse_resp.get("stamp_added", "")
        threat_dict["stamp updated"]       = parse_resp.get("stamp_updated", "")
        threat_dict["stamp seen"]          = parse_resp.get("stamp_seen", "")
        threat_dict["stamp retired"]       = parse_resp.get("stamp_retired", "")
        threat_dict["updated last domain"] = parse_resp.get("updated_last_domain", "")
        threat_dict["other names"]         = "|".join(parse_resp.get("othernames", ""))
        threat_dict["techniques"]          = "|".join(parse_resp.get("techniques", ""))

        if "news" in parse_resp:
            threat_dict["news"] = "|".join([x.get("link", "") for x in parse_resp["news"]])
        else:
            threat_dict["news"] = ""

        for key, value in threat_dict.iteritems():
            if value == None:
                threat_dict[key] = ""
            else:
                threat_dict[key] = value.replace(",", "")

        threat_dicts.append(threat_dict)
        time.sleep(2)

    session.close()

    if len(threat_dicts) > 0:
        return threat_dicts
    return

def write_file(data, file_path):
    """Write data to a file."""
    if data != None:
        with open(file_path, "w") as open_file:
            keys   = data[0].keys()
            header = ",".join(keys)
            open_file.write("{}\n".format(header))

            for obj in data:
                obj_string = ",".join(obj.values())
                open_file.write("{}\n".format(obj_string.encode("UTF-8")))
    return

def process_iocs(results):
    """Return data formatted for Splunk from Pulsedive."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

    session      = commons.create_session()
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = commons.deobfuscate_url(provided_ioc)

        if validators.domain(provided_ioc) or validators.ipv4(provided_ioc) or \
           validators.url(provided_ioc):
            ioc_dicts = query_pusledive(session, provided_ioc)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue

        for ioc_dict in ioc_dicts:
            splunk_table.append(ioc_dict)

    session.close()
    return splunk_table

def query_pusledive(session, provided_ioc):
    """ """
    if validators.domain(provided_ioc):
        ioc_type = "domain"
    elif validators.ipv4(provided_ioc):
        ioc_type = "ip"
    elif validators.url(provided_ioc):
        ioc_type = "url"
    data = {
        "value": provided_ioc,
        "type": ioc_type,
        "risk": "unknown,none,low,medium,high,critical,retired",
        "attribute": "",
        "property": "",
        "threat": "",
        "feed": "",
        "limit": "tenthousand",
        "key": api_key
    }
    resp = session.get(search_api, params=data)

    if resp.status_code == 200 and "results" in resp.json().keys() and \
       len(resp.json()["results"]) > 0:
        results = resp.json()["results"]
        return rename_dicts(results, provided_ioc)
    return [{"no data": provided_ioc}]

if __name__ == "__main__":
    if sys.argv[1].lower() == "name":
        names       = get_names()
        file_path   = "/opt/splunk/etc/apps/osweep/bin/pulsedive_names.py"
        lookup_path = "/opt/splunk/etc/apps/osweep/lookups/pulsedive_names.csv"

        with open(file_path, 'w') as open_file:
            open_file.write("#!/opt/splunk/bin/python\n\n")
            for line in names:
                open_file.write("{}".format(line))

        with open(lookup_path, 'w') as open_file:
            open_file.write("feed,threat\n")
            for fname, tname in itertools.izip_longest(pulsedive_names.feeds,
                                                       pulsedive_names.threats,
                                                       fillvalue=""):
                open_file.write("{},{}\n".format(fname, tname))
        exit(0)
    
    if sys.argv[1].lower() == "feed":
        feeds, threats = get_feed()
        lookup_path    = "/opt/splunk/etc/apps/osweep/lookups"

        for data in [feeds, threats]:
            source    = data[0]["source"]
            file_path = "{}/pulsedive_{}.csv".format(lookup_path, source)
            write_file(data, file_path)
        exit(0)

    current_module = sys.modules[__name__]
    commons.return_results(current_module)
