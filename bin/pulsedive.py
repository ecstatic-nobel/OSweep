#!/opt/splunk/bin/python
"""

"""

import os
import sys
import time

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)

import commons
import pulsedive_names


info_api  = "https://pulsedive.com/api/info.php"
api_key   = commons.get_apikey("pulsedive")
session   = commons.create_session()
data_feed = []

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

    for feed in pulsedive_names.feed:
        data = {
        "feed": str(feed),
        "key": api_key
        }
        resp = session.get(info_api, params=data)

        if resp.status_code != 200 or "error" in resp.json().keys():
            continue

        parse_resp = resp.json()
        feed_dict = {}
        feed_dict["source"]         = "feed"
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

    for threat in pulsedive_names.threat:
        data = {
        "threat": str(threat),
        "key": api_key
        }
        resp = session.get(info_api, params=data)

        if resp.status_code != 200 or "error" in resp.json().keys():
            continue

        parse_resp  = resp.json()
        threat_dict = {}
        threat_dict["source"]              = "threat"
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

if __name__ == "__main__":
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
