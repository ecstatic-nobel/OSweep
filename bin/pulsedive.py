#!/opt/splunk/bin/python
"""

"""

import os
import sys
import time

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)

import commons


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
    fids = [
        1, 10, 11, 13, 14, 17, 18, 19, 2, 20, 22, 23, 24, 27, 28, 29, 3, 31, 32, 
        33, 34, 35, 36, 37, 39, 4, 41, 42, 44, 45, 47, 48, 49, 5, 51, 53, 55, 
        56, 57, 58, 59, 6, 60, 61, 62, 7, 8, 9
    ]

    for feed_id in fids:
        data = {
        "fid": str(feed_id),
        "key": api_key
        }
        resp = session.get(info_api, params=data)

        if resp.status_code != 200 or "error" in resp.json().keys():
            continue

        parse_resp = resp.json()
        feed_dict           = {}
        feed_dict["source"] = "feed"
        feed_dict["fid"]    = str(parse_resp.get("fid", ""))

        if feed_dict["fid"] == "":
            break

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
    tids = [
        1, 10, 100, 101, 103, 106, 107, 108, 109, 11, 110, 111, 112, 113, 114, 
        117, 119, 12, 120, 121, 122, 123, 124, 126, 127, 128, 129, 13, 130, 131, 
        132, 133, 134, 135, 136, 138, 14, 140, 141, 143, 147, 148, 149, 15, 150, 
        153, 154, 156, 157, 158, 159, 16, 160, 161, 162, 163, 164, 165, 166, 167, 
        168, 169, 17, 170, 171, 172, 173, 174, 175, 177, 179, 18, 180, 182, 183, 
        184, 185, 186, 187, 188, 189, 19, 190, 191, 192, 193, 194, 195, 196, 197, 
        198, 199, 20, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 21, 210, 
        212, 213, 214, 215, 216, 217, 218, 219, 22, 220, 221, 222, 223, 224, 225, 
        227, 228, 229, 23, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 
        241, 242, 243, 244, 245, 246, 247, 248, 249, 25, 250, 251, 252, 253, 254, 
        255, 256, 257, 258, 259, 26, 260, 261, 262, 263, 264, 265, 266, 267, 268, 
        269, 27, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 28, 280, 281, 
        282, 283, 284, 29, 3, 30, 32, 35, 36, 38, 39, 4, 40, 41, 42, 43, 44, 45, 
        46, 47, 48, 49, 5, 50, 51, 52, 53, 54, 56, 57, 58, 59, 6, 60, 61, 62, 63, 
        65, 66, 67, 68, 69, 7, 70, 71, 72, 73, 75, 76, 81, 83, 84, 85, 87, 89, 9, 
        90, 91, 92, 94, 95, 96, 97, 99
    ]

    for threat_id in tids:
        data = {
        "tid": str(threat_id),
        "key": api_key
        }
        resp = session.get(info_api, params=data)

        if resp.status_code != 200 or "error" in resp.json().keys():
            continue

        parse_resp         = resp.json()
        threat_dict        = {}
        threat_dict["tid"] = str(parse_resp.get("tid", ""))

        if threat_dict["tid"] == "":
            continue

        threat_dict["source"] = "threat"
        threat_dict["threat"] = parse_resp.get("threat", "")
        threat_dict["category"] = parse_resp.get("category", "")
        threat_dict["risk"] = parse_resp.get("risk", "")
        threat_dict["description"] = parse_resp.get("description", "")
        threat_dict["wiki summary"] = parse_resp.get("wikisummary", "")
        threat_dict["wiki reference"] = parse_resp.get("wikireference", "")
        threat_dict["retired"] = parse_resp.get("retired", "")
        threat_dict["stamp added"] = parse_resp.get("stamp_added", "")
        threat_dict["stamp updated"] = parse_resp.get("stamp_updated", "")
        threat_dict["stamp seen"] = parse_resp.get("stamp_seen", "")
        threat_dict["stamp retired"] = parse_resp.get("stamp_retired", "")
        threat_dict["updated last domain"] = parse_resp.get("updated_last_domain", "")
        threat_dict["other names"] = "|".join(parse_resp.get("othernames", ""))
        threat_dict["techniques"] = "|".join(parse_resp.get("techniques", ""))

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
