#!/opt/splunk/bin/python
"""
Description: Analyze tweets to understand what others already know about 
particular IOCs. The scripts accepts a list of strings:
    | twitter <STRINGS>

or input from the pipeline. The first argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | threatcrowd <IOC_FIELD>

If the string is a username, it will return as invalid.

Source: https://twitter.com/

Instructions:
1. Open the terminal
2. Navigate to "$SPLUNK_HOME/etc/apps/osweep/etc/".
3. Edit "config.py" and add the following values as strings to the config file:
- twitter_consumer_key        -> Consumer Key
- twitter_consumer_secret     -> Consumer Secret
- twitter_access_token        -> Access Token
- twitter_access_token_secret -> Access Token Secret
4. Save "config.py" and close the terminal.
5. Switch to the Twitter dashboard in the OSweep app.
6. Add the list of IOCs to the "Search Term (+)" textbox.
7. Click "Submit".

Rate Limit: 180 requests/15 min

Results Limit: -

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import os
import sys
import time
import urllib

app_home   = "{}/etc/apps/osweep".format(os.environ['SPLUNK_HOME'])
tp_modules = "{}/bin/_tp_modules".format(app_home)
sys.path.insert(0, tp_modules)
import tweepy
import validators

import commons


def create_session():
    """Return Twitter session."""
    keys = commons.get_apikey("twitter")
    auth = tweepy.OAuthHandler(keys["consumer_key"],
                               keys["consumer_secret"])
    auth.set_access_token(keys["access_token"],
                          keys["access_token_secret"])
    session = tweepy.API(auth)

    try:
        session.rate_limit_status()
    except:
        sc  = session.last_response.status_code
        msg = session.last_response.content
        return {"error": "HTTP Status Code {}: {}".format(sc, msg)}
    return session

def process_iocs(results):
    """Return data formatted for Splunk from Twitter."""
    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

    if len(provided_iocs) > 180:
        return {"error": "Search term limit: 180\nTotal Search Terms Provided: {}".format(len(provided_iocs))}

    session      = create_session()
    splunk_table = []

    if isinstance(session, dict):
        splunk_table.append(session)
        return splunk_table

    rate_limit   = check_rate_limit(session, provided_iocs)
    if isinstance(rate_limit, dict):
        splunk_table.append(rate_limit)
        return splunk_table

    empty_files  = ["d41d8cd98f00b204e9800998ecf8427e",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = commons.deobfuscate_url(provided_ioc)

        if provided_ioc in empty_files:
            splunk_table.append({"invalid": provided_ioc})
            continue

        if validators.url(provided_ioc) or validators.domain(provided_ioc) or \
           validators.ipv4(provided_ioc) or validators.md5(provided_ioc) or \
           validators.sha256(provided_ioc) or \
           len(provided_ioc) > 2 and len(provided_ioc) <= 140:
            ioc_dicts = query_twitter(session, provided_ioc)
        else:
            splunk_table.append({"invalid": provided_ioc})
            continue
        
        for ioc_dict in ioc_dicts:
            ioc_dict = commons.lower_keys(ioc_dict)
            splunk_table.append(ioc_dict)
    return splunk_table

def check_rate_limit(session, provided_iocs):
    """Return rate limit information."""
    rate_limit = session.rate_limit_status()["resources"]["search"]["/search/tweets"]

    if rate_limit["remaining"] == 0:
        reset_time          = rate_limit["reset"]
        rate_limit["reset"] = time.strftime('%Y-%m-%d %H:%M:%S',
                                            time.localtime(reset_time))
        return rate_limit

    if len(provided_iocs) > rate_limit["remaining"]:
        rate_limit = {"Search term limit": rate_limit["remaining"],
                      "Total Search Terms Provided": len(provided_iocs)}
        return rate_limit
    return

def query_twitter(session, provided_ioc):
    """Return results from Twitter as a dictionary."""
    ioc_dicts = []

    if provided_ioc.startswith("@"):
        ioc_dicts.append({"invalid": "{} <-- Monitoring users is prohibited!".format(provided_ioc)})
        return ioc_dicts

    encoded_ioc   = urllib.quote_plus(provided_ioc)
    search_tweets = session.search(q=encoded_ioc,
                                   lang="en",
                                   result_type="mixed",
                                   count="100")

    for tweet in search_tweets:
        if tweet._json["user"]["name"] == provided_ioc.replace("#", "") or \
           tweet._json["user"]["screen_name"] == provided_ioc.replace("#", ""):
            ioc_dicts.append({"invalid": "{} <-- Monitoring users is prohibited!".format(provided_ioc)})
            return ioc_dicts

        if "retweeted_status" in tweet._json.keys():
            if tweet._json["retweeted_status"]["user"]["name"] == provided_ioc.replace("#", "") or \
               tweet._json["retweeted_status"]["user"]["screen_name"] == provided_ioc.replace("#", ""):
                ioc_dicts.append({"invalid": "{} <-- Monitoring users is prohibited!".format(provided_ioc)})
                return ioc_dicts

        urls = []
        for x in tweet._json["entities"]["urls"]:
            if not x["expanded_url"].startswith("https://twitter.com/i/web/status/"):
                urls.append(x["expanded_url"])

        hashtags = []
        for x in tweet._json["entities"]["hashtags"]:
            hashtags.append("#{}".format(x["text"]))

        ioc_dict = {}
        ioc_dict["search_term"] = provided_ioc
        ioc_dict["url"]         = "\n".join(urls)
        ioc_dict["hashtags"]    = "\n".join(hashtags)
        ioc_dict["timestamp"]   = tweet._json["created_at"]
        ioc_dict["tweet"]       = tweet._json["text"]

        if "retweeted_status" in tweet._json.keys():
            ioc_dict["timestamp"] = tweet._json["retweeted_status"]["created_at"]
            ioc_dict["tweet"]     = tweet._json["retweeted_status"]["text"]

        ioc_dicts.append(ioc_dict)
    return ioc_dicts

if __name__ == "__main__":
    current_module = sys.modules[__name__]
    commons.return_results(current_module)
