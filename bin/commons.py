#!/opt/splunk/bin/python
"""
Common functions
"""

import os
import re
import sys
import traceback

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import splunk.Intersplunk as InterSplunk
import requests

sys.path.insert(1, "/opt/splunk/etc/apps/osweep/etc/")
import cfg as config


def create_session():
    """Create a Requests Session object."""
    session = requests.session()
    uagent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
    session.headers.update({"User-Agent": uagent})
    session.proxies.update({
        "http": config.http_proxy_url,
        "https": config.https_proxy_url
    })
    return session

def get_apikey(api):
    """Return the API key."""
    if api == "greynoise":
        return config.greynoise_key
    if api == "pulsedive":
        return config.pulsedive_apikey
    if api == "twitter":
        return {
            "access_token": config.twitter_access_token,
            "access_token_secret": config.twitter_access_token_secret,
            "consumer_key": config.twitter_consumer_key,
            "consumer_secret": config.twitter_consumer_secret
        }

def lower_keys(target):
    """Return a string or dictionary with the first character capitalized."""
    if isinstance(target, str) or isinstance(target, unicode):
        words = target.encode("UTF-8").split("_")
        return " ".join(words).lower()

    if isinstance(target, dict):
        dictionary = {}
        for key, value in target.iteritems():
            words = key.encode("UTF-8").split("_")
            key   = " ".join(words).lower()
            dictionary[key] = value
        return dictionary

def merge_dict(one, two):
    """Merge two dictionaries."""
    merged_dict = {}
    merged_dict.update(lower_keys(one))
    merged_dict.update(lower_keys(two))
    return merged_dict

def return_results(module):
    try:
        results, dummy_results, settings = InterSplunk.getOrganizedResults()

        if isinstance(results, list) and len(results) > 0:
            new_results = module.process_iocs(results)
        elif len(sys.argv) > 1:
            new_results = module.process_iocs(None)
    except:
        stack = traceback.format_exc()
        new_results = InterSplunk.generateErrorResults("Error: " + str(stack))

    InterSplunk.outputResults(new_results)
    return

def deobfuscate_url(provided_ioc):
    """Return deobfuscated URLs."""
    pattern = re.compile("^h..p", re.IGNORECASE)
    provided_ioc = pattern.sub("http", provided_ioc)

    pattern = re.compile("\[.\]", re.IGNORECASE)
    provided_ioc = pattern.sub(".", provided_ioc)

    pattern = re.compile("^\*\.", re.IGNORECASE)
    provided_ioc = pattern.sub("", provided_ioc)
    return provided_ioc
