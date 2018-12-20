#!/opt/splunk/bin/python
"""
Description: Use the Phishing Catcher project to catch malicious phishing domain 
names either ad-hoc or on the wire using the project's scoring method. The 
script accepts a list of strings (domains):
    | phishingCatcher <DOMAINs>

or input from the pipeline (any field where the value is a domain). The first 
argument is the name of one field:
    <search>
    | fields <FIELD>
    | phishingCatcher <FIELD>

Source: https://github.com/x0rz/phishing_catcher

Instructions:
1. Switch to the **Phishing Catcher** dashboard in the OSweep app.  
2. Select whether you want to monitor the logs in realtime or add a list of domains.
3. If Monitor Mode is "Yes":  
    - Add a search string to the 'Base Search' textbox.  
    - Add the field name of the field containing the domain to the "Field Name" textbox.  
    - Select the time range to search.  
4. If Monitor Mode is "No":  
    - Add the list of domains to the 'Domain (+)' textbox.  
5. Click 'Submit'.  

Rate Limit: None

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import os
import re
import sys

app_home   = "{}/etc/apps/osweep".format(os.environ['SPLUNK_HOME'])
tp_modules = "{}/bin/_tp_modules".format(app_home)
sys.path.insert(0, tp_modules)
import entropy
import pylev
import tld
import yaml

import commons
import confusables


def get_modules():
    """Return Phishing Catcher modules."""
    session     = commons.create_session()
    suspicious  = request_module(session, "/suspicious.yaml")
    confusables = request_module(session, "/confusables.py")
    session.close()

    if suspicious == None or confusables == None:
        return
    return suspicious, confusables

def request_module(session, filename):
    """Return a list of tags."""
    base_url = "https://raw.githubusercontent.com/x0rz/phishing_catcher/master{}"
    resp     = session.get(base_url.format(filename), timeout=180)

    if resp.status_code == 200 and resp.content != "":
        return resp.content.splitlines()
    return

def write_file(file_contents, file_path):
    """Write data to a file."""
    with open(file_path, "w") as open_file:
        for content in file_contents:
            open_file.write("{}\n".format(content))
    return

def process_iocs(results):
    """Return data formatted for Splunk."""
    with open("suspicious.yaml", "r") as s, open("external.yaml", "r") as e:
        global suspicious
        suspicious = yaml.safe_load(s)
        external   = yaml.safe_load(e)

    if external["override_suspicious.yaml"] is True:
        suspicious = external
    else:
        if external["keywords"] is not None:
            suspicious["keywords"].update(external["keywords"])

        if external["tlds"] is not None:
            suspicious["tlds"].update(external["tlds"])

    if results != None:
        provided_iocs = [y for x in results for y in x.values()]
    else:
        provided_iocs = sys.argv[1:]

    splunk_table = []

    for provided_ioc in set(provided_iocs):        
        score = score_domain(provided_ioc.lower())

        if score >= 120:
            threat_level = "critical"
        elif score >= 90:
            threat_level = "high"
        elif score >= 80:
            threat_level = "medium"
        elif score >= 65:
            threat_level = "low"
        elif score < 65:
            threat_level = "harmless"

        splunk_table.append({
            "threat level": threat_level,
            "domain": provided_ioc,
            "score": score
        })
    return splunk_table

def score_domain(provided_ioc):
    """Return the scores of the provided domain."""
    score = 0

    for suspicious_tld in suspicious["tlds"]:
        if provided_ioc.endswith(suspicious_tld):
            score += 20

    try:
        res    = tld.get_tld(provided_ioc, as_object=True, fail_silently=True,
                             fix_protocol=True)
        domain = ".".join([res.subdomain, res.domain])
    except Exception:
        domain = provided_ioc

    score += int(round(entropy.shannon_entropy(domain)*50))
    domain = confusables.unconfuse(domain)
    words_in_domain = re.split("\W+", domain)


    if domain.startswith("*."):
        domain = domain[2:]

        if words_in_domain[0] in ["com", "net", "org"]:
            score += 10

    for word in suspicious["keywords"]:
        if word in domain:
            score += suspicious["keywords"][word]

    for key in [k for k, v in suspicious["keywords"].items() if v >= 70]:
        for word in [w for w in words_in_domain if w not in ["email", "mail", "cloud"]]:
            if pylev.levenshtein(str(word), str(key)) == 1:
                score += 70

    if "xn--" not in domain and domain.count("-") >= 4:
        score += domain.count("-") * 3

    if domain.count(".") >= 3:
        score += domain.count(".") * 3
    return score   

if __name__ == '__main__':
    if sys.argv[1].lower() == "modules":
        suspicious, confusables = get_modules()
        sfile = "{}/bin/suspicious.yaml".format(app_home)
        cfile = "{}/bin/confusables.py".format(app_home)

        write_file(suspicious, sfile)
        write_file(confusables, cfile)
        exit(0)

    current_module = sys.modules[__name__]
    commons.return_results(current_module)
