# [OSweep™]  
##### Don't Just Search OSINT. Sweep It.  

#### Description  
If you work in IT security, then you most likely use OSINT to help you understand what it is that your SIEM alerted you on and what everyone else in the world understands about it. More than likely you are using more than one OSINT service because most of the time OSINT will only provide you with reports based on the last analysis of the IOC. For some, that's good enough. They create network and email blocks, create new rules for their IDS/IPS, update the content in the SIEM, create new alerts for monitors in Google Alerts and DomainTools, etc etc. For others, they deploy these same countermeasures based on provided reports from their third-party tools that the company is paying THOUSANDS of dollars for.  

The problem with both of these is that the analyst needs to dig a little deeper (ex. FULLY deobfuscate a PowerShell command found in a malicious macro) to gather all of the IOCs. And what if the additional IOC(s) you are basing your analysis on has nothing to do with what is true about that site today? And then you get pwned? And then other questions from management arise...  

See where this is headed? You're about to get a pink slip and walked out of the building so you can start looking for another job in a different line of work.  

So why did you get pwned? You know that if you wasted time gathering all the IOCs for that one alert manually, it would have taken you half of your shift to complete and you would've got pwned regardless.  

The fix? **OSweep™**.  

#### Prerequisites  
- Splunk 7.1.3 >  
- Python 2.7.14 > ($SPLUNK_HOME/bin/python)  

#### Setup  
1. Open a terminal and run the following commands as the user running Splunk:  
```bash
cd /opt/splunk/etc/apps
git clone https://github.com/leunammejii/osweep.git
mv osweep-master osweep
sudo -H -u $SPLUNK_USER /opt/splunk/bin/splunk restart # $SPLUNK_USER = User running Splunk
```
2. Edit "config.py" and add the necessary values as strings to the config file:  
```bash
vim ./osweep/etc/config.py
```
Note: Values for the proxies should be the full URL including the port (ex. http://\<IP Adress\>:\<Port\>).  
3. Save "config.py" and close the terminal.  
4. Install Pip packages:  
```bash
cd /opt/splunk/etc/apps/osweep/bin
bash py_pkg_update.sh
```

#### Commands  
- crtsh - https://crt.sh/  
- cybercrimeTracker - http://cybercrime-tracker.net/index.php  
- cymon - https://cymon.io/  
- greyNoise - https://greynoise.io/  
- phishingCatcher - https://github.com/x0rz/phishing_catcher  
- phishingKitTracker - https://github.com/neonprimetime/PhishingKitTracker  
- ransomwareTracker - https://ransomwaretracker.abuse.ch/  
- threatcrowd - https://www.threatcrowd.org/  
- twitter - https://twitter.com/  
- urlhaus - https://urlhaus.abuse.ch/  
- urlscan - https://urlscan.io/  

#### Usage  
**Feed Overview - Dashboard**  
Three of the dashboards below use lookup tables to store the data feed from the sources. This dasboard shows the current stats compared to the previous day.  

![Feed Overview - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/feedOverview_dashboard.png)  

**The Round Table - Dashboard**  
1. Switch to the **The Round Table** dashboard in the OSweep™ app.  
2. Add the list of IOCs to the "IOC (+)" textbox to know which source has the most information.  
3. Click "Submit".  
4. After the panels have populated, click on one to be redirected to the corresponding dashboard to see the results.  

![The Round Table - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/theRoundTable_dashboard.png)  

**Certificate Search - Dashboard**
1. Switch to the **Certificate Search** dashboard in the OSweep™ app.  
2. Add the list of IOCs to the "Domain, IP (+)" textbox.  
3. Select "Yes" or "No" from the "Wildcard" dropdown to search for subdomains.  
4. Click "Submit".  

![crtsh - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/crtsh_dashboard.png)  

**Certificate Search - Adhoc**
```
| crtsh <DOMAINS>
| fillnull value="-"
| search NOT "issuer ca id"="-"
| dedup "issuer ca id" "issuer name" "name value" "min cert id" "min entry timestamp" "not before" "not after"
| table "issuer ca id" "issuer name" "name value" "min cert id" "min entry timestamp" "not before" "not after"
| sort - "min cert id"
```

or to search for subdomains,  

```
| crtsh subdomain <DOMAINS>
| fillnull value="-"
| search NOT "issuer ca id"="-"
| dedup "issuer ca id" "issuer name" "name value" "min cert id" "min entry timestamp" "not before" "not after"
| table "issuer ca id" "issuer name" "name value" "min cert id" "min entry timestamp" "not before" "not after"
| sort - "min cert id"
```

or to search for wildcard,  

```
| crtsh wildcard <DOMAINS>
| fillnull value="-"
| search NOT "issuer ca id"="-"
| dedup "issuer ca id" "issuer name" "name value" "min cert id" "min entry timestamp" "not before" "not after"
| table "issuer ca id" "issuer name" "name value" "min cert id" "min entry timestamp" "not before" "not after"
| sort - "min cert id"
```

**CyberCrime Tracker - Dashboard**
1. Switch to the **CyberCrime Tracker** dashboard in the OSweep™ app.
2. Add the list of IOCs to the 'Domain, IP (+)' textbox.  
3. Select whether the results will be grouped and how from the dropdowns.  
4. Click 'Submit'.  

![CyberCrime Tracker - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/cybercrimeTracker_dashboard.png)  

**CyberCrime Tracker - Adhoc**
```
| cybercrimeTracker <IOCs>
| fillnull value="-"
| search NOT date="-"
| dedup date url ip "vt latest scan" "vt ip info" type
| table date url ip "vt latest scan" "vt ip info" type
```

**Cymon - Dashboard**
1. Switch to the **Cymon** dashboard in the OSweep™ app.  
2. Add the list of IOCs to the "Domain, IP, MD5, SHA256 (+)" textbox.  
3. Select whether the results will be grouped and how from the dropdowns.  
4. Click "Submit".  

![Cymon - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/cymon_dashboard.png)  

**Cymon - Adhoc**
```
| cymon <IOCs>
| table "feed id" feed title description tags timestamp ip url hostname domain md5 sha1 sha256 ssdeep "reported by" country city lat lon
```

**GreyNoise - Dashboard**  
1. Manually download data feed (one-time only)  
```
| greyNoise feed
```
2. Switch to the **GreyNoise** dashboard in the OSweep™ app.  
3. Add the list of IOCs to the 'Domain, IP, Scanner Name (+)' textbox.  
4. Select whether the results will be grouped and how from the dropdowns.  
5. Click 'Submit'.  

![GreyNoise - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/greynoise_dashboard.png)  

**GreyNoise - Adhoc**  
```
| greynoise <IOCs>
| fillnull value="-" 
| search NOT "last updated"="-" 
| dedup category confidence "last updated" name ip intention "first seen" datacenter tor "rdns parent" link org os asn rdns
| table category confidence "last updated" name ip intention "first seen" datacenter tor "rdns parent" link org os asn rdns
| sort - "Last Updated"
```

**Phishing Catcher - Dashboard**  
1. Switch to the **Phishing Catcher** dashboard in the OSweep™ app.  
2. Select whether you want to monitor the logs in realtime or add a list of domains.  
3. If Monitor Mode is "Yes":  
    - Add a search string to the 'Base Search' textbox.  
    - Add the field name of the field containing the domain to the "Field Name" textbox.  
    - Select the time range to search.  
4. If Monitor Mode is "No":  
    - Add the list of domains to the 'Domain (+)' textbox.  
5. Click 'Submit'.  

![Phishing Catcher - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/phishingCatcher_dashboard.png)  

**Phishing Catcher - Adhoc**
```
| phishingCatcher <DOMAINS>
| table domain "threat level" score
```

**Phishing Kit Tracker - Dashboard**  
1. Manually download data feed (one-time only)  
```
| phishingKitTracker feed
```
2. Switch to the **Phishing Kit Tracker** dashboard in the OSweep™ app.  

![Phishing Kit Tracker - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/phishingKitTracker_dashboard.png)  

**Ransomare Tracker - Dashboard**
1. Manually download data feed (one-time only)  
```
| ransomwareTracker feed
```
2. Switch to the **Ransomare Tracker** dashboard in the OSweep™ app.  
3. Add the list of IOCs to the 'Domain, IP, Malware, Status, Threat, URL (+)' textbox.  
4. Select whether the results will be grouped and how from the dropdowns.  
5. Click 'Submit'.  

![Ransomare Tracker - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/ransomwareTracker_dashboard.png)  

**Ransomare Tracker - Adhoc**
```
| ransomwareTracker <DOMAINS>
| fillnull value="-" 
| search NOT "firstseen (utc)"="-"
| dedup "firstseen (utc)" threat malware host "ip address(es)" url status registrar asn(s) country
| table "firstseen (utc)" threat malware host "ip address(es)" url status registrar asn(s) country
| sort "firstseen (utc)"
```

**ThreatCrowd - Dashboard**
1. Switch to the **ThreatCrowd** dashboard in the OSweep™ app.  
2. Add the list of IOCs to the 'IP, Domain, or Email (+)' textbox.  
3. Select the IOC type.  
4. Click 'Submit'.  

![ThreatCrowd - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/threatcrowd_dashboard.png)  

**Twitter - Dashboard**
1. Switch to the **Twitter** dashboard in the OSweep app.
2. Add the list of IOCs to the "Search Term (+)" textbox.
3. Click "Submit".

![Twitter - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/twitter_dashboard.png)  

**Twitter - Adhoc**
```
| twitter <IOCs>
| eval epoch=strptime(timestamp, "%+")
| fillnull value="-" 
| search NOT timestamp="-" 
| dedup timestamp tweet url 
| sort - epoch
| table timestamp tweet url hashtags "search term"
```

**URLhaus - Dashboard**
1. Manually download data feed (one-time only)  
```
| urlhaus feed
```
2. Switch to the **URLhaus** dashboard in the OSweep™ app.  
3. Add the list of IOCs to the 'Domain, IP, MD5, SHA256, URL (+)' textbox.  
4. Select whether the results will be grouped and how from the dropdowns.  
5. Click 'Submit'.  

![URLhaus - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/urlhaus_dashboard.png)  

**URLhaus - Adhoc**
```
| urlhaus <IOCs>
| fillnull value="-"
| search NOT "provided ioc"="-"
| dedup id dateadded url payload "url status" threat tags "urlhaus link"
| table id dateadded url payload "url status" threat tags "urlhaus link"
```

**<span>urlscan</span>.io - Dashboard**
1. Switch to the **<span>urlscan</span>.io** dashboard in the OSweep™ app.  
2. Add the list of IOCs to the 'Domain, IP, SHA256 (+)' textbox.  
3. Select whether the results will be grouped and how from the dropdowns.  
4. Click 'Submit'.  

![urlscanio - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/urlscan_dashboard.png)  

**<span>urlscan</span>.io - Adhoc**
```
| urlscan <IOCs>
| fillnull value="-" 
| search NOT url="-"
| dedup url domain ip ptr server city country asn asnname filename filesize mimetype sha256 
| table url domain ip ptr server city country asn asnname filename filesize mimetype sha256 
| sort sha256
```

#### Destroy  
To remove the project completely,  run the following commands:  
```bash
rm -rf /opt/splunk/etc/apps/osweep
```

#### Things to know  
All commands accept input from the pipeline. Either use the `fields` or `table` command to select one field containing the values that the command accepts and pipe it to the command with the first argument being the field name.  
```
<search>
| fields <FIELD NAME>
| <OSWEEP COMMAND> <FIELD NAME>
```

ex. The following will allow a user to find other URLs analyzed by URLhaus that are hosting the same Emotet malware as ahsweater[d]com and group it by the payload:  
```
| urlhaus ahsweater.com
| fields payload
| urlhaus payload
| stats values(url) AS url BY payload
```

![alt text](https://github.com/leunammejii/osweep/blob/master/static/assets/input_from_pipeline.png)  

You can also pipe the results of one command into a totally different command to correlate data.  

![alt text](https://github.com/leunammejii/osweep/blob/master/static/assets/input_from_pipeline_correlation.png)  

#### Dashboards Coming Soon  
- Alienvault  
- Censys  
- Hybrid-Analysis  
- Malshare  
- PulseDive  

Please fork, create merge requests, and help make this better.  
