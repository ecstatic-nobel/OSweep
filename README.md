# [OSweep™]  
##### Don't Just Search OSINT. Sweep It.  

#### Description  
If you work in a IT security, then you most likely use OSINT to help understand what it is that your SIEM alerted you on and what everyone else in the world understands about it. More than likely, you are using more than one website because most of the time OSINT will only provide you with reports based on the last analysis of the IOC. For some, that's good enough. They create network and email blocks, create new rules for their IDS/IPS, update the content in the SIEM, create new alerts for monitors in Google Alerts and DomainTools, etc etc. For others, they perform deploy these same countermeasures based on provided reports from their third-party tool that the company is paying THOUSANDS of dollars for. The problem with both of these it that the analyst needs to dig a little deeper (ex. FULLY deobfuscate a PowerShell command found in a malicious macro) to gather all of the IOCs. And what if the additional IOC(s) you are basing your on has nothing to do with what is true today? And then you get pwned? Then other questions arise...  

See where this is headed? You're about to get a pink slip and walked out of the building so you can start looking for another job in a different line of work.  

So why did you get pwned? Because if wasted time gathering all the IOCs for that one alert manually, it would have taken you half of your shift to complete and you would've got pwned regardless.  

The fix? **OSweep™**.  

#### Prerequisites  
- Splunk  

#### Setup  
Open a terminal and run the following commands:  
```bash
cd /opt/splunk/etc/apps
git clone https://github.com/leunammejii/osweep.git
/opt/splunk/bin/splunk restart
```

#### Commands  
- crtsh  
- cybercrimeTracker  
- ransomwareTracker  
- threatcrowd  
- urlhaus  
- urlscan  

#### Usage    
##### ![crt.sh](https://crt.sh/ "Discover certificates by searching all of the publicly known Certificate Transparency (CT) logs.") - Dashboard
1. Switch to the ![crt.sh](https://crt.sh/ "Discover certificates by searching all of the publicly known Certificate Transparency (CT) logs.") dashboard in the OSweep™ app.  
2. Add the list of domains to the 'Domain (+)' textbox.  
3. Select 'Yes' or 'No' from the 'Wildcard' dropdown to search for subdomains.  
4. Click 'Submit'.  

![crtsh Wildcard Search](https://github.com/leunammejii/osweep/blob/master/static/assets/crtsh_dashboard.png)  

##### ![crt.sh](https://crt.sh/ "Discover certificates by searching all of the publicly known Certificate Transparency (CT) logs.") - Adhoc
```
| crtsh <DOMAINS>
| table "Issuer CA ID", "Issuer Name", "Name Value", "Min Cert ID", "Min Entry Timestamp", "Not Before", "Not After", Invalid 
| sort - "Min Cert ID"
``` 

or to search for subdomains,  

```
| crtsh wildcard <DOMAINS>
| table "Issuer CA ID", "Issuer Name", "Name Value", "Min Cert ID", "Min Entry Timestamp", "Not Before", "Not After", Invalid 
| sort - "Min Cert ID"
```

![crtsh Wildcard Search](https://github.com/leunammejii/osweep/blob/master/static/assets/crtsh_wildcard_adhoc.png)  

##### ![CyberCrime Tracker](http://cybercrime-tracker.net/index.php "Better understand the type of malware a site is hosting.") - Dashboard
1. Switch to the ![CyberCrime Tracker](http://cybercrime-tracker.net/index.php "Better understand the type of malware a site is hosting.") dashboard in the OSweep™ app.
2. Add the list of domains to the 'Domain (+)' textbox.  
3. Select whether the results will be grouped and how from the dropdowns.  
4. Click 'Submit'.  

![alt text](https://github.com/leunammejii/osweep/blob/master/static/assets/cybercrimeTracker_dashboard.png)  

##### ![CyberCrime Tracker](http://cybercrime-tracker.net/index.php "Better understand the type of malware a site is hosting.") - Adhoc
```
| cybercrimeTracker <DOMAINS>
| table Date URL IP "VT Latest Scan" "VT IP Info" Type Invalid
```

##### ![Ransomare Tracker](https://ransomwaretracker.abuse.ch/tracker/ "Distinguish threats between ransomware botnet Command & Control servers (C&Cs), ransomware payment sites, and ransomware distribution sites.") - Dashboard
1. Add the following cron jobs to the 'splunk' user's cron schedule:  
```bash
*/5 * * * * /opt/splunk/etc/apps/osweep/bin/ransomware_tracker.py feed
```
2. Manually download URL dump  
```
| ransomwareTracker feed
```
3. Switch to the ![Ransomare Tracker](https://ransomwaretracker.abuse.ch/tracker/ "Distinguish threats between ransomware botnet Command & Control servers (C&Cs), ransomware payment sites, and ransomware distribution sites.") dashboard in the OSweep™ app.  
4. Add the list of IOCs to the 'Domain, IP, Malware, Status, Threat, URL (+)' 
textbox.  
5. Select whether the results will be grouped and how from the dropdowns.  
6. Click 'Submit'.  

![alt text](https://github.com/leunammejii/osweep/blob/master/static/assets/ransomwareTracker_dashboard.png)  

##### ![Ransomare Tracker](https://ransomwaretracker.abuse.ch/tracker/ "Distinguish threats between ransomware botnet Command & Control servers (C&Cs), ransomware payment sites, and ransomware distribution sites.") - Adhoc
```
| ransomwareTracker <DOMAINS>
| table "Firstseen (UTC)" Threat Malware Host "IP Address(es)" URL Status Registrar ASN(s) Country Invalid
```

##### ![ThreatCrowd](https://www.threatcrowd.org/ "Quickly identify related infrastructure and malware.") - Dashboard
1. Switch to the ![ThreatCrowd](https://www.threatcrowd.org/ "Quickly identify related infrastructure and malware.") dashboard in the OSweep™ app.  
2. Add the list of IOCs to the 'IP, Domain, or Email (+)' textbox.  
3. Select the IOC type.  
4. Click 'Submit'.  

![alt text](https://github.com/leunammejii/osweep/blob/master/static/assets/threatcrowd_dashboard.png)  

##### ![URLhaus](https://urlhaus.abuse.ch/ "Get insights, browse the URLhaus database and find most recent additions.") - Dashboard
1. Add the following cron jobs to the 'splunk' user's cron schedule:  
```bash
*/5 * * * * /opt/splunk/etc/apps/osweep/bin/urlhaus.py feed
```
2. Manually download URL dump:  
```
| urlhaus feed
```
3. Switch to the ![URLhaus](https://urlhaus.abuse.ch/ "Get insights, browse the URLhaus database and find most recent additions.") dashboard in the OSweep™ app.  
4. Add the list of IOCs to the 'Domain, MD5, SHA256, URL (+)' textbox.  
5. Select whether the results will be grouped and how from the dropdowns.  
6. Click 'Submit'.  

![alt text](https://github.com/leunammejii/osweep/blob/master/static/assets/urlhaus_dashboard.png) 

##### ![URLhaus](https://urlhaus.abuse.ch/ "Get insights, browse the URLhaus database and find most recent additions.") - Adhoc
```
| urlhaus <IOCs>
| table URL Payload "URLhaus Link" Invalid
```  

##### ![urlscan.io](https://urlscan.io/search/#* "Get a look at what a particular website is requesting in the background.") - Dashboard
1. Switch to the ![urlscan.io](https://urlscan.io/search/#* "Get a look at what a particular website is requesting in the background.") dashboard in the OSweep™ app.  
2. Add the list of IOCs to the 'Domain, IP, SHA256 (+)' textbox.  
3. Select whether the results will be grouped and how from the dropdowns.  
4. Click 'Submit'.  

![alt text](https://github.com/leunammejii/osweep/blob/master/static/assets/urlscan_dashboard.png) 

##### ![urlscan.io](https://urlscan.io/search/#* "Get a look at what a particular website is requesting in the background.") - Adhoc
```
| urlscan <IOCs>
| Table URL Domain IP PTR Server City Country ASN "ASN Name" Filename "File Size" "MIME Type" SHA256 Invalid
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

ex. The following will allow a user to find other URLs analyzed by URLhaus that are hosting the same Lokibot malware as mytour[d]pk and group it by the payload:  
```
| urlhaus mytour.pk 
| fields Payload 
| urlhaus Payload 
| stats values("URL") AS "URL" values(Invalid) AS Invalid BY "Payload"
```

![alt text](https://github.com/leunammejii/osweep/blob/master/static/assets/input_from_pipeline.png)  

You can also pipe the results of one command into a totally different command to correlate data.  

![alt text](https://github.com/leunammejii/osweep/blob/master/static/assets/input_from_pipeline_correlation.png)  

#### Dashboards Coming Soon  
- Alienvault  
- Censys  
- Cymon  
- Grey Noise  
- Hybrid-Analysis  
- Malshare  

Please fork, create merge requests, and help make this better.  
