# [OSweep™]  
##### Don't Just Search OSINT. Sweep It.  

#### Description  
If you work in IT security, then you most likely use OSINT to help you understand what it is that your SIEM alerted you on and what everyone else in the world understands about it. More than likely you are using more than one OSINT service because most of the time OSINT will only provide you with reports based on the last analysis of the IOC. For some, that's good enough. They create network and email blocks, create new rules for their IDS/IPS, update the content in the SIEM, create new alerts for monitors in Google Alerts and DomainTools, etc etc. For others, they deploy these same countermeasures based on provided reports from their third-party tools that the company is paying THOUSANDS of dollars for. The problem with both of these is that the analyst needs to dig a little deeper (ex. FULLY deobfuscate a PowerShell command found in a malicious macro) to gather all of the IOCs. And what if the additional IOC(s) you are basing your analysis on has nothing to do with what is true about that site today? And then you get pwned? And then other questions from management arise...  

See where this is headed? You're about to get a pink slip and walked out of the building so you can start looking for another job in a different line of work.  

So why did you get pwned? You know that if you wasted time gathering all the IOCs for that one alert manually, it would have taken you half of your shift to complete and you would've got pwned regardless.  

The fix? **OSweep™**.  

#### Prerequisites  
- Splunk  

#### Setup  
Open a terminal and run the following commands as the user running Splunk:  
```bash
cd /opt/splunk/etc/apps
git clone https://github.com/leunammejii/osweep.git
sudo -H -u $SPLUNK_USER /opt/splunk/bin/splunk restart # $SPLUNK_USER = User running Splunk
```

#### Commands  
- crtsh - https://crt.sh/  
- cybercrimeTracker - http://cybercrime-tracker.net/index.php  
- greyNoise - https://greynoise.io/  
- ransomwareTracker - https://ransomwaretracker.abuse.ch/  
- threatcrowd - https://www.threatcrowd.org/  
- urlhaus - https://urlhaus.abuse.ch/  
- urlscan - https://urlscan.io/  

#### Usage    
**Feed Overview - Dashboard**
Three of the dashboards below use lookup tables to store the data feed from the sources. This dasboard shows the current stats compared to the last seven (7) days. The sparkline on the single value panels span one (1) week.  

![Feed Overview](https://github.com/leunammejii/osweep/blob/master/static/assets/feed_overview_dashboard.png)      

**<span>crt</span>.sh - Dashboard**
1. Switch to the **<span>crt</span>.sh** dashboard in the OSweep™ app.  
2. Add the list of domains to the 'Domain (+)' textbox.  
3. Select 'Yes' or 'No' from the 'Wildcard' dropdown to search for subdomains.  
4. Click 'Submit'.  

![crtsh - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/crtsh_dashboard.png)  

**<span>crt</span>.sh - Adhoc**
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

**CyberCrime Tracker - Dashboard**
1. Switch to the **CyberCrime Tracker** dashboard in the OSweep™ app.
2. Add the list of domains to the 'Domain (+)' textbox.  
3. Select whether the results will be grouped and how from the dropdowns.  
4. Click 'Submit'.  

![CyberCrime Tracker - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/cybercrimeTracker_dashboard.png)  

**CyberCrime Tracker - Adhoc**
```
| cybercrimeTracker <DOMAINS>
| table Date URL IP "VT Latest Scan" "VT IP Info" Type Invalid
```

**GreyNoise - Dashboard**  
1. Add the following cron job to the crontab of the user running Splunk:  
```bash
*/5 * * * * /opt/splunk/bin/python /opt/splunk/etc/apps/osweep/bin/greynoise.py feed
```
2. Manually download the data feed  
```
| greyNoise feed
```
3. Switch to the **GreyNoise** dashboard in the OSweep™ app.  
4. Add the list of IOCs to the 'Domain, IP, Scanner Name (+)' textbox.  
5. Select whether the results will be grouped and how from the dropdowns.  
6. Click 'Submit'.  

![GreyNoise - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/greynoise_dashboard.png)  

**GreyNoise - Adhoc**  
```
| greynoise <IOCs>
| table "Category" "Confidence" "Last Updated" "Name" "IP" "Intention" "First Seen" "Datacenter" "Tor" "RDNS Parent" "Link" "Org" "OS" "ASN" "RDNS" "Invalid"
```

**Ransomare Tracker - Dashboard**
1. Add the following cron job to the crontab of the user running Splunk:  
```bash
*/5 * * * * /opt/splunk/bin/python /opt/splunk/etc/apps/osweep/bin/ransomware_tracker.py feed
```
2. Manually download data feed  
```
| ransomwareTracker feed
```
3. Switch to the **Ransomare Tracker** dashboard in the OSweep™ app.  
4. Add the list of IOCs to the 'Domain, IP, Malware, Status, Threat, URL (+)' textbox.  
5. Select whether the results will be grouped and how from the dropdowns.  
6. Click 'Submit'.  

![Ransomare Tracker - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/ransomwareTracker_dashboard.png)  

**Ransomare Tracker - Adhoc**
```
| ransomwareTracker <DOMAINS>
| table "Firstseen (UTC)" Threat Malware Host "IP Address(es)" URL Status Registrar ASN(s) Country Invalid
```

**ThreatCrowd - Dashboard**
1. Switch to the **ThreatCrowd** dashboard in the OSweep™ app.  
2. Add the list of IOCs to the 'IP, Domain, or Email (+)' textbox.  
3. Select the IOC type.  
4. Click 'Submit'.  

![ThreatCrowd - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/threatcrowd_dashboard.png)  

**URLhaus - Dashboard**
1. Add the following cron job to the crontab of the user running Splunk:  
```bash
*/5 * * * * /opt/splunk/bin/python /opt/splunk/etc/apps/osweep/bin/urlhaus.py feed
```
2. Manually download data feed:  
```
| urlhaus feed
```
3. Switch to the **URLhaus** dashboard in the OSweep™ app.  
4. Add the list of IOCs to the 'Domain, MD5, SHA256, URL (+)' textbox.  
5. Select whether the results will be grouped and how from the dropdowns.  
6. Click 'Submit'.  

![URLhaus - Dashboard](https://github.com/leunammejii/osweep/blob/master/static/assets/urlhaus_dashboard.png) 

**URLhaus - Adhoc**
```
| urlhaus <IOCs>
| table URL Payload "URLhaus Link" Invalid
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
- Hybrid-Analysis  
- Malshare  

Please fork, create merge requests, and help make this better.  
