# [OSweep™]  
##### Don't Just Search OSINT. Sweep It.  

### Description  
If you work in IT security, then you most likely use OSINT to help you understand what it is that your SIEM alerted you on and what everyone else in the world understands about it. More than likely you are using more than one OSINT service because most of the time OSINT will only provide you with reports based on the last analysis of the IOC. For some, that's good enough. They create network and email blocks, create new rules for their IDS/IPS, update the content in the SIEM, create new alerts for monitors in Google Alerts and DomainTools, etc etc. For others, they deploy these same countermeasures based on provided reports from their third-party tools that the company is paying THOUSANDS of dollars for.  

The problem with both of these is that the analyst needs to dig a little deeper (ex. FULLY deobfuscate a PowerShell command found in a malicious macro) to gather all of the IOCs. And what if the additional IOC(s) you are basing your analysis on has nothing to do with what is true about that site today? And then you get pwned? And then other questions from management arise...  

See where this is headed? You're about to get a pink slip and walked out of the building so you can start looking for another job in a different line of work.  

So why did you get pwned? You know that if you wasted time gathering all the IOCs for that one alert manually, it would have taken you half of your shift to complete and you would've got pwned regardless.  

The fix? **OSweep™**.  

### Prerequisites  
Before getting started, ensure you have the following:  
**Ubuntu 18.04+**  
- Python 2.7.14 ($SPLUNK_HOME/bin/python)  
- Splunk 7.1.3+  
- Deb Packages  
  - gcc  
  - python-pip  

**CentOS 7+**  
- Python 2.7.14 ($SPLUNK_HOME/bin/python)  
- Splunk 7.1.3+  
- Yum Packages  
  - epel-release  
  - gcc  
  - python-pip  

**Optional Packages**  
- Git   

Click **[HERE](https://github.com/ecstatic-nobel/OSweep/wiki/Setup)** to get started.  

### Gallery  
**OSINT Sweep - Dashboard**  
![OSINT Sweep - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/osintSweep_dashboard.png)  

**Certificate Search - Dashboard**
![crtsh - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/crtsh_dashboard.png)  

**CyberCrime Tracker - Dashboard**
![CyberCrime Tracker - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/cybercrimeTracker_dashboard.png)  

**GreyNoise - Dashboard**  
![GreyNoise - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/greynoise_dashboard.png)  

**Hybrid-Analysis - Dashboard**  
![Hybrid-Analysis - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/hybridAnalysis_dashboard.png)  

**MalShare - Dashboard**  
![MalShare - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/malshare_dashboard.png)  

**Phishing Catcher - Dashboard**  
![Phishing Catcher - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/phishingCatcher_dashboard.png)  

**Phishing Kit Tracker - Dashboard**  
![Phishing Kit Tracker - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/phishingKitTracker_dashboard.png)  

**Pastebin Dump - Dashboard**  
![Pastebin Dump - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/psbdmp_dashboard.png)  

**ThreatCrowd - Dashboard**
![ThreatCrowd - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/threatcrowd_dashboard.png)  

**Twitter - Dashboard**
![Twitter - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/twitter_dashboard.png)  

**URLhaus - Dashboard**
![URLhaus - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/urlhaus_dashboard.png)  

**<span>urlscan</span>.io - Dashboard**
![urlscanio - Dashboard](https://raw.githubusercontent.com/ecstatic-nobel/OSweep/master/static/assets/urlscan_dashboard.png)  

### Dashboards Coming Soon  
- Alienvault  
- Censys   
- PulseDive  

Please fork, create merge requests, and help make this better.  
