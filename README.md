[![Follow on Twitter](https://img.shields.io/twitter/follow/phspades.svg?logo=twitter)](https://twitter.com/phspades)
[![Follow on Twitter](https://img.shields.io/twitter/follow/sumgr0.svg?logo=twitter)](https://twitter.com/sumgr0)
# Automated-Scanner

Usage: `~$ bash scanner.sh example.com`

Running in background in VPS using nohup

Usage: `~$ nohup bash scanner.sh example.com &> example.out&`

----

![flow](https://raw.githubusercontent.com/phspade/Automated-Scanner/master/gtrrty.png)
*Will update this in weekend*

**Subdomain Enumeration**
* [Amass](https://github.com/OWASP/Amass) 
>you need to have a [config.ini](https://github.com/OWASP/Amass/blob/master/examples/config.ini) and fill those API keys type thing.
* [Findomain](https://github.com/Edu4rdSHL/findomain)
* [Subfinder](https://github.com/subfinder/subfinder)
* Aquatone (old) `gem install aquatone`
* [Sublist3r](https://github.com/aboul3la/Sublist3r)
* [Rapid7's Project Sonar](https://opendata.rapid7.com/sonar.fdns_v2/)
> https://github.com/phspade/Project_Sonar_R7
* [CRT.SH](https://crt.sh/)
* [GoBuster](https://github.com/OJ/gobuster) using Jason Haddix's [all.txt](https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt) wordlist
* [DNSGen](https://github.com/ProjectAnte/dnsgen)
>changing altdns to dnsgen. it's faster than altdns

**Scan All Alive Hosts with [filter-resolved](https://github.com/tomnomnom/hacks/tree/master/filter-resolved) and [Httprobe](https://github.com/tomnomnom/httprobe)**

**Separating Cloudflare IPs to Non-Cloudflare IPs**
>It's useless to scan Cloudflare IPs.
FYI, Install grepcidr first `apt-get install grepcidr`

**Subdomain TakeOver**
* [tko-subs](https://github.com/anshumanbh/tko-subs)
* [Subjack](https://github.com/haccer/subjack)

**Collecting Endpoints thru [Linkfinder](https://github.com/GerbenJavado/LinkFinder/)**
>*Just comment out the line 253 to 256 in linkfinder.py file*

**[Massdns](https://github.com/blechschmidt/massdns) scanning**

**Port Scanning**
* [Aquatone](https://github.com/michenriksen/aquatone) (New)
* NMAP
* [Masscan](https://github.com/robertdavidgraham/masscan)

**[Whatweb](https://github.com/urbanadventurer/WhatWeb) for Fingerprinting assets**

**[Default Credential](https://github.com/ztgrace/changeme) Scanning**
>Scanning default credentials for all protocols and services
>Need a redis server to properly run this tool.

**File/Dir Discovery**
* [otxurls](https://github.com/lc/otxurls)
* [waybackurls](https://github.com/tomnomnom/waybackurls)
* [DirSearch](https://github.com/maurosoria/dirsearch) using [combined wordlists](https://github.com/phspade/Combined-Wordlists)

**[Virtual Hosts](https://github.com/ffuf/ffuf) Scan**

I hope that someone could help me to add more useful automated scanning technique :)

# Installation

For the installation of all the tools above. I linked all the github links, just make sure that its in the right directory PATH and your good to go. feel free to modify and feel free not to use it if you don't like it :)

# Future Tools to be added
* Install Script
>Thanks to [@sumgr0](https://twitter.com/sumgr0)

* Another Vhost Scanner
>Thinking about gobuster or codingo's VHost Scan

* HTML Report
>HTML Reporting Yey :)

* A Param Miner like tool
>A parameter bruteforcer, maybe [parameth](https://github.com/mak-/parameth) will do.

**ALL CREDIT GOES TO AMAZING CREATORS OF THIS WONDERFUL TOOLS :)**

<sup>cannot make to mention y'all co'z i'm too lazy to do that though :D (i'm being honest here)</sup>

### Need a Digitalocean?

You can help me (slash) support me in this project by registering an account [here](https://m.do.co/c/9d633afb889b) *(with my referral code of course)* .

## Contributor

Big thanks to [@sumgr0](https://twitter.com/sumgr0) :)
