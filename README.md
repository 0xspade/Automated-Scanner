[![Follow on Twitter](https://img.shields.io/twitter/follow/phspades.svg?logo=twitter)](https://twitter.com/phspades)
[![Follow on Twitter](https://img.shields.io/twitter/follow/sumgr0.svg?logo=twitter)](https://twitter.com/sumgr0)
# Automated-Scanner

Usage: `~$ bash scanner.sh example.com`

Running in background in VPS using nohup

Usage: `~$ nohup bash scanner.sh example.com &> example.out&`

----
**Subdomain Enumeration**
* [Amass](https://github.com/OWASP/Amass) 
* [Findomain](https://github.com/Edu4rdSHL/findomain)
* [Subfinder](https://github.com/subfinder/subfinder)
* [Assetfinder](https://github.com/tomnomnom/assetfinder)
* [Rapid7's Project Sonar](https://opendata.rapid7.com/sonar.fdns_v2/)
>https://github.com/phspade/Project_Sonar_R7
* [goaltdns](https://github.com/subfinder/goaltdns) + [massdns](https://github.com/blechschmidt/massdns)

**Scan All Alive Hosts with [Httprobe](https://github.com/tomnomnom/httprobe)**

* Getting All IP from the subdomains collected with [DNSProbe](https://github.com/projectdiscovery/dnsprobe)

**Separating Cloudflare, Incapsula, Sucuri, and Akamai IPs from collected IPs**
>It's useless to scan Cloudflare, Incapsula, Sucuri, and Akamai IPs. *(Just like talking to a wall)*
>
>FYI, Install grepcidr first `apt-get install grepcidr`

* S3 Bucket scanner with [s3scanner](https://github.com/sa7mon/S3Scanner)

**Subdomain TakeOver**
* [tko-subs](https://github.com/anshumanbh/tko-subs)
* [Subjack](https://github.com/haccer/subjack)

**Collecting Endpoints thru [Linkfinder](https://github.com/GerbenJavado/LinkFinder/)**

**Collecting [Endpoints](https://github.com/gwen001/github-search/blob/master/github-endpoints.py) and [Secrets](https://github.com/gwen001/github-search/blob/master/github-secrets.py) in Github**
>make sure to create `.tokens` file *(containing your github token)* together with `github-endpoints.py` and `github-secrets.py` *(probably in ~/tools folder)*.

**[HTTP Request Smuggler](https://github.com/gwen001/pentest-tools/blob/master/smuggler.py)**

**[ZDNS](https://github.com/zmap/zdns)**

**[Shodan](https://cli.shodan.io/)**

**[Aquatone](https://github.com/michenriksen/aquatone)**

**Port Scanning**
* NMAP
* [Naabu](https://github.com/projectdiscovery/naabu)

**[Webanalyze](https://github.com/rverton/webanalyze) for Fingerprinting assets**

**~~[Default Credential](https://github.com/ztgrace/changeme) Scanning~~**
>Disable for now until further updates in this tool.

**File/Dir Discovery**
* [gau](https://github.com/lc/gau) + [getching](https://github.com/phspade/getching)

**Potential XSS**
* [kxss](https://github.com/tomnomnom/hacks/tree/master/kxss)

**[Virtual Hosts](https://github.com/ffuf/ffuf) Scan**

* 401 Basic Authorization Bruteforce with FFUF
>Some subdomains has 401 authentication basic, so we need to bruteforce it with base64 credentials :)

* [FFUF](https://github.com/ffuf/ffuf)

>Added **X-Forwarded-For Header** *(you should [setup your own dns server](https://medium.com/@spade.com/a-noob-guide-to-setup-your-own-oob-dns-server-870d9e05b54a))* to check for IP Spoofing Attack.

Feel free to modify it on your own if you don't feel about on how it works :)

# Installation

For the installation of all the tools above. I linked all the github links, just make sure that its in the right directory PATH and your good to go. feel free to modify and feel free not to use it if you don't like it :)

**ALL CREDIT GOES TO AMAZING CREATORS OF THIS WONDERFUL TOOLS :)**

<sup>cannot make to mention y'all co'z i'm too lazy to do that though :D (i'm being honest here)</sup>

### Need a Digitalocean?

You can help me (slash) support me in this project by registering an account [here](https://m.do.co/c/9d633afb889b) *(with my referral code of course)* .

## Contributor

Big thanks to [@sumgr0](https://twitter.com/sumgr0) :)
