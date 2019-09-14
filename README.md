[![Follow on Twitter](https://img.shields.io/twitter/follow/phspades.svg?logo=twitter)](https://twitter.com/phspades)
# Automated-Scanner

Usage: `~$ bash scanner.sh example.com`

Running in background in VPS using nohup

Usage: `~$ nohup bash scanner.sh example.com &> example.out&`

**Subdomain Scanning**
* [Amass](https://github.com/OWASP/Amass) 
>you need to have a [config.ini](https://github.com/OWASP/Amass/blob/master/examples/config.ini) and fill those API keys type thing.
* [Subfinder](https://github.com/subfinder/subfinder)
* Aquatone (old) `gem install aquatone`
* [Sublist3r](https://github.com/aboul3la/Sublist3r)
* [Rapid7's Project Sonar](https://opendata.rapid7.com/sonar.fdns_v2/)
> https://github.com/phspade/Project_Sonar_R7
* [CRT.SH](https://crt.sh/)
* [GoBuster](https://github.com/OJ/gobuster) using Jason Haddix's [all.txt](https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt) wordlist
* [ALTDNS](https://github.com/infosec-au/altdns)
> `wget https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt -O altdns.txt`

**Scan All Alive Hosts**

**Separating Cloudflare IPs to Non-Cloudflare IPs**
>It's useless to scan Cloudflare IPs

**[CRLF Injection](https://github.com/random-robbie/CRLF-Injection-Scanner) Scan**

**Collecting Endpoints thru [Linkfinder](https://github.com/GerbenJavado/LinkFinder/)**
>*Just comment out the line 253 to 256 in linkfinder.py file*

**Checking CNAME with [massdns](https://github.com/blechschmidt/massdns)**

**Port Scanning**
* [Aquatone](https://github.com/michenriksen/aquatone) (New)
* NMAP
* [Masscan](https://github.com/robertdavidgraham/masscan)

**File/Dir Discovery**
* [sensitive.py](https://github.com/phspade/Sensitive-File-Explorer)
* [otxurls](https://github.com/lc/otxurls)
* [waybackurls](https://github.com/tomnomnom/waybackurls)
* [DirSearch](https://github.com/maurosoria/dirsearch) using [combined wordlists](https://github.com/phspade/Combined-Wordlists)

**[Virtual Hosts](https://github.com/codingo/VHostScan) Scan**

I hope that someone could help me to add more useful automated scanning technique :)

**ALL CREDIT GOES TO AMAZING CREATORS OF THIS WONDERFUL TOOLS :)**

*cannot make to mention y'all co'z i'm too lazy to do that though :D (i'm being honest here)*
