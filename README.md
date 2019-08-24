# Automated-Scanner

Usage: `~$ bash scanner.sh example.com`

Running in background in VPS using nohup

Usage: `~$ nohup bash scanner.sh example.com &> example.out&`

**Subdomain Scanning**
* [Amass](https://github.com/OWASP/Amass)
* [Subfinder](https://github.com/subfinder/subfinder)
* Aquatone (old) `gem install aquatone`
* [Sublist3r](https://github.com/aboul3la/Sublist3r)
* [Rapid7's Project Sonar](https://opendata.rapid7.com/sonar.fdns_v2/)
* [GoBuster](https://github.com/OJ/gobuster) using Jason Haddix's [all.txt](https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt) wordlist

**Scan All Alive Hosts**

**[CRLF Injection](https://github.com/random-robbie/CRLF-Injection-Scanner) Scan**

**Collecting Endpoints thru [Linkfinder](https://github.com/GerbenJavado/LinkFinder/)**
>*Just comment out the line 253 to 256 in linkfinder.py file*

**Port Scanning**
* [Aquatone](https://github.com/michenriksen/aquatone) (New)
* NMAP
* [Masscan](https://github.com/robertdavidgraham/masscan)

**File/Dir Discovery**
* [sensitive.py](https://github.com/phspade/Sensitive-File-Explorer)
* [otxurls](https://github.com/lc/otxurls)
* [waybackurls](https://github.com/tomnomnom/waybackurls)
* [DirSearch](https://github.com/maurosoria/dirsearch) using combined wordlist of nullenc0de and Jason Haddix [content discovery wordlist](https://mega.nz/#!Pgom0azQ!ZK9m085CpimYHp5Z9adqL9oFSIG3PGoTGj0kdxclgME)

**[Virtual Hosts](https://github.com/codingo/VHostScan) Scan**

I hope that someone could help me to add more useful automated scanning technique :)
