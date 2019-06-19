# Automated-Scanner

Usage: `~$ bash scanner.sh example.com`

Running in background in VPS using nohup

Usage: `~$ nohup bash scanner.sh example.com &> example.out&`

**Subdomain Scanning**
* Amass
* Subfinder
* Aquatone (old)
* Sublist3r
* GoBuster using Jason Haddix's [all.txt](https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt) wordlist

**Virtual Hosts Scan**

**Scan All Alive Hosts**

**CRLF Injection Scan**

**Angular CLient-Based Injection Scan**

**Port Scanning**
* Aquatone (New)
* NMAP
* Masscan

**File/Dir Discovery**
* sensitive.py
* DirSearch using combined wordlist of nullenc0de and Jason Haddix [content discovery wordlist](https://mega.nz/#!Pgom0azQ!ZK9m085CpimYHp5Z9adqL9oFSIG3PGoTGj0kdxclgME)

I hope that someone could help me to add more useful automated scanning technique :)
