#!/bin/bash

#requirements for running scanner.sh

# amass, subfinder, snapd, aquatone, project sonar, grepcidr, gobuster, masscan, nmap, sensitive.py, curl, CRLF-Injection-Scanner, otxurls, waybackurls, DirSearch, LinkFinder, VHostScan

apt-get install pv curl wget grepcidr snapd nmap masscan sublist3r pigz golang sublist3r xsltproc

export PATH=$PATH:/snap/bin #setup snap
service snapd start #starting snap services
sudo snap install amass #installing amass via snap

go get github.com/subfinder/subfinder
go get github.com/OJ/gobuster
go get github.com/lc/otxurls
go get github.com/tomnomnom/waybackurls
go get github.com/hacks/filter-resolved
go get github.com/Ice3man543/SubOver
go get github.com/haccer/subjack
go get github.com/michenriksen/aquatone
go get github.com/ffuf/ffuf
go get -u github.com/OWASP/Amass/...
gem install aquatone
pip3 install dnsgen

# Findomain
sudo wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux -O /usr/bin/findomain
sudo chmod +x /usr/bin/findomain

#Massdns
git clone https://github.com/blechschmidt/massdns.git ~/tools/massdns
cd ~/tools/massdns
make
sudo ln -sf ~/tools/massdns/bin/massdns /usr/bin/massdns

#dirsearch
git clone https://github.com/maurosoria/dirsearch.git
ln -sf ~/dirsearch/dirsearch.py /usr/bin/dirsearch

#changeme
git clone https://github.com/ztgrace/changeme ~/tools/changeme
cd ~/tools/changeme
python3 -m pip install -r requirements.txt
python3 -m pip install -r dev-requirements.txt

#linkfinder
git clone https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder
cd ~/tools/LinkFinder
python setup.py install
pip3 install -r requirements.txt
