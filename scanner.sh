#!/bin/bash

# amass, subfinder, snapd, aquatone, project sonar, grepcidr, gobuster, masscan, nmap, sensitive.py, curl, CRLF-Injection-Scanner, otxurls, waybackurls, DirSearch, LinkFinder, VHostScan

passwordx=""

[ ! -f ~/recon/$1 ] && mkdir ~/recon/$1
[ ! -f ~/recon/$1/dirsearch ] && mkdir ~/recon/$1/dirsearch
[ ! -f ~/recon/$1/virtual-hosts ] && mkdir ~/recon/$1/virtual-hosts
[ ! -f ~/recon/$1/endpoints ] && mkdir ~/recon/$1/endpoints
[ ! -f ~/recon/$1/otxurls ] && mkdir ~/recon/$1/otxurls
[ ! -f ~/recon/$1/waybackurls ] && mkdir ~/recon/$1/waybackurls
sleep 5

message () {
	telegram_bot=""	
	telegram_id=""
	alert="https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text="
	[ -z $telegram_bot ] && [ -z $telegram_id ] || curl -g $alert$1 --silent > /dev/null
}

scanned () {
	cat $1 | sort -u | wc -l
}

message="[+] Initiating%20scan%20:%20$1 [+]"

echo "[+] AMASS SCANNING [+]"
if [ ! -f ~/recon/$1/$1-amass.txt ] && [ ! -z $(which amass) ]; then
	#amass enum -active -brute -d $1 -o ~/recon/$1/$1-amass.txt -config ~/config.ini
	amass enum -passive -d $1 -o ~/recon/$1/$1-amass.txt
	amasscan=`scanned ~/recon/$1/$1-amass.txt`
	message "Amass%20Found%20$amasscan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Amass%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] FINDOMAIN SCANNING [+]"
if [ ! -f ~/recon/$1/$1-findomain.txt ] && [ ! -z $(which findomain) ]; then
	findomain -t $1 -q -u ~/recon/$1/$1-findomain.txt
	findomainscan=`scanned ~/recon/$1/$1-findomain.txt`
	message "Findomain%20Found%20$findomainscan%20subdomain(s)%20for%20$1"
else
	message "[-]%20Skipping%20Findomain%20$findomainscan%20previously%20discovered%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBFINDER SCANNING [+]"
if [ ! -f ~/recon/$1/$1-subfinder.txt ] && [ ! -z $(which subfinder) ]; then
	subfinder -d $1 -nW -silent -o ~/recon/$1/$1-subfinder.txt
	subfinderscan=`scanned ~/recon/$1/$1-subfinder.txt`
	message "SubFinder%20Found%20$subfinderscan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Subfinder%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] AQUATONE SCANNING [+]"
if [ ! -f ~/aquatone/$1/urls.txt ] && [ ! -z $(which aquatone-discover) ] && [ ! -z $(which aquatone-scan) ]; then
	aquatone-discover -d $1
	aquatone-scan -d $1 -p huge
	for domains in `cat ~/aquatone/$1/urls.txt`; do domain="${domains#*://}"; domainx="${domain%/*}"; domainz="${domainx%:*}"; echo $domainz >> ~/recon/$1/$1-aquatone.txt;done
	aquatonescan=`scanned ~/recon/$1/$1-aquatone.txt`
	message "Aquatone%20Found%20$aquatonescan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	for domains in `cat ~/aquatone/$1/urls.txt`; do domain="${domains#*://}"; domainx="${domain%/*}"; domainz="${domainx%:*}"; echo $domainz >> ~/recon/$1/$1-aquatone.txt;done
	aquatonescan=`scanned ~/recon/$1/$1-aquatone.txt`
	message "[-]%20Skipping%20Aquatone%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBLIST3R SCANNING [+]"
if [ ! -f ~/recon/$1/$1-sublist3r.txt ] && [ -e ~/tools/Sublist3r/sublist3r.py ]; then
	python ~/tools/Sublist3r/sublist3r.py -b -d $1 -o ~/recon/$1/$1-sublist3r.txt
	sublist3rscan=`scanned ~/recon/$1/$1-sublist3r.txt`
	message "Sublist3r%20Found%20$sublist3rscan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Sublist3r%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SCANNING SUBDOMAINS WITH PROJECT SONAR [+]"
if [ ! -f ~/recon/$1/$1-project-sonar.txt ] && [ -e ~/recon/data/fdns_cname.json.gz ]; then
	pv ~/recon/data/fdns_cname.json.gz | pigz -dc | grep -E "*[.]$1\"," | jq -r '.name' | sort -u >> ~/recon/$1/$1-project-sonar.txt
	scanned ~/recon/$1/$1-project-sonar.txt
	#pv ~/reverse_dns.json.gz | pigz -dc | grep -E "*[.]$1\"," | jq -r '.value' | sort -u >> ~/recon/$1/$1-project-sonar.txt
	projectsonar=$(scanned ~/recon/$1/$1-project-sonar.txt)
	message "Project%20Sonar%20Found%20$projectsonar%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Project%20Sonar%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] CRT.SH SCANNING [+]"
if [ ! -f ~/recon/$1/$1-crt.txt ]; then
	[ ! -f ~/recon/scanner/crtname.txt ] && wget "https://gist.githubusercontent.com/sumgr0/58e234fb96ae30e85271634b38331912/raw/bdd9ed497bfe4741249d98fc01703e99282f1f2d/altname.txt" -O ~/recon/scanner/crtname.txt
	while read url; do
    {
        curl -s "https://crt.sh/?q=$url.$1&output=json" | jq '.[].name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/recon/$1/$1-crt.txt
    }; done < ~/recon/scanner/crtname.txt

	cat ~/recon/$1/$1-crt.txt | sort -u >> ~/recon/$1/$1-crtx.txt && rm ~/recon/$1/$1-crt.txt && mv ~/recon/$1/$1-crtx.txt ~/recon/$1/$1-crt.txt
	crt=`scanned ~/recon/$1/$1-crt.txt`
	message "CRT.SH%20Found%20$crt%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20CRT.SH%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] GOBUSTER SCANNING [+]"
if [ ! -f ~/recon/$1/$1-gobuster.txt ] && [ ! -z $(which gobuster) ]; then
	[ ! -f ~/wordlists/all.txt ] && wget "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt" -O ~/wordlists/all.txt
	gobuster dns -d $1 -t 100 -w ~/wordlists/all.txt --wildcard -o ~/recon/$1/$1-gobust.txt
	cat ~/recon/$1/$1-gobust.txt | grep "Found:" | awk {'print $2'} > ~/recon/$1/$1-gobuster.txt
	rm ~/recon/$1/$1-gobust.txt
	gobusterscan=`scanned ~/recon/$1/$1-gobuster.txt`
	message "Gobuster%20Found%20$gobusterscan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Gobuster%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

## Deleting all the results to less disk usage
cat ~/recon/$1/$1-amass.txt ~/recon/$1/$1-findomain.txt ~/recon/$1/$1-project-sonar.txt ~/recon/$1/$1-subfinder.txt ~/recon/$1/$1-aquatone.txt ~/recon/$1/$1-sublist3r.txt ~/recon/$1/$1-crt.txt ~/recon/$1/$1-gobuster.txt | sort -uf > ~/recon/$1/$1-final.txt
rm ~/recon/$1/$1-amass.txt ~/recon/$1/$1-findomain.txt ~/recon/$1/$1-project-sonar.txt ~/recon/$1/$1-subfinder.txt ~/recon/$1/$1-aquatone.txt ~/recon/$1/$1-sublist3r.txt ~/recon/$1/$1-crt.txt ~/recon/$1/$1-gobuster.txt
touch ~/recon/$1/$1-ipz.txt
sleep 5

# echo "[+] DNSGEN SCANNING [+]"
# if [ ! -f ~/recon/$1/$1-dnsgen.txt ] && [ ! -z $(which dnsgen) ]; then
# 	[ ! -f ~/scanner/dnsgen.txt ] && wget "https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt" -O ~/scanner/dnsgen.txt
# 	cat ~/recon/$1/$1-final.txt | dnsgen -w ~/scanner/dnsgen.txt - >> ~/recon/$1/$1-dnsgen.txt
# 	sleep 3
# 	dnsgens=`scanned ~/recon/$1/$1-dnsgen.txt`
# 	message "DNSGEN%20Found%20$dnsgens%20subdomain(s)%20for%20$1"
# else
# 	message "[-]%20Skipping%20DNSGEN%20Scanning%20for%20$1"
# 	echo "[!] Skipping ..."
# fi
# sleep 5

echo "[+] DNSGEN SCANNING [+]"
if [ ! -f ~/recon/$1/$1-dnsgen.txt ] && [ ! -z $(which dnsgen) ]; then
	[ ! -f ~/recon/scanner/dnsgen.txt ] && wget "https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt" -O ~/recon/scanner/dnsgen.txt
	rm ~/recon/$1/$1-dnsgen.txt
	cat ~/recon/$1/$1-final.txt | dnsgen - | massdns -r ~/tools/massdns/lists/resolvers.txt -t A -o J --flush 2>/dev/null | jq -r .query_name | sort -u | tee -a ~/recon/$1/$1-dnsgen.tmp
	cat ~/recon/$1/$1-dnsgen.tmp | sed 's/-\.//g' | sed 's/-\.//g' | sed 's/-\-\-\-//g' | sort -u > ~/recon/$1/$1-dnsgen.txt
	rm ~/recon/$1/$1-dnsgen.tmp
	sleep 3
	dnsgens=`scanned ~/recon/$1/$1-dnsgen.txt`
	message "DNSGEN%20Found%20$dnsgens%20subdomain(s)%20for%20$1"
else
	message "[-]%20Skipping%20DNSGEN%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

cat ~/recon/$1/$1-dnsgen.txt ~/recon/$1/$1-final.txt | sort -u >> ~/recon/$1/$1-fin.txt
rm ~/recon/$1/$1-final.txt && mv ~/recon/$1/$1-fin.txt ~/recon/$1/$1-final.txt
all=`scanned ~/recon/$1/$1-final.txt`
message "Almost%20$all%20Collected%20Subdomains%20for%20$1"
sleep 3

# collecting all IP from collected subdomains
ulimit -n 800000
while read -r domain; do dig +short $domain | grep -v '[[:alpha:]]' >> ~/recon/$1/$1-ipf.txt &; done < ~/recon/$1/$1-final.txt
cat ~/recon/$1/$1-ipf.txt | sort -u >> ~/recon/$1/$1-ipz.txt
rm ~/recon/$1/$1-ipf.txt

## segregating cloudflare IP from non-cloudflare IP
## non-sense if I scan cloudflare IP. :(
iprange="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/12 172.64.0.0/13 131.0.72.0/22"
for ip in `cat ~/recon/$1/$1-ipz.txt`; do
	grepcidr "$iprange" <(echo "$ip") >/dev/null && echo "$ip is cloudflare" || echo "$ip" >> ~/recon/$1/$1-ip.txt
done
ipz=`scanned ~/recon/$1/$1-ip.txt`
ip_old=`scanned ~/recon/$1/$1-ipz.txt`
message "$ipz%20non-cloudflare%20IPs%20has%20been%20$collected%20in%20$1%20out%20of%20$ip_old%20IPs"
rm ~/recon/$1/$1-ipz.txt
cat ~/recon/$1/$1-ip.txt ~/recon/$1/$1-final.txt > ~/recon/$1/$1-all.txt
sleep 5

# echo "[+] HTTPROBE Scanning for Alive Hosts [+]"
# if [ ! -f ~/recon/$1/$1-httprobe.txt ] && [ ! -z $(which httprobe) ]; then
# 	cat ~/recon/$1/$1-all.txt | httprobe | sed 's/http:\/\///g' | sed 's/https:\/\///g' | sort -u >> ~/recon/$1/$1-httprobe.txt
# 	alivesu=`scanned ~/recon/$1/$1-httprobe.txt`
# 	rm ~/recon/$1/$1-all.txt ~/recon/$1/$1-final.txt
# 	message "$alivesu%20alive%20domains%20out%20of%20$all%20domains%20in%20$1"
# else
# 	message "[-]%20Skipping%20httprobe%20Scanning%20for%20$1"
# 	echo "[!] Skipping ..."
# fi
# sleep 5

echo "[+] Filter-Resolved Scanning for Alive Hosts [+]"
if [ ! -f ~/recon/$1/$1-alive.txt ] && [ ! -z $(which httprobe) ]; then
	cat ~/recon/$1/$1-all.txt | filter-resolved | sort -u >> ~/recon/$1/$1-alive.txt
	alivesu=`scanned ~/recon/$1/$1-alive.txt`
	rm ~/recon/$1/$1-all.txt ~/recon/$1/$1-final.txt
	message "$alivesu%20alive%20domains%20out%20of%20$all%20domains%20in%20$1"
else
	message "[-]%20Skipping%20httprobe%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBOVER for Subdomain TKO [+]"
if [ ! -f ~/recon/$1/$1-subover.txt ] && [ ! -z $(which SubOver) ]; then
	[ ! -f ~/recon/$1/providers.json ] && wget "https://raw.githubusercontent.com/Ice3man543/SubOver/master/providers.json" -O ~/recon/$1/providers.json
	cd ~/recon/$1/
	SubOver -l ~/recon/$1/$1-alive.txt -timeout 15 >> ~/recon/$1/$1-subtemp.txt
	SubOver -l ~/recon/$1/$1-alive.txt -timeout 15 -https >> ~/recon/$1/$1-subtmp.txt
	cat ~/recon/$1/$1-subtemp.txt ~/recon/$1/$1-subtmp.txt | sort -u > ~/recon/$1/$1-subover.txt
	rm ~/recon/$1/$1-subtemp.txt ~/recon/$1/$1-subtmp.txt
	message "Subover%20scanner%20done%20for%20$1"
else
	message "[-]%20Skipping%20subover%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBJACK for Subdomain TKO [+]"
if [ ! -f ~/recon/$1/$1-subjack.txt ] && [ ! -z $(which subjack) ]; then
	[ ! -f ~/scanner/fingerprints.json ] && wget "https://raw.githubusercontent.com/sumgr0/subjack/master/fingerprints.json" -O ~/scanner/fingerprints.json
	subjack -w ~/recon/$1/$1-alive.txt -a -timeout 15 -c ~/scanner/fingerprints.json -v -m -o ~/recon/$1/$1-subtemp.txt
	subjack -w ~/recon/$1/$1-alive.txt -a -timeout 15 -c ~/scanner/fingerprints.json -v -m -ssl -o ~/recon/$1/$1-subtmp.txt
	cat ~/recon/$1/$1-subtemp.txt ~/recon/$1/$1-subtmp.txt | sort -u > ~/recon/$1/$1-subjack.txt
	rm ~/recon/$1/$1-subtemp.txt ~/recon/$1/$1-subtmp.txt
	message "subjack%20scanner%20done%20for%20$1"
else
	message "[-]%20Skipping%20subjack%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

# echo "[+] SCANNING CRLF [+]"
# python3 ~/tools/CRLF-Injection-Scanner/crlf_scan.py -i ~/recon/$1/$1-alive.txt -o ~/recon/$1/$1-crlf.txt
# message "CRLF%20Scanning%20done%20for%20$1"
# sleep 5

declare -a protocol=("http" "https")
echo "[+] COLLECTING ENDPOINTS [+]"
for urlz in `cat ~/recon/$1/$1-alive.txt`; do 
	for protoc in ${protocol[@]}; do
		python ~/LinkFinder/linkfinder.py -i $protoc://$urlz -d -o ~/recon/$1/endpoints/$protoc_$urlz-result.html
	done
done
message "Done%20collecting%20endpoint%20in%20$1"
sleep 5

echo "[+] MASSDNS SCANNING [+]"
massdns -r ~/tools/massdns/lists/resolvers.txt ~/recon/$1/$1-alive.txt -o S > ~/recon/$1/$1-massdns.txt
message "Done%20Massdns%20Scanning%20for%20$1"
sleep 5

echo "[+] MASSCAN PORT SCANNING [+]"
if [ ! -f ~/recon/$1/$1-masscan.txt ] && [ ! -z $(which masscan) ]; then
	echo $passwordx | sudo -S masscan -p1-65535 -iL ~/recon/$1/$1-ip.txt --max-rate 10000 -oG ~/recon/$1/$1-masscan.txt
	mass=`scanned $1/$1-ip.txt`
	message "Masscan%20Scanned%20$mass%20IPs%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Masscan%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

big_ports=`cat ~/recon/$1/$1-masscan.txt | grep 'Host:' | awk {'print $5'} | awk -F '/' {'print $1'} | sort -u | paste -s -d ','`
echo "[+] PORT SCANNING [+]"
cat ~/recon/$1/$1-alive.txt | aquatone -ports $big_ports -out ~/recon/$1/$1-ports
message "Done%20Aquatone%20Port%20Scanning%20for%20$1"
sleep 5

echo "[+] NMAP PORT SCANNING [+]"
if [ ! -f ~/recon/$1/$1-nmap.txt ] && [ ! -z $(which nmap) ]; then
	[ ! -f ~/scanner/nmap-bootstrap.xsl ] && wget "https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl" -O ~/scanner/nmap-bootstrap.xsl
	echo $passwordx | sudo -S nmap -sVTC -A -O -Pn -p$big_ports -iL ~/recon/$1/$1-ip.txt --stylesheet ~/scanner/nmap-bootstrap.xsl -oA ~/recon/$1/$1-nmap
	nmaps=`scanned ~/recon/$1/$1-ip.txt`
	xsltproc -o ~/recon/$1/$1-nmap.html ~/nmap-bootstrap.xsl ~/recon/$1/$1-nmap.xml
	message "Nmap%20Scanned%20$nmaps%20IPs%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Nmap%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] DEFAULT CREDENTIAL SCANNING [+]"
if [ ! -f ~/recon/$1/$1-nmap.xml ] && [ -e ~/tools/changeme/changeme.py ]; then
	python3 ~/tools/changeme/changeme.py ~/recon/$1/$1-nmap.xml -d --fresh -v --ssl -o ~/recon/$1/$1-changeme.csv
	message "Default%20Credential%20done%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Default%20Credential%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] Scanning for Sensitive Files [+]"
cp ~/recon/$1/$1-alive.txt ~/recon/$1/$1-sensitive.txt
python ~/tools/Sensitive-File-Explorer/sensitive.py -u ~/recon/$1-sensitive.txt
sens=`scanned ~/recon/$1-sensitive.txt`
message "Sensitive%20File%20Scanned%20$sens%20asset(s)%20for%20$1"
rm $1-sensitive.txt
sleep 5

echo "[+] OTXURL Scanning for Archived Endpoints [+]"
for u in `cat ~/recon/$1/$1-alive.txt`;do echo $u | otxurls | grep "$u" >> ~/recon/$1/otxurls/tmp-$u.txt; done
cat ~/recon/$1/otxurls/* | sort -u >> ~/recon/$1/otxurls/$1-otxurl.txt 
rm ~/recon/$1/otxurls/tmp-*
message "OTXURL%20Done%20for%20$1"
sleep 5

echo "[+] WAYBACKURLS Scanning for Archived Endpoints [+]"
for u in `cat ~/recon/$1/$1-alive.txt`;do echo $u | waybackurls | grep "$u" >> ~/recon/$1/waybackurls/tmp-$u.txt; done
cat ~/recon/$1/waybackurls/* | sort -u >> ~/recon/$1/waybackurls/$1-waybackurls.txt 
rm ~/recon/$1/waybackurls/tmp-*
message "WAYBACKURLS%20Done%20for%20$1"
sleep 5

echo "[+] Scanning for Virtual Hosts Resolution [+]"
vhost_ports=`cat ~/recon/$1/$1-masscan.txt | grep 'Host:' | awk {'print $5'} | awk -F '/' {'print $1'} | sort -u | paste -s -d ' '`
declare -a vhost=($vhost_ports)
cat ~/recon/$1/$1-alive.txt ~/VHostScan/vhost-wordlist.txt | sort -u >> ~/recon/$1/$1-temp-vhost-wordlist.txt
for test in `cat ~/recon/$1/$1-ip.txt`; do
	for p in ${vhost[@]}; do
		VHostScan -t $test -b $1 -r 80 -p $p -v --fuzzy-logic --waf --random-agent -w ~/recon/$1/$1-temp-vhost-wordlist.txt -oN ~/recon/$1/virtual-hosts/initial-$test_$p.txt
		VHostScan -t $test -b $1 -p $p -r 80 -v --fuzzy-logic --waf --ssl --random-agent -w ~/recon/$1/$1-temp-vhost-wordlist.txt -oN ~/recon/$1/virtual-hosts/ssl-$test_$p.txt
		cat ~/recon/$1/virtual-hosts/initial-$test_$p.txt ~/recon/$1/virtual-hosts/ssl-$test_$p.txt >> ~/recon/$1/virtual-hosts/final-$test.txt
	done
done
message "Virtual%20Host(s)%20done%20for%20$1"
rm ~/recon/$1/$1-temp-vhost-wordlist.txt ~/recon/$1/virtual-hosts/initial-* ~/recon/$1/virtual-hosts/ssl-*
sleep 5

echo "[+] DirSearch Scanning for Sensitive Files [+]"
[ ! -f ~/newlist.txt ] && echo "visit https://github.com/phspade/Combined-Wordlists/"
for u in `cat ~/recon/$1/$1-alive.txt`;do python3 ~/dirsearch/dirsearch.py -u $u -e php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp,yaml,yml,config -x 400,301,404,303,403,500,406,503 -t 50 --http-method=POST --random-agents -b -w ~/newlist.txt --plain-text-report ~/recon/$1/dirsearch/$u-dirsearch.txt;done
sleep 5

[ ! -f ~/recon/$1.out ] && mv $1.out ~/recon/$1/ 
message "Scanner%20Done%20for%20$1"