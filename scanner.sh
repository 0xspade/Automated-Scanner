#!/bin/bash

passwordx=$(cat ~/tools/.creds | grep password | awk {'print $3'})

[ ! -f ~/recon ] && mkdir ~/recon
[ ! -f ~/recon/$1 ] && mkdir ~/recon/$1
[ ! -f ~/recon/$1/whatweb ] && mkdir ~/recon/$1/whatweb
[ ! -f ~/recon/$1/eyewitness ] && mkdir ~/recon/$1/eyewitness
[ ! -f ~/recon/$1/shodan ] && mkdir ~/recon/$1/shodan
[ ! -f ~/recon/$1/dirsearch ] && mkdir ~/recon/$1/dirsearch
[ ! -f ~/recon/$1/default-credential ] && mkdir ~/recon/$1/default-credential
[ ! -f ~/recon/$1/virtual-hosts ] && mkdir ~/recon/$1/virtual-hosts
[ ! -f ~/recon/$1/endpoints ] && mkdir ~/recon/$1/endpoints
[ ! -f ~/recon/$1/github-endpoints ] && mkdir ~/recon/$1/github-endpoints
[ ! -f ~/recon/$1/otxurls ] && mkdir ~/recon/$1/otxurls
[ ! -f ~/recon/$1/waybackurls ] && mkdir ~/recon/$1/waybackurls
sleep 5

message () {
	telegram_bot=$(cat ~/tools/.creds | grep "telegram_bot" | awk {'print $3'})
	telegram_id=$(cat ~/tools/.creds | grep "telegram_id" | awk {'print $3'})
	alert="https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text="
	[ -z $telegram_bot ] && [ -z $telegram_id ] || curl -g $alert$1 --silent > /dev/null
}

scanned () {
	cat $1 | sort -u | wc -l
}

message "[+]%20Initiating%20scan%20%3A%20$1%20[+]"
date

echo "[+] AMASS SCANNING [+]"
if [ ! -f ~/recon/$1/$1-amass.txt ] && [ ! -z $(which amass) ]; then
	amass enum -passive -d $1 -o ~/recon/$1/$1-amass.txt
	amasscan=`scanned ~/recon/$1/$1-amass.txt`
	message "Amass%20Found%20$amasscan%20subdomain(s)%20for%20$1"
	echo "[+] Amass Found $amasscan subdomains"
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
	echo "[+] Findomain Found $findomainscan subdomains"
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
	echo "[+] Subfinder Found $subfinderscan subdomains"
else
	message "[-]%20Skipping%20Subfinder%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] AQUATONE SCANNING [+]"
if [ ! -f ~/aquatone/$1/urls.txt ] && [ ! -z $(which aquatone-discover) ] && [ ! -z $(which aquatone-scan) ]; then
	aquatone-discover -d $1
	aquatone-scan -d $1 -p huge
	for domains in `cat ~/aquatone/$1/urls.txt`; do domain="${domains#*://}"; domainx="${domain%/*}"; domainz="${domainx%:*}"; echo $domainz | sort -u >> ~/recon/$1/$1-aquatone.txt;done
	aquatonescan=`scanned ~/recon/$1/$1-aquatone.txt`
	message "Aquatone%20Found%20$aquatonescan%20subdomain(s)%20for%20$1"
	echo "[+] Aquatone Found $aquatonescan subdomains"
else
	for domains in `cat ~/aquatone/$1/urls.txt`; do domain="${domains#*://}"; domainx="${domain%/*}"; domainz="${domainx%:*}"; echo $domainz | sort -u >> ~/recon/$1/$1-aquatone.txt;done
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
	echo "[+] Sublist3r Found $sublist3rscan subdomains"
else
	message "[-]%20Skipping%20Sublist3r%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SCANNING SUBDOMAINS WITH PROJECT SONAR [+]"
if [ ! -f ~/recon/$1/$1-project-sonar.txt ] && [ -e ~/tools/forward_dns.json.gz ]; then
	pv ~/tools/forward_dns.json.gz | pigz -dc | grep -E "*[.]$1\"," | jq -r '.name' | sort -u >> ~/recon/$1/$1-project-sonar.txt
	projectsonar=`scanned ~/recon/$1/$1-project-sonar.txt`
	message "Project%20Sonar%20Found%20$projectsonar%20subdomain(s)%20for%20$1"
	echo "[+] Project Sonar Found $projectsonar subdomains"
else
	message "[-]%20Skipping%20Project%20Sonar%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] CRT.SH SCANNING [+]"
if [ ! -f ~/recon/$1/$1-crt.txt ]; then
	curl "https://crt.sh/?q=%25.$1&output=json" --silent | jq '.[]|.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/recon/$1/$1-crt.txt
	crt=`scanned ~/recon/$1/$1-crt.txt`
	message "CRT.SH%20Found%20$crt%20subdomain(s)%20for%20$1"
	echo "[+] CRT.sh Found $crt subdomains"
else
	message "[-]%20Skipping%20CRT.SH%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] GOBUSTER SCANNING [+]"
if [ ! -f ~/recon/$1/$1-gobuster.txt ] && [ ! -z $(which gobuster) ]; then
	[ ! -f ~/tools/all.txt ] && wget "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt" -O ~/tools/all.txt
	gobuster dns -d $1 -t 100 -w ~/tools/all.txt --wildcard -o ~/recon/$1/$1-gobust.txt
	cat ~/recon/$1/$1-gobust.txt | grep "Found:" | awk {'print $2'} > ~/recon/$1/$1-gobuster.txt
	rm ~/recon/$1/$1-gobust.txt
	gobusterscan=`scanned ~/recon/$1/$1-gobuster.txt`
	message "Gobuster%20Found%20$gobusterscan%20subdomain(s)%20for%20$1"
	echo "[+] Gobuster Found $gobusterscan subdomains"
else
	message "[-]%20Skipping%20Gobuster%20Scanning%20for%20$1"
	echo "[!] Skipping ..."		
fi
sleep 5

## Deleting all the results to less disk usage
cat ~/recon/$1/$1-amass.txt ~/recon/$1/$1-project-sonar.txt ~/recon/$1/$1-findomain.txt ~/recon/$1/$1-subfinder.txt ~/recon/$1/$1-aquatone.txt ~/recon/$1/$1-sublist3r.txt ~/recon/$1/$1-crt.txt ~/recon/$1/$1-gobuster.txt | sort -uf > ~/recon/$1/$1-final.txt
rm ~/recon/$1/$1-amass.txt ~/recon/$1/$1-project-sonar.txt ~/recon/$1/$1-findomain.txt ~/recon/$1/$1-subfinder.txt ~/recon/$1/$1-aquatone.txt ~/recon/$1/$1-sublist3r.txt ~/recon/$1/$1-crt.txt ~/recon/$1/$1-gobuster.txt
touch ~/recon/$1/$1-ipz.txt
sleep 5

echo "[+] DNSGEN & TOK SUBDOMAIN PERMUTATION [+]"
if [ ! -f ~/recon/$1/$1-dnsgen.txt ] && [ ! -z $(which dnsgen) ] && [ ! -z $(which tok) ]; then
	cat ~/recon/$1/$1-final.txt | tok | sort -u > ~/recon/$1/$1-final.tmp
	cat ~/recon/$1/$1-final.txt | dnsgen -w ~/recon/$1/$1-final.tmp - | massdns -r ~/tools/massdns/lists/resolvers.txt -o J --flush 2>/dev/null | jq -r .query_name | sort -u | tee -a ~/recon/$1/$1-dnsgen.tmp
	cat ~/recon/$1/$1-dnsgen.tmp | sed 's/-\.//g' | sed 's/-\.//g' | sed 's/-\-\-\-//g' | sort -u > ~/recon/$1/$1-dnsgen.txt
	sleep 3
	dnsgens=`scanned ~/recon/$1/$1-dnsgen.txt`
	message "DNSGEN%20generates%20$dnsgens%20subdomain(s)%20for%20$1"
	echo "[+] DNSGEN generate $dnsgens subdomains"
else
	message "[-]%20Skipping%20DNSGEN%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

cat ~/recon/$1/$1-dnsgen.txt ~/recon/$1/$1-final.txt | sort -u >> ~/recon/$1/$1-fin.txt
rm ~/recon/$1/$1-final.txt && mv ~/recon/$1/$1-fin.txt ~/recon/$1/$1-final.txt
all=`scanned ~/recon/$1/$1-final.txt`
message "Almost%20$all%20Collected%20Subdomains%20for%20$1"
echo "[+] $all collected subdomains"
sleep 3

# collecting all IP from collected subdomains
ulimit -n 800000
while read -r domain; do dig +short $domain | grep -v '[[:alpha:]]' | sort -u >> ~/recon/$1/$1-ipf.txt; done < ~/recon/$1/$1-final.txt
cat ~/recon/$1/$1-ipf.txt | sort -u > ~/recon/$1/$1-ipz.txt
rm ~/recon/$1/$1-ipf.txt ~/recon/$1/$1-dnsgen.txt

## segregating cloudflare IP from non-cloudflare IP
## non-sense if I scan cloudflare IP. :(
iprange="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/12 172.64.0.0/13 131.0.72.0/22"
for ip in `cat ~/recon/$1/$1-ipz.txt`; do
	grepcidr "$iprange" <(echo "$ip") >/dev/null && echo "[!] $ip is cloudflare" || echo "$ip" >> ~/recon/$1/$1-ip.txt
done
ipz=`scanned ~/recon/$1/$1-ip.txt`
ip_old=`scanned ~/recon/$1/$1-ipz.txt`
message "$ipz%20non-cloudflare%20IPs%20has%20been%20$collected%20in%20$1%20out%20of%20$ip_old%20IPs"
echo "[+] $ipz non-cloudflare IPs has been collected out of $ip_old IPs!"
rm ~/recon/$1/$1-ipz.txt ~/recon/$1/$1-ips.txt
sleep 5

echo "[+] MASSCAN PORT SCANNING [+]"
if [ ! -f ~/recon/$1/$1-masscan.txt ] && [ ! -z $(which masscan) ]; then
	echo $passwordx | sudo -S masscan -p1-65535 -iL ~/recon/$1/$1-ip.txt --max-rate 10000 -oG ~/recon/$1/$1-masscan.txt
	mass=`scanned ~/recon/$1/$1-ip.txt`
	message "Masscan%20Scanned%20$mass%20IPs%20for%20$1"
	echo "[+] Done masscan for scanning IPs"
else
	message "[-]%20Skipping%20Masscan%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

cat ~/recon/$1/$1-masscan.txt | grep "Host:" | awk {'print $2":"$5'} | awk -F '/' {'print $1'} | sort -u > ~/recon/$1/$1-open-ports.txt  
cat ~/recon/$1/$1-open-ports.txt ~/recon/$1/$1-final.txt > ~/recon/$1/$1-all.txt

echo "[+] HTTProbe Scanning Alive Hosts [+]"
if [ ! -f ~/recon/$1/$1-httprobe.txt ] && [ ! -z $(which httprobe) ]; then
	cat ~/recon/$1/$1-all.txt | httprobe | sort -u >> ~/recon/$1/$1-httprobe.txt
	alivesu=`scanned ~/recon/$1/$1-httprobe.txt`
	message "$alivesu%20alive%20domains%20out%20of%20$all%20domains%20in%20$1"
	echo "[+] $alivesu alive domains out of $all domains/IPs using httprobe"
else
	message "[-]%20Skipping%20httprobe%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] Scanning Alive Hosts [+]"
if [ ! -f ~/recon/$1/$1-alive.txt ] && [ ! -z $(which filter-resolved) ]; then
	cat ~/recon/$1/$1-all.txt | filter-resolved >> ~/recon/$1/$1-alive.txt
	alivesu=`scanned ~/recon/$1/$1-alive.txt`
	rm ~/recon/$1/$1-all.txt
	message "$alivesu%20alive%20domains%20out%20of%20$all%20domains%20in%20$1"
	echo "[+] $alivesu alive domains out of $all domains/IPs using filter-resolved"
else
	message "[-]%20Skipping%20filter-resolved%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

diff --new-line-format="" --unchanged-line-format="" <(cat ~/recon/$1/$1-httprobe.txt | sed 's/http:\/\///g' | sed 's/https:\/\///g' | sort) <(sort ~/recon/$1/$1-alive.txt) > ~/recon/$1/$1-diff.txt

echo "[+] TKO-SUBS for Subdomain TKO [+]"
if [ ! -f ~/recon/$1/$1-subover.txt ] && [ ! -z $(which tko-subs) ]; then
	[ ! -f ~/tools/providers-data.csv ] && wget "https://raw.githubusercontent.com/anshumanbh/tko-subs/master/providers-data.csv" -O ~/tools/providers-data.csv
	tko-subs -domains=recon/$1/$1-alive.txt -data=tools/providers-data.csv -output=recon/$1/$1-tkosubs.txt
	rm ~/recon/$1/$1-subtemp.txt ~/recon/$1/$1-subtmp.txt
	message "TKO-Subs%20scanner%20done%20for%20$1"
	echo "[+] TKO-Subs scanner is done"
else
	message "[-]%20Skipping%20tko-subs%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBJACK for Subdomain TKO [+]"
if [ ! -f ~/recon/$1/$1-subjack.txt ] && [ ! -z $(which subjack) ]; then
	[ ! -f ~/tools/fingerprints.json ] && wget "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json" -O ~/tools/fingerprints.json
	subjack -w ~/recon/$1/$1-alive.txt -a -timeout 15 -c ~/tools/fingerprints.json -v -m -o ~/recon/$1/$1-subtemp.txt
	subjack -w ~/recon/$1/$1-alive.txt -a -timeout 15 -c ~/tools/fingerprints.json -v -m -ssl -o ~/recon/$1/$1-subtmp.txt
	cat ~/recon/$1/$1-subtemp.txt ~/recon/$1/$1-subtmp.txt | sort -u > ~/recon/$1/$1-subjack.txt
	rm ~/recon/$1/$1-subtemp.txt ~/recon/$1/$1-subtmp.txt
	message "subjack%20scanner%20done%20for%20$1"
	echo "[+] Subjack scanner is done"
else
	message "[-]%20Skipping%20subjack%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] COLLECTING ENDPOINTS [+]"
for urlz in `cat ~/recon/$1/$1-httprobe.txt`; do 
	filename=`echo $urlz | sed 's/http:\/\///g' | sed 's/https:\/\//ssl-/g'`
	link=$(python ~/tools/LinkFinder/linkfinder.py -i $urlz -d -o cli | grep -E "*.js$" | grep "$1" | grep "Running against:" |awk {'print $3'})
	if [ ! -z $link ]; then
		for linx in $link; do
			python3 ~/tools/LinkFinder/linkfinder.py -i $linx -o cli > ~/recon/$1/endpoints/$filename-result.txt
		done
	else
		echo "------ :) ------"
	fi
done
message "Done%20collecting%20endpoint%20in%20$1"
echo "[+] Done collecting endpoint"
sleep 5

echo "[+] COLLECTING ENDPOINTS FROM GITHUB [+]"
if [ ! -z $(cat ~/tools/.tokens) ] && [ -e ~/tools/.tokens ]; then
	for url in `cat ~/recon/$1/$1-httprobe.txt | sed 's/http:\/\///g' | sed 's/https:\/\///g' | sort -u`; do 
		python3 ~/tools/github-endpoints.py -d $url -s -r > ~/recon/$1/github-endpoints/$url.txt
		sleep 3
	done
	message "Done%20collecting%20endpoint%20in%20$1"
	echo "[+] Done collecting endpoint"
else
	message "Skipping%20github-endpoint%20script%20in%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] MASSDNS SCANNING [+]"
massdns -r ~/tools/massdns/lists/resolvers.txt ~/recon/$1/$1-alive.txt -o S > ~/recon/$1/$1-massdns.txt
message "Done%20Massdns%20Scanning%20for%20$1"
echo "[+] Done massdns for scanning assets"
sleep 5

echo "[+] SHODAN HOST SCANNING [+]"
if [ ! -z $(which shodan) ]; then
	for ip in `cat ~/recon/$1/$1-ip.txt`; do filename=`echo $ip | sed 's/\./_/g'`;shodan host $ip > ~/recon/$1/shodan/$filename.txt; done
	message "Done%20Shodan%20for%20$1"
	echo "[+] Done shodan"
else
	message "[-]%20Skipping%20Shodan%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5	

echo "[+] EYEWITNESS SCREENSHOT [+]"
if [ ! -z $(which eyewitness) ]; then
	echo $passwordx | sudo -S eyewitness -f ~/recon/$1/$1-httprobe.txt --web --timeout 10 --no-dns --no-prompt --cycle all -d ~/recon/$1/eyewitness
	message "Done%20Eyewitness%20for%20Screenshot%20for%20$1"
	echo "[+] Done eyewitness for screenshot of Alive assets"
else
	message "[-]%20Skipping%20Eyewitness%20Screenshot%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] NMAP PORT SCANNING [+]"
big_ports=`cat ~/recon/$1/$1-masscan.txt | grep 'Host:' | awk {'print $5'} | awk -F '/' {'print $1'} | sort -u | paste -s -d ','`
if [ ! -f ~/recon/$1/$1-nmap.txt ] && [ ! -z $(which nmap) ]; then
	[ ! -f ~/tools/nmap-bootstrap.xsl ] && wget "https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl" -O ~/tools/nmap-bootstrap.xsl
	echo $passwordx | sudo -S nmap -sSVC -A -O -Pn -p$big_ports -iL ~/recon/$1/$1-ip.txt --script http-enum,http-title --stylesheet ~/tools/nmap-bootstrap.xsl -oA ~/recon/$1/$1-nmap
	nmaps=`scanned ~/recon/$1/$1-ip.txt`
	xsltproc -o ~/recon/$1/$1-nmap.html ~/tools/nmap-bootstrap.xsl ~/recon/$1/$1-nmap.xml
	message "Nmap%20Scanned%20$nmaps%20IPs%20for%20$1"
	echo "[+] Done nmap for scanning IPs"
else
	message "[-]%20Skipping%20Nmap%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] DEFAULT CREDENTIAL SCANNING [+]"
if [ -e ~/tools/changeme/changeme.py ] && [ "active" == `systemctl is-active redis` ]; then
	for targets in `cat ~/recon/$1/$1-open-ports.txt`;do python3 ~/tools/changeme/changeme.py --redishost redis --all --threads 20 --portoverride $targets -d --fresh -v --ssl --timeout 25 -o ~/recon/$1/default-credential/$targets-changeme.csv; done
	message "Default%20Credential%20done%20for%20$1"
	echo "[+] Done changeme for scanning default credentials"
	for process in `ps aux | grep changeme | awk {'print $2'}`; do kill -9 $process > /dev/null; done
else
	message "[-]%20Skipping%20Default%20Credential%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] WHATWEB SCANNING FOR FINGERPRINTING [+]"
if [ ! -z $(which whatweb) ]; then
	for d in `cat ~/recon/$1/$1-masscan.txt | grep "Host:" | awk {'print $2":"$5'} | awk -F "/" {'print $1'}`;do whatweb $d | sed 's/, /  \r\n/g' >> ~/recon/$1/whatweb/$d-whatweb.txt; done
	for d in `cat ~/recon/$1/$1-alive.txt`; do whatweb $d | sed 's/, /  \r\n/g' >> ~/recon/$1/whatweb/$d-whatweb.txt; done
	message "Done%20whatweb%20for%20fingerprinting%20$1"
	echo "[+] Done whatweb for fingerprinting the assets!"
else
	message "[-]%20Skipping%20whatweb%20for%20fingerprinting%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] OTXURL Scanning for Archived Endpoints [+]"
for u in `cat ~/recon/$1/$1-httprobe.txt | sed 's/http:\/\///g' | sed 's/https:\/\///g' | sort -u`;do echo $u | otxurls | grep "$u" >> ~/recon/$1/otxurls/tmp-$u.txt; done
cat ~/recon/$1/otxurls/* | sort -u >> ~/recon/$1/otxurls/$1-otxurl.txt 
rm ~/recon/$1/otxurls/tmp-*
message "OTXURL%20Done%20for%20$1"
echo "[+] Done otxurls for discovering useful endpoints"
sleep 5

echo "[+] WAYBACKURLS Scanning for Archived Endpoints [+]"
for u in `cat ~/recon/$1/$1-httprobe.txt | sed 's/http:\/\///g' | sed 's/https:\/\///g' | sort -u`;do echo $u | waybackurls | grep "$u" >> ~/recon/$1/waybackurls/tmp-$u.txt; done
cat ~/recon/$1/waybackurls/* | sort -u >> ~/recon/$1/waybackurls/$1-waybackurls.txt 
rm ~/recon/$1/waybackurls/tmp-*
message "WAYBACKURLS%20Done%20for%20$1"
echo "[+] Done waybackurls for discovering useful endpoints"
sleep 5

echo "[+] Scanning for Virtual Hosts Resolution [+]"
if [ ! -z $(which ffuf) ]; then
	[ ! -f ~/tools/virtual-host-scanning.txt ] && wget "https://raw.githubusercontent.com/codingo/VHostScan/master/VHostScan/wordlists/virtual-host-scanning.txt" -O ~/tools/virtual-host-scanning.txt
	cat ~/recon/$1/$1-final.txt ~/recon/$1/$1-dnsgen.tmp ~/recon/$1/$1-final.tmp ~/recon/$1/$1-diff.txt ~/tools/virtual-host-scanning.txt | sed "s/\%s/$1/g" | sort -u >> ~/recon/$1/$1-temp-vhost-wordlist.txt
	path=$(pwd)
	ffuf -c -w "$path/recon/$1/$1-temp-vhost-wordlist.txt:HOSTS" -w "$path/recon/$1/$1-open-ports.txt:TARGETS" -u http://TARGETS -k -H "Host: HOSTS" -mc all -fc 500-599 -o ~/recon/$1/virtual-hosts/$1.txt
	ffuf -c -w "$path/recon/$1/$1-temp-vhost-wordlist.txt:HOSTS" -w "$path/recon/$1/$1-open-ports.txt:TARGETS" -u https://TARGETS -k -H "Host: HOSTS" -mc all -fc 500-599 -o ~/recon/$1/virtual-hosts/$1-ssl.txt
	message "Virtual%20Host(s)%20done%20for%20$1"
	rm ~/recon/$1/$1-dnsgen.tmp ~/recon/$1/$1-final.tmp ~/recon/$1/$1-diff.txt
	echo "[+] Done ffuf for scanning virtual hosts"
else
	message "[-]%20Skipping%20ffuf%20for%20vhost%20scanning"
	echo "[!] Skipping ..."
fi
rm ~/recon/$1/$1-temp-vhost-wordlist.txt 
sleep 5

echo "[+] DirSearch Scanning for Sensitive Files [+]"
cat ~/recon/$1/$1-httprobe.txt | sed 's/http:\/\///g' | sed 's/https:\/\///g' | sort -u | xargs -P10 -I % sh -c "python3 ~/dirsearch/dirsearch.py -u % -e php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp,yaml,yml,config,save,rsa,ppk -x 400,403,401,500,406,503,502 -t 100 --random-agents -b --plain-text-report ~/recon/$1/dirsearch/%-dirsearch.txt"
echo "[+] Done dirsearch for file and directory scanning"
sleep 5

[ ! -f ~/$1.out ] && mv $1.out ~/recon/$1/ 
message "Scanner%20Done%20for%20$1"
date
echo "[+] Done scanner :)"
