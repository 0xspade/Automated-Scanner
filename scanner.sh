#!/bin/bash

# amass, subfinder, snapd, aquatone, project sonar, grepcidr, gobuster, masscan, nmap, sensitive.py, curl, CRLF-Injection-Scanner, otxurls, waybackurls, DirSearch, LinkFinder, VHostScan

## Password for root is required in masscan idk why :D
passwordx=""

[ ! -f ~/$1 ] && mkdir ~/$1
[ ! -f ~/$1/dirsearch ] && mkdir ~/$1/dirsearch
[ ! -f ~/$1/virtual-hosts ] && mkdir ~/$1/virtual-hosts
[ ! -f ~/$1/endpoints ] && mkdir ~/$1/endpoints
[ ! -f ~/$1/otxurls ] && mkdir ~/$1/otxurls
[ ! -f ~/$1/waybackurls ] && mkdir ~/$1/waybackurls
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

echo "[+] AMASS SCANNING [+]"
if [ ! -f ~/$1/$1-amass.txt ] && [ ! -z $(which amass) ]; then
	amass enum -brute -active -d $1 -o ~/$1/$1-amass.txt -config ~/amass/config.ini
	amasscan=`scanned ~/$1/$1-amass.txt`
	message "Amass%20Found%20$amasscan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Amass%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBFINDER SCANNING [+]"
if [ ! -f ~/$1/$1-subfinder.txt ] && [ ! -z $(which subfinder) ]; then
	subfinder -d $1 -o ~/$1/$1-subfinder.txt
	subfinderscan=`scanned ~/$1/$1-subfinder.txt`
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
	for domains in `cat ~/aquatone/$1/urls.txt`; do domain="${domains#*://}"; domainx="${domain%/*}"; echo $domainx >> ~/$1/$1-aquatone.txt;done
	aquatonescan=`scanned ~/$1/$1-aquatone.txt`
	message "Aquatone%20Found%20$aquatonescan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	for domains in `cat ~/aquatone/$1/urls.txt`; do domain="${domains#*://}"; domainx="${domain%/*}"; echo $domainx >> ~/$1/$1-aquatone.txt;done
	aquatonescan=`scanned ~/$1/$1-aquatone.txt`
	message "[-]%20Skipping%20Aquatone%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBLIST3R SCANNING [+]"
if [ ! -f ~/$1/$1-sublist3r.txt ] && [ -e ~/Sublist3r/sublist3r.py ]; then
	python ~/Sublist3r/sublist3r.py -b -d $1 -o ~/$1/$1-sublist3r.txt
	sublist3rscan=`scanned ~/$1/$1-sublist3r.txt`
	message "Sublist3r%20Found%20$sublist3rscan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Sublist3r%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SCANNING SUBDOMAINS WITH PROJECT SONAR [+]"
if [ ! -f ~/$1/$1-project-sonar.txt ] && [ -e ~/forward_dns.json.gz ] && [ -e ~/reverse_dns.json.gz ]; then
	pv ~/forward_dns.json.gz | pigz -dc | grep -E "*[.]$1\"," | jq -r '.name' | sort -u >> ~/$1/$1-project-sonar.txt
	scanned ~/$1/$1-project-sonar.txt
	pv ~/reverse_dns.json.gz | pigz -dc | grep -E "*[.]$1\"," | jq -r '.value' | sort -u >> ~/$1/$1-project-sonar.txt
	projectsonar=`scanned ~/$1/$1-project-sonar.txt`
	message "Project%20Sonar%20Found%20$projectsonar%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Project%20Sonar%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] CRT.SH SCANNING [+]"
if [ ! -f ~/$1/$1-crt.txt ]; then
	curl "https://crt.sh/?q=%25.$1&output=json" --silent | jq '.[]|.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/$1/$1-crt.txt
	scanned ~/$1/$1-crt.txt
	sleep 3
	curl "https://crt.sh/?q=%25dev%25.$1&output=json" --silent | jq '.[]|.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/$1/$1-crt.txt
	scanned ~/$1/$1-crt.txt
	sleep 3
	curl "https://crt.sh/?q=%25stg%25.$1&output=json" --silent | jq '.[]|.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/$1/$1-crt.txt
	scanned ~/$1/$1-crt.txt
	sleep 3
	curl "https://crt.sh/?q=%25api%25.$1&output=json" --silent | jq '.[]|.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/$1/$1-crt.txt
	scanned ~/$1/$1-crt.txt
	sleep 3
	curl "https://crt.sh/?q=%25staging%25.$1&output=json" --silent | jq '.[]|.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/$1/$1-crt.txt
	scanned ~/$1/$1-crt.txt
	sleep 3
	curl "https://crt.sh/?q=%25mobile%25.$1&output=json" --silent | jq '.[]|.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/$1/$1-crt.txt
	scanned ~/$1/$1-crt.txt
	sleep 3
	curl "https://crt.sh/?q=%25admin%25.$1&output=json" --silent | jq '.[]|.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/$1/$1-crt.txt
	scanned ~/$1/$1-crt.txt
	sleep 3
	curl "https://crt.sh/?q=%25console%25.$1&output=json" --silent | jq '.[]|.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/$1/$1-crt.txt
	scanned ~/$1/$1-crt.txt
	sleep 3
	curl "https://crt.sh/?q=%25portal%25.$1&output=json" --silent | jq '.[]|.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/$1/$1-crt.txt
	scanned ~/$1/$1-crt.txt
	sleep 3
	curl "https://crt.sh/?q=%25internal%25.$1&output=json" --silent | jq '.[]|.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/$1/$1-crt.txt
	scanned ~/$1/$1-crt.txt
	sleep 3
	cat ~/$1/$1-crt.txt | sort -u >> ~/$1/$1-crtx.txt && rm ~/$1/$1-crt.txt && mv ~/$1/$1-crtx.txt ~/$1/$1-crt.txt
	crt=`scanned ~/$1/$1-crt.txt`
	message "CRT.SH%20Found%20$crt%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20CRT.SH%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] GOBUSTER SCANNING [+]"
if [ ! -f ~/$1/$1-gobuster.txt ] && [ ! -z $(which gobuster) ]; then
	[ ! -f ~/all.txt ] && wget "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt" -O ~/all.txt
	gobuster dns -d $1 -t 100 -w ~/all.txt --wildcard -o ~/$1/$1-gobust.txt
	cat ~/$1/$1-gobust.txt | grep "Found:" | awk {'print $2'} > ~/$1/$1-gobuster.txt
	rm ~/$1/$1-gobust.txt
	gobusterscan=`scanned ~/$1/$1-gobuster.txt`
	message "Gobuster%20Found%20$gobusterscan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Gobuster%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

## Deleting all the results to less disk usage
cat ~/$1/$1-amass.txt ~/$1/$1-project-sonar.txt ~/$1/$1-subfinder.txt ~/$1/$1-aquatone.txt ~/$1/$1-sublist3r.txt ~/$1/$1-crt.txt ~/$1/$1-gobuster.txt | sort -uf > ~/$1/$1-final.txt
rm ~/$1/$1-amass.txt ~/$1/$1-project-sonar.txt ~/$1/$1-subfinder.txt ~/$1/$1-aquatone.txt ~/$1/$1-sublist3r.txt ~/$1/$1-crt.txt ~/$1/$1-gobuster.txt
touch ~/$1/$1-ipz.txt
sleep 5

echo "[+] ALTDNS SCANNING [+]"
if [ ! -f ~/$1/$1-altdns.txt ] && [ ! -z $(which altdns) ]; then
	[ ! -f ~/altdns.txt ] && wget "https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt" -O ~/altdns.txt
	altdns -i ~/$1/$1-final.txt -w ~/altdns.txt -t 100 -e -r -o ~/$1/$1-altdns.txt -s ~/$1/$1-altdns-2.txt
	sleep 3
	rm ~/$1/$1-altdns.txt
	for alt in `cat ~/$1/$1-altdns-2.txt`; do dns="${alt%:*}"; echo $dns | grep -E "*[.]$1\$" >> ~/$1/$1-altdns.txt; done
	altdnx=`scanned ~/$1/$1-altdns.txt`
	message "Altdns%20Found%20$altdnx%20subdomain(s)%20for%20$1"
else
	message "[-]%20Skipping%20Altdns%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

cat ~/$1/$1-altdns.txt ~/$1/$1-final.txt | sort -u >> ~/$1/$1-fin.txt
rm ~/$1/$1-final.txt && mv ~/$1/$1-fin.txt ~/$1/$1-final.txt
all=`scanned ~/$1/$1-final.txt`
message "Almost%20$all%20Collected%20Subdomains%20for%20$1"
sleep 3

cp ~/$1/$1-final.txt ~/$1/ports.txt
for ipx in `cat ~/$1/ports.txt`; do i="${ipx%:*}"; echo $i | grep -E "*[.]$1\$" >> ~/$1/$1-ips.txt;done
rm ~/$1/ports.txt
sleep 5

# collecting all IP from collected subdomains
for ip in `cat ~/$1/$1-ips.txt`; do host $ip | grep "has address" | awk {'print $4'} >> ~/$1/$1-ipf.txt;done
cat ~/$1/$1-ipf.txt | sort -u >> ~/$1/$1-ipz.txt
rm ~/$1/$1-ipf.txt

## segregating cloudflare IP from non-cloudflare IP
## non-sense if I scan cloudflare IP. :(
iprange="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/12 172.64.0.0/13 131.0.72.0/22"
for ip in `cat ~/$1/$1-ipz.txt`; do
	grepcidr "$iprange" <(echo "$ip") >/dev/null && echo "$ip is cloudflare" || echo "$ip" >> ~/$1/$1-ip.txt
done
rm ~/$1/$1-ipz.txt ~/$1/$1-ips.txt
ipz=`scanned ~/$1/$1-ip.txt`
message "$ipz%20non-cloudflare%20IPs%20has%20been%20$collected%20in%20$1"
cat ~/$1/$1-ip.txt ~/$1/$1-final.txt > ~/$1/$1-all.txt
sleep 5

echo "[+] HTTPROBE Scanning for Alive Hosts [+]"
if [ ! -f ~/$1/$1-httprobe.txt ] && [ ! -z $(which httprobe) ]; then
	cat ~/$1/$1-all.txt | httprobe | sed 's/http:\/\///g' | sed 's/https:\/\///g' | sort -u >> ~/$1/$1-httprobe.txt
	alivesu=`scanned ~/$1/$1-httprobe.txt`
	rm ~/$1/$1-all.txt ~/$1/$1-final.txt
	message "$alivesu%20alive%20domains%20out%20of%20$all%20domains%20in%20$1"
else
	message "[-]%20Skipping%20httprobe%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBOVER for Subdomain TKO [+]"
if [ ! -f ~/$1/$1-subover.txt ] && [ ! -z $(which SubOver) ]; then
	[ ! -f ~/providers.json ] && wget "https://raw.githubusercontent.com/Ice3man543/SubOver/master/providers.json" -O ~/providers.json
	SubOver -l ~/$1/$1-httprobe.txt -timeout 15 >> ~/$1/$1-subover.txt
	SubOver -l ~/$1/$1-httprobe.txt -timeout 15 -https >> ~/$1/$1-subover.txt
	message "Subover%20scanner%20done%20for%20$1"
else
	message "[-]%20Skipping%20subover%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBJACK for Subdomain TKO [+]"
if [ ! -f ~/$1/$1-subjack.txt ] && [ ! -z $(which subjack) ]; then
	[ ! -f ~/fingerprints.json ] && wget "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json" -O ~/fingerprints.json
	subjack -w ~/$1/$1-httprobe.txt -a -timeout 15 -c ~/fingerprints.json -v -m -o ~/$1/$1-subjack.txt
	subjack -w ~/$1/$1-httprobe.txt -a -timeout 15 -c ~/fingerprints.json -v -m -ssl -o ~/$1/$1-subjack.txt
	message "subjack%20scanner%20done%20for%20$1"
else
	message "[-]%20Skipping%20subjack%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SCANNING CRLF [+]"
python3 ~/CRLF-Injection-Scanner/crlf_scan.py -i ~/$1/$1-httprobe.txt -o ~/$1/$1-crlf.txt
message "CRLF%20Scanning%20done%20for%20$1"
sleep 5

declare -a protocol=("http" "https")
echo "[+] COLLECTING ENDPOINTS [+]"
for urlz in `cat ~/$1/$1-httprobe.txt`; do 
	for protoc in ${protocol[@]}; do
		python ~/LinkFinder/linkfinder.py -i $protoc://$urlz -d -o ~/$1/endpoints/$protoc_$urlz-result.html
	done
done
message "Done%20collecting%20endpoint%20in%20$1"
sleep 5

echo "[+] MASSDNS SCANNING [+]"
massdns -r ~/massdns/lists/resolvers.txt -t CNAME ~/$1/$1-httprobe.txt -o S > $1/$1-massdns.txt
message "Done%20Massdns%20CNAME%20Scanning%20for%20$1"
sleep 5

echo "[+] PORT SCANNING [+]"
cat ~/$1/$1-httprobe.txt | aquatone -ports xlarge -out ~/$1/$1-ports
message "Done%20Aquatone%20Port%20Scanning%20for%20$1"
sleep 5


echo "[+] MASSCAN PORT SCANNING [+]"
if [ ! -f ~/$1/$1-masscan.txt ] && [ ! -z $(which masscan) ]; then
	echo $passwordx | sudo -S masscan -p1-65535 -iL ~/$1/$1-ip.txt --max-rate 10000 -oG ~/$1/$1-masscan.txt
	mass=`scanned $1/$1-ip.txt`
	message "Masscan%20Scanned%20$mass%20IPs%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Masscan%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5


echo "[+] NMAP PORT SCANNING [+]"
if [ ! -f ~/$1/$1-nmap.txt ] && [ ! -z $(which nmap) ]; then
	[ ! -f ~/nmap-bootstrap.xsl ] && wget "https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl" -O ~/nmap-bootstrap.xsl
	nmap -sV -Pn -p- -iL ~/$1/$1-ip.txt --stylesheet ~/nmap-bootstrap.xsl -oA ~/$1/$1-nmap
	nmaps=`scanned ~/$1/$1-ip.txt `
	xsltproc -o ~/$1/$1-nmap.html ~/nmap-bootstrap.xsl ~/$1/$1-nmap.xml
	message "Nmap%20Scanned%20$nmaps%20IPs%20for%20$1"
	echo "[+] Done"
else
	message "[-]%20Skipping%20Nmap%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] Scanning for Sensitive Files [+]"
cp ~/$1/$1-httprobe.txt ~/$1-sensitive.txt
python ~/sensitive.py -u ~/$1-sensitive.txt
sens=`scanned ~/$1-sensitive.txt`
message "Sensitive%20File%20Scanned%20$sens%20asset(s)%20for%20$1"
rm $1-sensitive.txt
sleep 5

echo "[+] OTXURL Scanning for Archived Endpoints [+]"
for u in `cat ~/$1/$1-httprobe.txt`;do echo $u | otxurls >> ~/$1/otxurls/$u.txt; done
cat ~/$1/otxurls/* | sort -u >> ~/$1/otxurls/$1-otxurl.txt 
rm ~/$1/otxurls/*.$1.txt
message "OTXURL%20Done%20for%20$1"
sleep 5

echo "[+] WAYBACKURLS Scanning for Archived Endpoints [+]"
for u in `cat ~/$1/$1-httprobe.txt`;do echo $u | waybackurls >> ~/$1/waybackurls/$u.txt; done
cat ~/$1/waybackurls/* | sort -u >> ~/$1/waybackurls/$1-waybackurls.txt 
rm ~/$1/waybackurls/*.$1.txt
message "WAYBACKURLS%20Done%20for%20$1"
sleep 5

echo "[+] Scanning for Virtual Hosts Resolution [+]"
declare -a vhost=("66" "80" "81" "443" "445" "457" "1080" "1100" "1241" "1352" "1433" "1434" "1521" "1944" "2301" "3128" "3306" "4000" "4001" "4002" "4100" "5000" "5432" "5800" "5801" "5802" "6346" "6347" "7001" "7002" "8080" "8888" "30821")
cat ~/$1/$1-httprobe.txt ~/VHostScan/vhost-wordlist.txt | sort -u >> ~/$1/$1-temp-vhost-wordlist.txt
for test in `cat $1/$1-ip.txt`; do
	for p in ${vhost[@]}; do
		VHostScan -t $test -b $1 -r 80 -p $p -v --fuzzy-logic --waf --random-agent -w ~/$1/$1-temp-vhost-wordlist.txt -oN ~/$1/virtual-hosts/initial-$test_$p.txt
		VHostScan -t $test -b $1 -p $p -r 80 -v --fuzzy-logic --waf --ssl --random-agent -w ~/$1/$1-temp-vhost-wordlist.txt -oN ~/$1/virtual-hosts/ssl-$test_$p.txt
		cat ~/$1/virtual-hosts/initial-$test_$p.txt ~/$1/virtual-hosts/ssl-$test_$p.txt >> ~/$1/virtual-hosts/final-$test.txt
	done
done
vt=`ls ~/$1/virtual-hosts/* | wc -l`
message "Virtual%20Host(s)%20found%20$vt%20in%20$1"
rm ~/$1/$1-temp-vhost-wordlist.txt ~/$1/virtual-hosts/initial-* ~/$1/virtual-hosts/ssl-*
sleep 5

echo "[+] DirSearch Scanning for Sensitive Files [+]"
[ ! -f ~/newlist.txt ] && wget "https://github.com/phspade/Combined-Wordlists/raw/master/newlist.txt" -O ~/newlist.txt
for u in `cat ~/$1/$1-httprobe.txt`;do python3 ~/dirsearch/dirsearch.py -u $u -e php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp -x 400,301,404,303,403,500 -t 200 -R 5 --http-method=POST --random-agents -b -w ~/newlist.txt --plain-text-report ~/$1/dirsearch/$u-dirsearch.txt;done
sleep 5

message "Scanner%20Done%20for%20$1"

