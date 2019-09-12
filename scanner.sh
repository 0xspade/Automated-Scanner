#!/bin/bash

# amass, subfinder, snapd, aquatone, project sonar, gobuster, masscan, nmap, sensitive.py, curl, CRLF-Injection-Scanner, otxurls, waybackurls, DirSearch, LinkFinder, VHostScan


passwordx=""

if [ ! -f ~/$1 ]; then
	mkdir ~/$1
fi

if [ ! -f ~/$1/dirsearch ]; then
	mkdir ~/$1/dirsearch
fi

if [ ! -f ~/$1/virtual-hosts ]; then
	mkdir ~/$1/virtual-hosts
fi

if [ ! -f ~/$1/endpoints ]; then
	mkdir ~/$1/endpoints
fi

if [ ! -f ~/$1/otxurls ]; then
	mkdir ~/$1/otxurls
fi

if [ ! -f ~/$1/waybackurls ]; then
	mkdir ~/$1/waybackurls
fi
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
if [ ! -f ~/$1/$1-amass.txt ]; then
	amass enum -brute -active -d $1 -o ~/$1/$1-amass.txt -config ~/amass/config.ini
	amasscan=`scanned ~/$1/$1-amass.txt`
	message "Amass%20Found%20$amasscan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "Skipping%20Amass%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBFINDER SCANNING [+]"
if [ ! -f ~/$1/$1-subfinder.txt ]; then
	subfinder -d $1 -o ~/$1/$1-subfinder.txt
	subfinderscan=`scanned ~/$1/$1-subfinder.txt`
	message "SubFinder%20Found%20$subfinderscan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "Skipping%20Subfinder%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] AQUATONE SCANNING [+]"
if [ ! -f ~/aquatone/$1/urls.txt ]; then
	aquatone-discover -d $1
	aquatone-scan -d $1 -p huge
	for domains in `cat ~/aquatone/$1/urls.txt`; do domain="${domains#*://}"; domainx="${domain%/*}"; echo $domainx >> ~/$1/$1-aquatone.txt;done
	aquatonescan=`scanned ~/$1/$1-aquatone.txt`
	message "Aquatone%20Found%20$aquatonescan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	for domains in `cat ~/aquatone/$1/urls.txt`; do domain="${domains#*://}"; domainx="${domain%/*}"; echo $domainx >> ~/$1/$1-aquatone.txt;done
	aquatonescan=`scanned ~/$1/$1-aquatone.txt`
	message "Skipping%20Aquatone%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBLIST3R SCANNING [+]"
if [ ! -f ~/$1/$1-sublist3r.txt ]; then
	python ~/Sublist3r/sublist3r.py -b -d $1 -o ~/$1/$1-sublist3r.txt
	sublist3rscan=`scanned ~/$1/$1-sublist3r.txt`
	message "Sublist3r%20Found%20$sublist3rscan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "Skipping%20Sublist3r%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5


echo "[+] SCANNING SUBDOMAINS WITH PROJECT SONAR [+]"
if [ ! -f ~/$1/$1-project-sonar.txt ]; then
	dom=$1
	domainss="${dom//./\\.}"
	pv ~/2019-07-26-1564183467-fdns_any.json.gz | pigz -dc | grep -E ".\\$domainss\"," | jq -r '.name' | sort -u | grep -E "*[.]$domainss" >> ~/$1/$1-project-sonar.txt
	projectsonar=`scanned ~/$1/$1-project-sonar.txt`
	message "Project%20Sonar%20Found%20$projectsonar%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "Skipping%20Project%20Sonar%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] GOBUSTER SCANNING [+]"
if [ ! -f ~/$1/$1-gobuster.txt ]; then
	gobuster dns -d $1 -t 100 -w all.txt --wildcard -o ~/$1/$1-gobust.txt
	gobusterscan=`scanned ~/$1/$1-gobust.txt`
	message "Gobuster%20Found%20$gobusterscan%20subdomain(s)%20for%20$1"
	echo "[+] Done"
else
	message "Skipping%20Gobuster%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5


cat ~/$1/$1-gobust.txt | grep "Found:" | awk {'print $2'} > ~/$1/$1-gobuster.txt
rm ~/$1/$1-gobust.txt
sleep 5

## Deleting all the results to less disk usage
cat ~/$1/$1-amass.txt ~/$1/$1-project-sonar.txt ~/$1/$1-subfinder.txt ~/$1/$1-aquatone.txt ~/$1/$1-sublist3r.txt ~/$1/$1-gobuster.txt | sort -uf > ~/$1/$1-final.txt
rm ~/$1/$1-amass.txt ~/$1/$1-project-sonar.txt ~/$1/$1-subfinder.txt ~/$1/$1-aquatone.txt ~/$1/$1-sublist3r.txt ~/$1/$1-gobuster.txt
touch ~/$1/$1-ipz.txt
sleep 5


all=`scanned ~/$1/$1-final.txt`
message "Almost%20$all%20Collected%20Subdomains%20for%20$1"
sleep 3


cp ~/$1/$1-final.txt ~/$1/ports.txt
for ipx in `cat ~/$1/ports.txt`; do i="${ipx%:*}"; echo $i >> ~/$1/$1-ips.txt;done
rm ~/$1/ports.txt
sleep 5

# collecting all IP from collected subdomains
for ip in `cat ~/$1/$1-ips.txt`; do host $ip | grep "has address" | awk {'print $4'} >> ~/$1/$1-ipf.txt;done
cat ~/$1/$1-ipf.txt | sort -u >> ~/$1/$1-ipz.txt
rm ~/$1/$1-ipf.txt

## segregating cloudflare IP from non-cloudflare IP
## non-sense if I scan cloudflare IP. :(
iprange="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/12 172.64.0.0/13 131.0.72.0/22"
for ip in `cat ~/$1/$1-ip.txt`; do
	grepcidr "$iprange" <(echo "$ip") >/dev/null && echo "$ip is cloudflare" || echo "$ip" >> ~/$1/$1-ip.txt
done
ipz=`scanned ~/$1/$1-ip.txt`
message "$ipz%20non-cloudflare%20IPs%20has%20been%20$collected%20in%20$1"
cat ~/$1/$1-ip.txt ~/$1/$1-final.txt > ~/$1/$1-all.txt
sleep 5

declare -a protocol=("http" "https")

echo "[+] Scanning for Alive Hosts [+]"
for alive in `cat ~/$1/$1-all.txt`; do
	for proto in ${protocol[@]}; do
		iamalive=$(curl -s -o /dev/null -w "%{http_code}" -k $proto://$alive --max-time 15)
		if [ $iamalive == 000 ]
		then
			echo "[$iamalive] $alive tango down!"
		else
			echo "[$iamalive] $alive is up!"
			echo $alive >> ~/$1/$1-allx.txt
		fi
	done
done
alivesu=`scanned ~/$1/$1-allx.txt`
cat ~/$1/$1-allx.txt | sort -u > ~/$1/$1-allz.txt
rm ~/$1/$1-allx.txt
message "$alivesu%20alive%20domains%20out%20of%20$all%20domains%20in%20$1"
sleep 5

echo "[+] SCANNING CRLF [+]"
python3 ~/CRLF-Injection-Scanner/crlf_scan.py -i ~/$1/$1-allz.txt -o ~/$1/$1-crlf.txt
message "CRLF%20Scanning%20done%20for%20$1"
sleep 5

echo "[+] COLLECTING ENDPOINTS [+]"
for urlz in `cat ~/$1/$1-allz.txt`; do 
	for protoc in ${protocol[@]}; do
		python ~/LinkFinder/linkfinder.py -i $protoc://$urlz -d -o ~/$1/endpoints/$protoc_$urlz-result.html
	done
done
message "Done%20collecting%20endpoint%20in%20$1"
sleep 5

echo "[+] MASSDNS SCANNING [+]"
massdns -r ~/massdns/lists/resolvers.txt -t CNAME ~/$1/$1-allz.txt -o S > $1/$1-massdns.txt
message "Done%20Massdns%20CNAME%20Scanning%20for%20$1"
sleep 5

echo "[+] PORT SCANNING [+]"
cat ~/$1/$1-allz.txt | aquatone -ports xlarge -out ~/$1/$1-ports
message "Done%20Aquatone%20Port%20Scanning%20for%20$1"
sleep 5


echo "[+] MASSCAN PORT SCANNING [+]"
if [ ! -f ~/$1/$1-masscan.txt ]; then
	echo $passwordx | sudo -S masscan -p1-65535 -iL ~/$1/$1-ip.txt --max-rate 10000 -oG ~/$1/$1-masscan.txt
	mass=`scanned $1/$1-ip.txt`
	message "Masscan%20Scanned%20$mass%20IPs%20for%20$1"
	echo "[+] Done"
else
	message "Skipping%20Masscan%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5


echo "[+] NMAP PORT SCANNING [+]"
if [ ! -f ~/$1/$1-nmap.txt ]; then
	nmap -sV -Pn -p- -iL ~/$1/$1-ip.txt --stylesheet ~/nmap-bootstrap.xsl -oA ~/$1/$1-nmap
	nmaps=`scanned ~/$1/$1-ip.txt `
	xsltproc -o ~/$1/$1-nmap.html ~/nmap-bootstrap.xsl ~/$1/$1-nmap.xml
	message "Nmap%20Scanned%20$nmaps%20IPs%20for%20$1"
	echo "[+] Done"
else
	message "Skipping%20Nmap%20Scanning%20for%20$1"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] Scanning for Sensitive Files [+]"
cp ~/$1/$1-allz.txt ~/$1-sensitive.txt
python ~/sensitive.py -u ~/$1-sensitive.txt
sens=`scanned ~/$1-sensitive.txt`
message "Sensitive%20File%20Scanned%20$sens%20asset(s)%20for%20$1"
rm $1-sensitive.txt
sleep 5

echo "[+] OTXURL Scanning for Archived Endpoints [+]"
for u in `cat ~/$1/$1-allz.txt`;do echo $u | otxurls >> ~/$1/otxurls/$u.txt; done
cat ~/$1/otxurls/* | sort -u >> ~/$1/otxurls/$1-otxurl.txt 
rm *.$1.txt
message "OTXURL%20Done%20for%20$1"
sleep 5

echo "[+] WAYBACKURLS Scanning for Archived Endpoints [+]"
for u in `cat ~/$1/$1-allz.txt`;do echo $u | waybackurls >> ~/$1/waybackurls/$u.txt; done
cat ~/$1/waybackurls/* | sort -u >> ~/$1/waybackurls/$1-waybackurls.txt 
rm *.$1.txt
message "WAYBACKURLS%20Done%20for%20$1"
sleep 5

NMAP_FILE=~/$1/$1-nmap.gnmap
cat $NMAP_FILE | awk '{printf "%s\t", $2; for (i=4;i<=NF;i++) { split($i,a,"/"); if (a[2]=="open") printf ",%s",a[1];} print ""}' | sed -e 's/,//' | awk '{print $2}' | sort -u | tr ',' '\n' > ~/$1/tmp.txt
MASSCAN_FILE=~/$1/$1-masscan.txt
cat $MASSCAN_FILE | grep 'Ports: ' | awk '{print $5}' | sort -u >> ~/$1/tmp.txt
for i in `cat ~/$1/tmp.txt`; do test="${i%/open*}"; echo $test >> ~/$1/temp.txt; done
rm ~/$1/tmp.txt;cat ~/$1/temp.txt | sort -u >> ~/$1/tmp.txt; rm ~/$1/temp.txt

echo "[+] Scanning for Virtual Hosts Resolution [+]"
for test in `cat $1/$1-ip.txt`; do
	for p in `cat ~/$1/tmp.txt`; do
		VHostScan -t $test -b $1 -p $p -v --fuzzy-logic --waf --random-agent -w ~/VHostScan/vhost-wordlist.txt -oN ~/$1/virtual-hosts/initial-$test_$p.txt
		VHostScan -t $test -b $1 -p $p -v --fuzzy-logic --waf --ssl --random-agent -w ~/VHostScan/vhost-wordlist.txt -oN ~/$1/virtual-hosts/ssl-$test_$p.txt
		cat ~/$1/virtual-hosts/$test_$p.txt ~/$1/virtual-hosts/ssl-$test_$p.txt >> ~/$1/virtual-hosts/final-$test.txt
		rm -rf ~/$1/virtual-hosts/initial-* ~/$1/virtual-hosts/ssl-*
	done
done
vt=`ls ~/$1/virtual-hosts/* | wc -l`
message "Virtual%20Host(s)%20found%20$vt"
rm ~/$1/tmp.txt
sleep 5

echo "[+] DirSearch Scanning for Sensitive Files [+]"
for u in `cat ~/$1/$1-allz.txt`;do python3 ~/dirsearch/dirsearch.py -u $u --ext php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old -t 100 -R 5 --http-method=POST -F -f --random-agents -b -w ~/newlist.txt --plain-text-report ~/$1/dirsearch/$u-dirsearch.txt;done
sleep 5

message "Scanner%20Done%20for%20$1"
