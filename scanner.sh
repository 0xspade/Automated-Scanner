#!/bin/bash

# amass, subfinder, snapd, aquatone, gobuster, masscan, nmap, sensitive.py, curl, CRLF-Injection-Scanner, DirSearch, LinkFinder

telegram_bot=""
passwordx=""
telegram_id=""

if [ ! -f $1 ]; then
	mkdir $1
fi

if [ ! -f $1/dirsearch ]; then
	mkdir $1/dirsearch
fi

if [ ! -f $1/virtual-hosts ]; then
	mkdir $1/virtual-hosts
fi

if [ ! -f $1/CSTI ]; then
	mkdir $1/CSTI
fi

if [ ! -f $1/endpoints ]; then
	mkdir $1/endpoints
fi

sleep 5

echo "[+] AMASS SCANNING [+]"
if [ ! -f $1/$1-amass.txt ]; then
	amass enum -brute -active -d $1 -o $1/$1-amass.txt
	amasscan=`cat $1/$1-amass.txt | wc -l`
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Amass%20Found%20$amasscan%20subdomain(s)%20for%20$1" --silent > /dev/null
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Amass%20Scanning%20for%20$1" --silent > /dev/null
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBFINDER SCANNING [+]"
if [ ! -f $1/$1-subfinder.txt ]; then
	subfinder -d $1 -o $1/$1-subfinder.txt
	subfinderscan=`cat $1/$1-subfinder.txt | wc -l`
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=SubFinder%20Found%20$subfinderscan%20subdomain(s)%20for%20$1" --silent > /dev/null
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Subfinder%20Scanning%20for%20$1" --silent > /dev/null
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] AQUATONE SCANNING [+]"
if [ ! -f ~/aquatone/$1/urls.txt ]; then
	aquatone-discover -d $1
	aquatone-scan -d $1 -p huge
	for domains in `cat ~/aquatone/$1/urls.txt`; do domain="${domains#*://}"; domainx="${domain%/*}"; echo $domainx >> $1/$1-aquatone.txt;done
	aquatonescan=`cat $1/$1-aquatone.txt | wc -l`
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Aquatone%20Found%20$aquatonescan%20subdomain(s)%20for%20$1" --silent > /dev/null
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Aquatone%20Scanning%20for%20$1" --silent > /dev/null
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] SUBLIST3R SCANNING [+]"
if [ ! -f $1/$1-sublist3r.txt ]; then
	python ~/Sublist3r/sublist3r.py -b -d $1 -o $1/$1-sublist3r.txt
	sublist3rscan=`cat $1/$1-sublist3r.txt | wc -l`
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Sublist3r%20Found%20$sublist3rscan%20subdomain(s)%20for%20$1" --silent > /dev/null
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Sublist3r%20Scanning%20for%20$1" --silent > /dev/null
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] GOBUSTER SCANNING [+]"
if [ ! -f $1/$1-gobuster.txt ]; then
	gobuster -m dns -u $1 -t 100 -w all.txt -o $1/$1-gobust.txt -fw
	gobusterscan=`cat $1/$1-gobust.txt | wc -l`
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Gobuster%20Found%20$gobusterscan%20subdomain(s)%20for%20$1" --silent > /dev/null
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Gobuster%20Scanning%20for%20$1" --silent > /dev/null
	echo "[!] Skipping ..."
fi
sleep 5
cat $1/$1-gobust.txt | grep "Found:" | awk {'print $2'} > $1/$1-gobuster.txt
rm $1/$1-gobust.txt
sleep 5


cat $1/$1-amass.txt $1/$1-subfinder.txt $1/$1-aquatone.txt $1/$1-sublist3r.txt $1/$1-gobuster.txt | sort -uf > $1/$1-final.txt
rm $1/$1-amass.txt $1/$1-subfinder.txt $1/$1-aquatone.txt $1/$1-sublist3r.txt $1/$1-gobuster.txt
touch $1/$1-ip.txt
sleep 5


all=`cat $1/$1-final.txt | wc -l`
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Almost%20$all%20Collected%20Subdomain(s)%20for%20$1" --silent > /dev/null
sleep 3



cp $1/$1-final.txt $1/ports.txt
for ipx in `cat $1/ports.txt`; do i="${ipx%:*}"; echo $i >> $1/$1-ips.txt;done
rm $1/ports.txt

sleep 5
for ip in `cat $1/$1-ips.txt`; do host $ip | grep "has address" | awk {'print $4'} >> $1/$1-ipf.txt;done
cat $1/$1-ipf.txt | sort -u >> $1/$1-ip.txt
rm $1/$1-ipf.txt

cat $1/$1-ip.txt $1/$1-final.txt > $1/$1-all.txt
sleep 5

declare -a protocol=("http" "https")

echo "[+] Scanning for Virtual Hosts Resolution [+]"
declare -a home=("127.0.0.1" "proxy" "intranet" "localhost" "mail" "exchange" "ad" "fw" "reverse-proxy")
for test in `cat $1/$1-all.txt`; do
	for proton in ${protocol[@]}; do
		for h in ${home[@]}; do
			for p in {1..65535}; do
				response=$(curl -s -o /dev/null -w "%{http_code}" $proton://$test -H "Host: $h:$p" --max-time 10 --silent)
				if [ $response == 000 ]
				then
					sleep 1
					continue
				else
					if curl -iL $proton://$test --silent | egrep 'cloudflare|Cloudflare|CloudFlare' > /dev/null
					then
						continue
					else
						count=`curl -iL $proton://$test --silent| wc -c`
						echo "$proton://$test is open in $h:$p with a content-length of $count and response of $response" >> $1/virtual-hosts/$test-virtualhosts.log
					fi
				fi
			done
		done
	done
done
vt=`cat $1/virtual-hosts/$1-virtualhosts.log | wc -l`
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Virtual%20Host(s)%20found%20$vt" --silent > /dev/null
sleep 5

echo "[+] Scanning for Alive Hosts [+]"
for alive in `cat $1/$1-all.txt`; do
	for proto in ${protocol[@]}; do
		if [ $(curl -s -o /dev/null -w "%{http_code}" $proto://$alive --max-time 10) == 000 ]
		then
			echo "$alive tango down!"
		else
			echo "$alive is up!"
			echo $alive >> $1/$1-allx.txt
		fi
	done
done
alivesu=`cat $1/$1-allx.txt | sort -u | wc -l`
cat $1/$1-allx.txt | sort -u > $1/$1-allz.txt
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=$alivesu%20alive%20domains%20out%20of%20$all%20domains%20in%20$1" --silent > /dev/null
sleep 5

echo "[+] SCANNING CRLF [+]"
python3 ~/CRLF-Injection-Scanner/crlf_scan.py -i $1/$1-allz.txt -o $1/$1-crlf.txt
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=CRLF%20Scanning%20done%20for%20$1" --silent > /dev/null
sleep 5

echo "[+] COLLECTING ENDPOINTS [+]"
for urlz in `cat $1/$1-allz.txt`; do 
	for protoc in ${protocol[@]}; do
		python ~/LinkFinder/linkfinder.py -i $protoc://$urlz -d -o $1/endpoints/$protoc_$urlz-result.html
	done
done
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Done%20collecting%20endpoint%20in%20$1" --silent > /dev/null
sleep 5

echo "[+] SCANNING ANGULAR CSTI [+]"
for url in `cat $1/$1-allz.txt`; do acstis -c -vp --iic -vrl $1/CSTI/$url.log -d $url; done
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Angular%20CSTI%20Scanning%20done%20for%20$1" --silent > /dev/null
sleep 5

echo "[+] PORT SCANNING [+]"
cat $1/$1-allz.txt | aquatone -ports xlarge -out $1/$1-ports
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Done%20Aquatone%20Port%20Scanning%20for%20$1" --silent > /dev/null
sleep 5


echo "[+] MASSCAN PORT SCANNING [+]"
if [ ! -f $1/$1-masscan.txt ]; then
	echo $passwordx | sudo -S masscan -p1-65535 -iL $1/$1-ip.txt --max-rate 10000 -oG $1/$1-masscan.txt
	mass=`cat $1/$1-ip.txt | wc -l`
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Masscan%20Scanned%20$mass%20IPs%20for%20$1" --silent > /dev/null
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Masscan%20Scanning%20for%20$1" --silent > /dev/null
	echo "[!] Skipping ..."
fi
sleep 5


echo "[+] NMAP PORT SCANNING [+]"
if [ ! -f $1/$1-nmap.txt ]; then
	nmap -sTVC -A -Pn -p- -iL $1/$1-ip.txt --stylesheet nmap-bootstrap.xsl -oA $1/$1-nmap
	nmaps=`cat $1/$1-ip.txt | wc -l`
	xsltproc -o $1/$1-nmap.html nmap-bootstrap.xsl $1/$1-nmap.xml
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Nmap%20Scanned%20$nmaps%20IPs%20for%20$1" --silent > /dev/null
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Nmap%20Scanning%20for%20$1" --silent > /dev/null
	echo "[!] Skipping ..."
fi

sleep 5

echo "[+] Scanning for Sensitive Files [+]"
cp $1/$1-allz.txt $1-sensitive.txt
python sensitive.py -u $1-sensitive.txt
sens=`cat $1-sensitive.txt | wc -l`
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Sensitive%20File%20Scanned%20$sens%20asset(s)%20for%20$1" --silent > /dev/null
rm $1-sensitive.txt
sleep 5
echo "[+] DirSearch Scanning for Sensitive Files [+]"
for u in `cat $1/$1-allz.txt`;do python3 ~/dirsearch/dirsearch.py -u $u --ext php,bak,txt,asp,aspx,jsp,html,zip,jar,sql -b -w newlist.txt >> $1/dirsearch/$u-dirsearch.txt;done
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=DirSearch%20Done%20for%20$1" --silent > /dev/null
sleep 5

curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Scanner%20Done%20for%20$1" --silent > /dev/null
