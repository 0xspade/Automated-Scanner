#!/bin/bash

# amass, subfinder, snapd, aquatone, gobuster, masscan, nmap, sensitive.py, curl, CRLF-Injection-Scanner, DirSearch

telegram_bot=""
passwordx=""
telegram_id=""

if [ ! -f $1 ]; then
	mkdir $1
fi

echo "[+] AMASS SCANNING [+]"
if [ ! -f $1/$1.txt ]; then
	amass -brute -active -d $1 -o $1/$1.txt
	amasscan=`cat $1/$1.txt | wc -l`
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Amass%20Found%20$amasscan%20subdomain(s)%20for%20$1" --silent
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Amass%20Scanning%20for%20$1" --silent
	echo "[!] Skipping ..."
fi

echo "[+] SUBFINDER SCANNING [+]"
if [ ! -f $1/$1x.txt ]; then
	subfinder -d $1 -o $1/$1x.txt
	subfinderscan=`cat $1/$1x.txt | wc -l`
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=SubFinder%20Found%20$subfinderscan%20subdomain(s)%20for%20$1" --silent
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Subfinder%20Scanning%20for%20$1" --silent
	echo "[!] Skipping ..."
fi

echo "[+] AQUATONE SCANNING [+]"
if [ ! -f ~/aquatone/$1/urls.txt ]; then
	aquatone-discover -d $1
	aquatone-scan -d $1 -p huge
	for domains in `cat ~/aquatone/$1/urls.txt`; do domain="${domains#*://}"; domainx="${domain%/*}"; echo $domainx >> $1/$1-aquatone.txt;done
	aquatonescan=`cat $1/$1-aquatone.txt | wc -l`
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Aquatone%20Found%20$aquatonescan%20subdomain(s)%20for%20$1" --silent
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Aquatone%20Scanning%20for%20$1" --silent
	echo "[!] Skipping ..."
fi

echo "[+] GOBUSTER SCANNING [+]"
if [ ! -f $1/$1-gobuster.txt ]; then
	gobuster -m dns -u $1 -t 50 -w all.txt -o $1/$1-gobust.txt -fw
	cat $1/$1-gobust.txt | grep "Found:" | awk {'print $2'} > $1/$1-gobuster.txt
	rm $1/$1-gobust.txt
	gobusterscan=`cat $1/$1-gobuster.txt | wc -l`
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Gobuster%20Found%20$gobusterscan%20subdomain(s)%20for%20$1" --silent
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Gobuster%20Scanning%20for%20$1" --silent
	echo "[!] Skipping ..."
fi

cat $1/$1.txt $1/$1x.txt $1/$1-aquatone.txt $1/$1-gobuster.txt | sort -u > $1/$1-final.txt
rm $1/$1.txt $1/$1x.txt $1/$1-aquatone.txt $1/$1-gobuster.txt
touch $1/$1-ip.txt

all=`cat $1/$1-final.txt | wc -l`
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Almost%20$all%20Collected%20Subdomain(s)%20for%20$1" --silent

echo "[+] SCANNING CRLF [+]"
python3 ~/CRLF-Injection-Scanner/crlf_scan.py -i $1/$1-final.txt -o $1/$1-crlf.txt
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=CRLF%20Scanning%20done%20for%20$1" --silent

cp $1/$1-final.txt $1/ports.txt
for ipx in `cat $1/ports.txt`; do i="${ipx%:*}"; echo $i >> $1/$1-ips.txt;done
rm $1/ports.txt
for ip in `cat $1/$1-ips.txt`; do host $ip | grep "has address" | awk {'print $4'} | sort -u >> $1/$1-ip.txt;done

echo "[+] PORT SCANNING [+]"
cat $1/$1-final.txt | aquatone -ports xlarge -out $1/$1-ports
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Done%20Aquatone%20Port%20Scanning%20for%20$1" --silent

echo "[+] MASSCAN PORT SCANNING [+]"
if [ ! -f $1/$1-masscan.txt ]; then
	echo $passwordx | sudo -S masscan -p1-65535 -iL $1/$1-ip.txt --max-rate 10000 -oG $1/$1-masscan.txt
	mass=`cat $1/$1-ip.txt | wc -l`
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Masscan%20Scanned%20$mass%20IPs%20for%20$1" --silent
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Masscan%20Scanning%20for%20$1" --silent
	echo "[!] Skipping ..."
fi

echo "[+] MASSCAN PORT SCANNING [+]"
if [ ! -f $1/$1-nmap.txt ]; then
	nmap -sVC -A --script vuln -Pn -p- -iL $1/$1-ip.txt -oA $1/$1-nmap.txt
	nmaps=`cat $1/$1-ip.txt | wc -l`
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Nmap%20Scanned%20$nmaps%20IPs%20for%20$1" --silent
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Nmap%20Scanning%20for%20$1" --silent
	echo "[!] Skipping ..."
fi

cat $1/$1-ip.txt $1/$1-final.txt > $1/$1-all.txt

echo "[+] Scanning for Sensitive Files [+]"
cp $1/$1-all.txt $1-sensitive.txt
python sensitive.py -u $1-sensitive.txt
sens=`cat $1-sensitive.txt | wc -l`
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Sensitive%20File%20Scanned%20$sens%20asset(s)%20for%20$1" --silent
rm $1-sensitive.txt

echo "[+] DirSearch Scanning for Sensitive Files [+]"
for u in `cat $1/$1-all.txt`;do python3 ~/dirsearch/dirsearch.py -u $u --ext php,bak,txt,zip -b -w content_discover_all.txt >> $1/$1-dirsearch.txt;done
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=DirSearch%20Done%20for%20$1" --silent
rm $1/$1-all.txt

mv $1.out $1/
zip -r $1.zip $1/ 
rm -rf $1/

curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Scanner%20Done%20for%20$1" --silent

