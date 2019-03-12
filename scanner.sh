#!/bin/bash

# amass, subfinder, snapd, aquatone, gobuster, masscan, nmap, sensitive.py, wfuzz, curl, libcurl4-openssl-dev

telegram_bot=""
passwordx=""
telegram_id=""

if [ ! -f $1 ]; then
	mkdir $1
fi

echo "[+] AMASS SCANNING"
if [ ! -f $1/$1.txt ]; then
	amass -brute -active -d $1 -o $1/$1.txt
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Amass%20Done%20for%20$1" --silent
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Amass%20Scanning%20for%20$1" --silent
	echo "[!] Skipping ..."
fi

echo "[+] SUBFINDER SCANNING"
if [ ! -f $1/$1x.txt ]; then
	subfinder -d $1 -o $1/$1x.txt
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=SubFinder%20Done%20for%20$1" --silent
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Subfinder%20Scanning%20for%20$1" --silent
	echo "[!] Skipping ..."
fi

echo "[+] AQUATONE SCANNING"
if [ ! -f ~/aquatone/$1/urls.txt ]; then
	aquatone-discover -d $1
	aquatone-scan -d $1 -p huge
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Aquatone%20Done%20for%20$1" --silent
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Aquatone%20Scanning%20for%20$1" --silent
	echo "[!] Skipping ..."
fi

for domains in $(cat ~/aquatone/$1/urls.txt); do domain="${domains#*://}"; domainx="${domain%/*}"; echo $domainx >> $1/$1-aquatone.txt;done

echo "[+] Running Gobuster"
if [ ! -f $1/$1-gobuster.txt ]; then
	gobuster -m dns -u $1 -t 50 -w all.txt -o $1/$1-gobust.txt -fw
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Gobuster%20Done%20for%20$1" --silent
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Gobuster%20Scanning%20for%20$1" --silent
	echo "[!] Skipping ..."
fi

cat $1/$1-gobust.txt | grep "Found:" | awk {'print $2'} > $1/$1-gobuster.txt
rm $1/$1-gobust.txt

cat $1/$1.txt $1/$1x.txt $1/$1-aquatone.txt $1/$1-gobuster.txt | sort -u > $1/$1-final.txt
rm $1/$1.txt $1/$1x.txt $1/$1-aquatone.txt $1/$1-gobuster.txt
touch $1/$1-ip.txt

cp $1/$1-final.txt $1/ports.txt
for ipx in $(cat $1/ports.txt); do i="${ipx%:*}"; echo $1 >> $1/$1-ips.txt;done
rm $1/ports.txt
for ip in $(cat $1/$1-ips.txt); do host $ip | grep "has address" | awk {'print $4'} >> $1/$1-ipx.txt;done
cat $1/$1-ipx.txt | sort -u > $1/$1-ip.txt
rm $1/$1-ipx.txt

echo "[+] Scanning Ports"
cat $1/$1-final.txt | aquatone -ports xlarge -out $1/$1-ports

if [ ! -f $1/$1-masscan.txt ]; then
	echo $passwordx | sudo -S masscan -p1-65535 -iL $1/$1-ip.txt --max-rate 10000 -oG $1/$1-masscan.txt
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Masscan%20Done%20for%20$1" --silent
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Masscan%20Scanning%20for%20$1" --silent
	echo "[!] Skipping ..."
fi

if [ ! -f $1/$1-nmap.txt ]; then
	nmap -sC -sV -Pn -p- -iL $1/$1-ip.txt -oA $1/$1-nmap.txt
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Nmap%20Done%20for%20$1" --silent
	echo "[+] Done"
else
	curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Skipping%20Nmap%20Scanning%20for%20$1" --silent
	echo "[!] Skipping ..."
fi

echo "[+] Scanning for Sensitive Files"
cp $1/$1-final.txt $1-sensitive.txt
python sensitive.py -u $1-sensitive.txt
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Sensitive%20Files%20Done%20for%20$1" --silent
rm $1-sensitive.txt
wfuzz -f $1/$1-wfuzz,raw -w content_discovery_all.txt --hc 404 https://$1/FUZZ
curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=wfuzz%20Done%20for%20$1" --silent

curl -g "https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text=Scanner%20Done%20for%20$1" --silent

