---
description: Discover as much about the target without revealing your IP address
---

# Passive Information Gathering

## Passive Web enumeration

for DNS lookup utility use the host command

```
host hackersploit.org
```

### DNS Recon

```
dnsrecon -d hackersploit.org
```

### dnsdumpster

{% embed url="https://dnsdumpster.com/" %}

<figure><img src="../.gitbook/assets/dnsdumspter.png" alt="" width="375"><figcaption><p>Example result dnsdumspter</p></figcaption></figure>



### robots.txt & sitemap\_index.xml

<figure><img src="../.gitbook/assets/robots.png" alt="" width="386"><figcaption><p>robots.txt</p></figcaption></figure>

<figure><img src="../.gitbook/assets/sitemap_index.png" alt="" width="375"><figcaption><p>sitemap_index.xml</p></figcaption></figure>

### Whatweb&#x20;

to profile the website tech used in cli (or just use builtwith or wappalyzer in firefox addon)

```
whatweb hackersploit.org
```

### Whois

```
whois hackersploit.org
```

### Netcraft

Finds underlying OS, web server version uptime&#x20;

{% embed url="https://sitereport.netcraft.com/?url=" %}

<figure><img src="../.gitbook/assets/netcraft.png" alt="" width="375"><figcaption><p>Example netcraft result</p></figcaption></figure>

### WAF With wafw00f

```
wafw00f hackersploit.org
```

<figure><img src="../.gitbook/assets/wafw00f.png" alt="" width="330"><figcaption><p>wafw00f result</p></figcaption></figure>

## Google Dorks

```
site:ine.com employees
site:ine.com inurl:admin
site:*.ine.com
site:*.ine.com intitle:admin
site:*.ine.com filetype:pdf
intitle:index of
inurl:auth_user_file.txt
cache:ine.com
```

For more google dorking

{% embed url="https://www.exploit-db.com/google-hacking-database" %}
Link to google dorking exploitdb
{% endembed %}

also heck out doc meta info, gives info such as where doc was stored - network share ip address, who created it, what was it created with etc&#x20;

{% embed url="https://github.com/ElevenPaths/FOCA" %}

## Wayback Machine

{% embed url="https://archive.org/web/" %}
Link to wayback machine
{% endembed %}

## Subdomain Enumeration

### Find Subdomains

Sometimes SSL is a goldmine of information

```sh
#!/bin/bash
# a basic script to pull information from crt and present it
# example ./crt.sh offsecnewbie.com
# author rowbot
if [[ $# -eq 0 ]] ;

then
	echo "Usage: ./crt.sh domain. Also you might have to install jq - 'apt get install jq'"
	exit 1

else

curl -s https://crt.sh/\?q\=\%.$1\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > $1

fi
```

Can also find subdomain using sublist3r

### sublist3r

```
sublist3r -d hackersploit.org -e yahoo,bing
```

Compare subdomains found using sublist3r & theHavester with crt.sh script as some will be missing - not all domains have ssl.

### theHarvester

```
theHarvester -d zonetransfer.me -b bing,yahoo
```

IP addresses from subdomains

```sh
for i in $(cat subdomains.txt); do dig $i | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | grep -vE "10.*"; done
```

Use Virustotal to find subdomains

<figure><img src="../.gitbook/assets/image.png" alt="" width="373"><figcaption><p>virustotal find subdomains</p></figcaption></figure>

### Bugcrowd

{% embed url="https://www.bugcrowd.com/blog/discovering-subdomains/" %}

FireFox addon - passive recon

## Social Media Search

```sh
// Example usage
sherlock steve
```

## Recon

A giant inventory of recon tools is available via the Skip Tracing Framework

{% embed url="https://makensi.es/stf/" %}

## Find Information about a device that is connected

Create a [https://grabify.link/](https://grabify.link/) and get someone to click on it.

On device go to [https://device.info.me/](https://device.info.me/)

## List of OSINT Tools

{% embed url="https://start.me/p/wMdQMQ/tools" %}

{% embed url="https://start.me/p/1kJKR9/commandergirl-s-suggestions" %}

{% embed url="https://www.osintme.com/index.php/2021/01/16/ultimate-osint-with-shodan-100-great-shodan-queries" %}

## Leaked Password Databases

{% embed url="https://haveibeenpwned.com/" %}
