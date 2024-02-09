# Nmap

## Nmap

### Scan for hosts

```sh
nmap -sn $iprange -oG - | grep Up | cut -d' ' -f2 > network.txt
```

### **All TCP Ports**

```sh
nmap -Pn -sC -sV -oA all -vv -p- $ip
```

### UDP Top 100 Ports

```sh
nmap -Pn -sU --top-ports 100 -oA udp -vv $ip
```

## Utilize nmap's scripts

Find script related to a service your interested in, example here is ftp

```sh
locate .nse | grep ftp
```

What does a script do?

```sh
nmap --script-help ftp-anon
```

### Uniscan

```sh
uniscan -u $ip -qweds
```

### Good nmap command

```sh
nmap -T4 -n -sC -sV -p- -oN nmap-versions --script='*vuln*' [ip]
```

### **unicornscan + nmap = onetwopunch**

Unicornscan supports asynchronous scans, speeding port scans on all 65535 ports. Nmap has powerful features that unicornscan does not have. With onetwopunch, unicornscan is used first to identify open ports, and then those ports are passed to nmap to perform further enumeration.

```sh
nmap -p 80 --script=all $ip - Scan a target using all NSE scripts. May take an hour to complete.
nmap -p 80 --script=*vuln* $ip - Scan a target using all NSE vuln scripts.
nmap -p 80 --script=http*vuln* $ip  - Scan a target using all HTTP vulns NSE scripts.
nmap -p 21 --script=ftp-anon $ip/24 - Scan entire network for FTP servers that allow anonymous access.
nmap -p 80 --script=http-vuln-cve2010-2861 $ip/24 - Scan entire network for a directory traversal vulnerability. It can even retrieve admin's password hash.
```

## Search services vulnerabilities

```
searchsploit --exclude=dos -t apache 2.2.3
```

```
msfconsole; > search apache 2.2.3
```

