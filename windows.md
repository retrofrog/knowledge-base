# Windows

### Windows Internals and Components

#### Processes

We can make the process tangible by observing them in the _Windows Task Manager_. The task manager can report on many components and information about a process. There are multiple utilities available that make observing processes easier; including [Process Hacker 2](https://github.com/processhacker/processhacker), [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer), and [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon). **Processes Components**

* `Private Virtual Address Space`: Virtual memory addresses that the process is allocated. A memory manager is used to translate virtual addresses to physical addresses. Providing virtual addresses to processes as if it were physical addresses prevents collisions between processes. Applications may use more virtual memory than physical memory allocated; the memory manager will transfer or page virtual memory to the disk to solve this problem. The theoretical maximum virtual address space is 4 GB on a 32-bit x86 system.
* `Executable Program`: Defines code and data stored in the virtual address space.
* `Open Handles`: Defines handles to system resources accessible to the process.
* `Security Context`: The access token defines the user, security groups, privileges, and other security information.
* `Process ID`: Unique numerical identifier of the process.
* `Threads`: Section of a process scheduled for execution. Threads control the process execution and share the same details and resources as their parent process, such as code, global variables, etc.

#### DLLs

A DLL is a library that contains code and data that can be used by more than one program at the same time so that the operating system and the programs load faster, run faster, and take less disk space on the computer. DLLs can be loaded in a program using _load-time dynamic linking_ or _run-time dynamic linking_. When loaded using _load-time dynamic linking_, explicit calls to the DLL functions are made from the application. You can only achieve this type of linking by providing a header (_.h_) and import library (_.lib_) file. When loaded using _run-time dynamic linking_, a separate function (`LoadLibrary` or `LoadLibraryEx`) is used to load the DLL at run time. Once loaded, you need to use `GetProcAddress` to identify the exported DLL function to call.

#### Portable Executable Format

The PE (**P**ortable **E**xecutable) format defines the information about the executable and stored data. The PE format also defines the structure of how data components are stored. PE has the below components:

* The **DOS Header** defines the type of file. The `MZ` DOS header defines the file format as `.exe`
* The **DOS Stub** is a program run by default at the beginning of a file that prints a compatibility message. This does not affect any functionality of the file for most users.
* The **PE File Header** provides PE header information of the binary. Defines the format of the file, contains the signature and image file header, and other information headers.
* The **Data Dictionaries** are part of the image optional header. They point to the image data directory structure.
* The **Section Table** will define the available sections and information in the image. As previously discussed, sections store the contents of the file, such as code, imports, and data

### Description of Common Directories and Registry Keys in Windows

#### Directories

**DNS file**

```
C:\Windows\System32\drivers\etc\hosts 
```

**Network Config file**

```
C:\Windows\System32\drivers\etc\networks 
```

**Usernames and Password**

```
C:\Windows\System32\config\SAM 
```

**Security Log**

```
C:\Windows\System32\config\SECURITY 
```

**Software Log**

```
C:\Windows\System32\config\SOFTWARE 
```

**System Log**

```
C:\Windows\System32\config\SYSTEM 
```

**Windows Event Logs**

```
C:\Windows\System32\winevt\ 
```

**Backup of Users and Passwords**

```
C:\Windows\repair\SAM
```

**Windows All User Startup**

```
C:\ProgramData\Microsoft\Windows\StartMenu\Programs\StartUp
```

**Windows User Startup**

```
C:\Users\*\AppData\Roaming\Microsoft\
Windows\Start Menu\Programs\Startup
```

**Prefetch files**

```
C:\Windows\Prefetch
```

**Amcache.hve**

```
C:\Windows\AppCompat\Programs\Amcache.hve 
```

**NTUSER.dat**

```
C:\Windows\Users\*\NTUSER.dat NTUSER.dat
```

#### Registry

**OS Information**

```
HKLM\Software\Microsoft\WindowsNT\CurrentVersion /v ProductName 
```

**Product Name**

```
HKLM\Software\Microsoft\WindowsNT\CurrentVersion /v ProductName
```

**Install Date**

```
HKLM\Software\Microsoft\WindowsNT\CurrentVersion /v InstallDate
```

**Registered Owner**

```
HKLM\Software\Microsoft\WindowsNT\CurrentVersion /v RegisteredOwner
```

**System Root**

```
HKLM\Software\Microsoft\WindowsNT\CurrentVersion /v SystemRoot
```

**Time Zone**

```
HKLM\System\CurrentControllerSet\Control\TimeZoneInformation /v ActiveTimeBias
```

**Mapped Network Drives**

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Explorer\Map Network Drive
MRU
```

**Mounted Devices**

```
HKLM\System\MountedDevices
```

**USB Devices**

```
HKLM\System\CurrentControllerSet\Enum\USBStor
```

**Audit Policies**

```
HKLM\Security\Policy\PolAdTev
```

**Installed Software (Machine)**

```
HKLM\Software
```

**Installed Software (User)** \[1]

```
HKCU\Software
```

\[2]

```
wmic product get name,version,vendor
```

**Recent Documents**

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

**Recent User Locations**

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVistitedMRU
```

**Typed URLs**

```
HKCU\Software\Microsoft\InternetExplorer\TypedURLs
```

**MRU List**

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

**Last Registry Key Accessed**

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\RegEdit /v LastKey
```

**View installed updates** This information will give you an idea of how quickly systems are being patched and updated.

```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

### Networking

**With netstat** We use the options `-a` to display all listening ports and active connections. The `-b` lets us find the binary involved in the connection, while `-n` is used to avoid resolving IP addresses and port numbers. Finally, `-o` display the process ID (PID). Open Connections

```
C:\> netstat ano
```

Listening Ports

```
netstat -an findstr LISTENING
```

Other netstat commands

```
C:\> netstat -e
C:\> netstat -naob
C:\> netstat -nr
C:\> netstat -vb
C:\> nbtstat -s
```

**View routing table**

```
C:\> route print
```

**View ARP table**

```
C:\> arp -a
```

**View DNS settings**

```
C:\> ipconfig /displaydns
```

**Proxy Information**

```
C:\> netsh winhttp show proxy
```

**All IP configs**

```
C:\> ipconfig /allcompartments /all
```

**Network Interfaces**

```
C:\> netsh wlan show interfaces
C:\> netsh wlan show all
```

**With registry**

```
C:\> reg query
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings"
C:\> type %SYSTEMROOT%\system32\drivers\etc\hosts
```

**With wmic**

```
C:\> wmic nicconfig get
descriptions,IPaddress,MACaddress

C:\> wmic netuse get
name,username,connectiontype, localname
```

**Downloading a file from the command line**

```
Certutil -urlcache -f ‘url’
```

**Listing network shares on windows:**

```
net view \\10.10.20.229 /all
```

**Allow an incoming connection on specific port in the firewall** Instead of the GUI interface, you can execute the below command

```
netsh advfirewall firewall add rule name="allowed_PORT" protocol=TCP dir=in localip=machine-ip  localport=port action=allow
```

Or you can do the same using Powershell

```
New-NetFirewallRule -DisplayName
"allowed_PORT" -Direction Inbound -Protocol TCP –LocalPort port -Action Allow
```

#### Windows Port forwarding

**With Netsh command**

**Syntax**

```
netsh interface portproxy add v4tov4 listenaddress=localaddress listenport=localport connectaddress=destaddress connectport=destport
```

* **listenaddress** –is a local IP address to listen for incoming connection.
* **listenport** – a local TCP port number to listen on (the connection is waiting on)
* **connectaddress** – is a local or remote IP address (or DNS name) to which you want to redirect the incoming connection
* **connectport** – is a TCP port to which the connection from `listenport` is forwarded to.

**Example** The below command will redirect connections on port 3340 to 3389 and will let you to access RDP service on a non-standard port.

```
netsh interface portproxy add v4tov4 listenport=3340 listenaddress=10.1.1.110 connectport=3389 connectaddress=172.10.10.2
```

`10.1.1.110` Your computer IP address on which portforwarding is enabled.

`172.10.10.2` the remote server hosting RDP service on port 3389

Next you can use RDP and connect using port 3340.

`Note`: Make sure port 3340 is allowed in windows firewall as an incoming connection and also make sure that **iphlpsvc** (IP Helper) service running on your Windows device

After all the configs are complete, you can display all portforwarding rules enabled on the machine using the below command \[1]

```
netsh interface portproxy show all
```

\[2]

```
netsh interface portproxy dump
```

In order to remove a specific port forwarding rule, run the below

```
netsh interface portproxy delete v4tov4 listenport=3340 listenaddress=10.1.1.110
```

To remove all port forwarding rules

```
netsh interface portproxy reset
```

#### Network Shares

```
C:\> net use \\<TARGET IP ADDRESS>
C:\> net share
C:\> net session
```

With wmic

```
C:\> wmic volume list brief

C:\> wmic logicaldisk get
description,filesystem,name,size

C:\> wmic share get name,path
```

#### Netsh Utility

**Saved wireless profiles**

```
netsh wlan show profiles
```

**Export wifi plaintext pwd**

```
netsh wlan export profile folder=. key=clear
```

**List interface IDs/MTUs**

```
netsh interface ip show interfaces
```

**Set IP**

```
netsh interface ip set address local static
IP netmask gateway ID
```

**Set DNS server**

```
netsh interface ip set dns local static ip
```

**Set interface to use DHCP**

```
netsh interface ip set address local dhcp
```

**Disable Firewall**

```
netsh advfirewall set currentprofile state off
netsh advfirewall set allprofiles state off
```

### Management

#### System Info

**Date and Time**

```
C:\> echo %DATE% %TIME%
```

**Export OS info into a file with Powershell**

```
Get-WmiObject -class win32 operatingsjstem | select -property | exportcsv
c:\os.txt
```

**Host-Name**

```
C:\> hostname
```

**All systeminfo**

```
C:\> systeminfo
```

OS Name

```
C:\> systeminfo I findstr /B /C:"OS Name" /C:"OS Version"
```

System info with wmic

```
C:\> wmic csproduct get name
C:\> wmic bios get serialnumber
C:\> wmic computersystem list brief
```

System info with sysinternals

```
C:\> psinfo -accepteula -s -h -d

Ref. https://technet.microsoft.com/enus/
sysinternals/psinfo.aspx
```

#### System Management Tools

Windows offers some great set of system management tools such as tools dedicated to display system information, troubleshooting problems, Event viewer, UAC settings, etc. All can be found by typing the below in the search box

```
msconfig --> Tools Tab
```

**Troubleshooting Tool**

Enter the below command in 'CMD'

```
C:\Windows\System32\control.exe /name Microsoft.Troubleshooting
```

**Manage UAC**

Enter the below command in 'CMD'

```
UserAccountControlSettings.exe
```

**Computer Management Tool**

Enter the below command in 'CMD'

```
compmgmt.msc
```

**View Sys Info Tool**

Enter the below command in 'CMD'

```
msinfo32.exe
```

**Resource Monitor Tool**

Enter the below command in 'CMD'

```
resmon.exe
```

**Group Policy Management**

Any of the commands below will list the current GPO settings and the second and third ones will send the output to an external file

```
C:\> gpresult /r
C:\> gpresult /z > <OUTPUT FILE NAME>.txt
C:\> gpresult /H report.html /F
```

With wmic

```
C:\> wmic qfe
```

**Regular Windows**

Use the user accounts in the control panel. You can also change details about a specific user by running.

**Managing users**

**Windows Server without AD**

Use the utility 'RUN' and type the below

```
lusrmgr.msc
```

You will be able to manager groups and users more in details. Just type the below in the search box

```
netplwiz
```

**Netview Tool**

**Hosts in current domain**

```
net view /domain
```

**Hosts in example.com**

```
net view /domain:example.com
```

**All users in current domain**

```
net user /domain
```

**Add user**

```
net user user pass /add
```

**Add user to Administrators**

```
net localgroup "Administrators" user /add
```

**Show Domain password policy**

```
net accounts /domain
```

**List local Admins**

```
net localgroup "Administrators"
```

**List domain groups**

```
net group /domain
```

**List users in Domain Admins**

```
net group "Domain Adrnins" /domain
```

**List domain controllers for current domain**

```
net group "Domain Controllers 11 /domain
```

**Current SMB shares**

```
net share
```

**Active SMB sessions**

```
net session I find I "\\"
```

**Unlock domain user account**

```
net user user /ACTIVE:jes /domain
```

**Change domain user password**

```
net user user '' newpassword '' /domain
```

**Share folder**

```
net share share c:\share /GRANT:Everyone,FULL
```

**PSexec**

**Execute file hosted on an SMB share on a remote machine providing the credentials**

```
psexec /accepteula \\ targetiP -u domain\user -p password -c -f \\smbiP\share\file.exe
```

**Execute a command on a remote machine but authenticating through LM/NTLM hashing**

```
psexec /accepteula \\ ip -u Domain\user -p LM:NTLM cmd.exe ipconfig/all
```

**Remotely execute command as system**

```
psexec /accepteula \\ ip -s cmd.exe
```

### User Info and Management

Current user

```
C:\> whoami
```

Retrieve all users

```
C:\> net users
```

Retrieve administrators

```
C:\> net localgroup administrators
```

Retrieve administrators Groups

```
C:\> net group administrators
```

Retrieve user info with wmic

```
C:\> wmic rdtoggle list
C:\> wmic useraccount list
C:\> wmic group list
C:\> wmic netlogin get name, lastlogon,badpasswordcount
C:\> wmic netclient list brief
```

**Using history file**

```
C:\> doskey /history> history.txt
```

**Get information about other users according to department**

```
PS> Get-NetUser -filter "department=HR*"
```

### Services and processes

**Listing processes**

```
C:\> tasklist
```

**Listing processes with services**

```
C:\> tasklist /SVC
```

**Listing processes with DLLs**

```
C:\> tasklist /m
```

**Listing Processes with remote IPs**

```
tasklist /S ip /v
```

**Listing Processes with their executables**

```
C: \> tasklist /SVC /fi "imagename eq svchost.exe"
```

**Force Process to terminate**

```
taskkill /PID pid /F
```

**Scheduled tasks list** One of the below commands can be used \[1]

```
schtasks /query /fo LIST /v
```

\[2]

```
schtasks /query /fo LIST 2>nul | findstr TaskName
```

\[3]

```
dir C:\windows\tasks
```

\[4]

```
schtasks /query /fo LIST /v
```

\[5]

```
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

\[6]

```
Get-ScheduledTask
```

**Managing network services**

```
C:\> net start
```

**Managing services with `sc` and `wmic`**

```
C:\> sc query
C:\> wmic service list brief
C:\> wmic service list conf ig
C:\> wmic process list brief
C:\> wmic process list status
C:\> wmic process list memory
C:\> wmic job list brief | findstr "Running"
```

**Services running with PowerShell**

```
[1]
PS C:\> Get-Service I Where-Object { $_.Status -eq "running" }

[2]
get-service
```

### File and Directory Management

**Searching**

Based on the extension \[1]

```
C:\> dir /A /5 /T:A *.exe *.dll *.bat *·PS1 *.zip
```

\[2] Below will do the same as above but specifying a date which will list the files newer than the date used in the command

```

C:\> for %G in (.exe, .dll, .bat, .ps) do forfiles -p "C:" -m *%G -s -d +1/1/2023 -c "cmd /c echo @fdate @ftime @path"
```

**Based on the name**

```
C:\> dir /A /5 /T:A bad.exe
```

**Based on date** Below will find `.exe` files after `01/01/2023`

```
C:\> forfiles /p C:\ /M *.exe /5 /0 +1/1/2023 /C "cmd /c echo @fdate @ftime @path"
```

**Based on date with Powershell** Below will return files that were modified past 09/21/2023

```
Get-Childitem -Path c:\ -Force -Rec~rse -Filter '.log -ErrorAction
Silentl~Con~inue I where {$ .LastWriteTime -gt ''2012-09-21''}
```

**Based on the size** Below will find files smaller than 50MB

```
C:\> forfiles /5 /M * /C "cmd /c if @fsize GEO
5097152 echo @path @fsize"
```

Based alternate data streams

```
C:\> streams -s <FILE OR DIRECTORY>
```

[Tool link](https://technet.microsoft.com/enus/sysinternals/streams.aspx)

**Prcoessing**

**Display file content**

```
[1]
get-content file

[2]
type file
```

Pipe output to clipboard

```
C:\> some_command.exe I clip
```

Output clip to file

```
PS C:\> Get-Clipboard> clip.txt
```

**Combine contents of multiple files**

```
C:\> type <FILE NAME 1> <FILE NAME 2> <FILE NAME 3>> <NEW FILE NAME>
```

**Compare two files for changes**

```
PS C:\> Compare-Object (Get-Content ,<LOG FILE NAMEl>.log) -DifferenceObject (Get-Content.<LOG FILENAME 2>.log)
```

**Download a file over http with Powershell**

```
(new-object sjstem.net.webclient) .downloadFile("url","C:\temp")
```

### Startup and Autorun Management

**With wmic**

```
C:\> wmic startup list full
C:\> wmic ntdomain list brief
```

**By viewing the contents startup folder**

```
C:\> dir
"%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\P rog rams\Startup"

C:\> dir "%SystemDrive%\Documents and Settings\All

Users\Sta rt Menu\Prog rams\Sta rtup"
C:\> dir %userprofile%\Start Menu\Programs\Startup

C:\> %ProgramFiles%\Startup\

C:\> dir C:\Windows\Start Menu\Programs\startup

C:\> dir "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

C:\> dir "C:\ProgramData\Microsoft\Windows\Start
Menu\Programs\Startup"

C:\> dir "%APPDATA%\Microsoft\Windows\Start
Menu\Programs\Startup"

C:\> dir "%ALLUSERSPROFILE%\Microsoft\Windows\Start
Menu\Programs\Startup"

C:\> dir "%ALLUSERSPROFILE%\Start
Menu\Programs\Startup"
```

Through wininit

```
C:\> type C:\Windows\winstart.bat
C:\> type %windir%\wininit.ini
C:\> type %windir%\win.ini
```

**With Sysinternal tools**

```
C:\> autorunsc -accepteula -m
C:\> type C:\Autoexec.bat"
```

**You can also export the output to a CSV file**

```
C:\> autorunsc.exe -accepteula -a -c -i -e -f -l -m -v
```

**With regsitry**

```
C:\> reg query HKCR\Comfile\Shell\Open\Command

C:\> reg query HKCR\Batfile\Shell\Open\Command

C:\> reg query HKCR\htafile\Shell\Open\Command

C:\> reg query HKCR\Exefile\Shell\Open\Command

C:\> reg query HKCR\Exefiles\Shell\Open\Command

C:\> reg query HKCR\piffile\shell\open\command

C:\> reg query uHKCU\Control Panel\Desktop"

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Run

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Runonce

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Windows\Run

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Windows\Load

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Windows\Scripts

C:\> reg query «HKCU\Software\Microsoft\Windows
NT\CurrentVersion\Windows« /f run

C:\> reg query «HKCU\Software\Microsoft\Windows
NT\CurrentVersion\Windows« /f load

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComD1g32\0pen5aveMRU

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComD1g32\0pen5avePidlMRU /s

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

C:\> reg query
«HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"

C:\> reg query
uHKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

C:\> reg query
HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\RegEdit /v LastKey

C:\> reg query "HKCU\Software\Microsoft\InternetExplorer\TypedURLs"

C:\> reg query
uHKCU\Software\Policies\Microsoft\Windows\ControlPanel \Desktop"

C: \> reg query uHKLM\SOFTWARE\Mic rosoft\Act iveSetup\Installed Components" /s

C:\> reg query
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\User Shell Folders"

C:\> reg query
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\Shell Folders"

C:\> reg query
HKLM\Software\Microsoft\Windows\CurrentVersion\explorer\ShellExecuteHooks

C:\> reg query
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s

C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce

C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx

C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
C:\> reg query

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce

C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Winlogon\Userinit

C:\> reg query
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\shellServiceObjectDelayLoad

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\Schedule\TaskCache\Tasks" /s

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\Windows"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\Windows" /f Appinit_DLLs

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\Winlogon" /f Shell

C: \> reg query "HKLM\SOFTWARE\Mic rosoft\WindowsNT\CurrentVersion\Winlogon" /f Userinit

C:\> reg query
HKLM\SOFTWARE\Policies\Microsoft\Windows\Systern\Scripts
C:\> reg query

HKLM\SOFTWARE\Classes\batfile\shell\open\cornrnand

C:\> reg query
HKLM\SOFTWARE\Classes\cornfile\shell\open\cornrnand

C:\> reg query
HKLM\SOFTWARE\Classes\exefile\shell\open\command

C:\> reg query
HKLM\SOFTWARE\Classes\htafile\Shell\Open\Command

C:\> reg query
HKLM\SOFTWARE\Classes\piffile\shell\open\command

C:\> reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s

C:\> reg query
"HKLM\SYSTEM\CurrentControlSet\Control\Session
Manager"

C:\> reg query
"HKLM\SYSTEM\CurrentControlSet\Control\Session
Manager\KnownDLLs"

C:\> reg query
"HKLM\SYSTEM\ControlSet001\Control\Session
Manager\KnownDLLs"
```

### Troubleshooting

#### Fixing corrupted system files

Execute the below commands

```
DISM /Online /Cleanup-Image /ScanHealth
DISM /Online /Cleanup-Image /RestoreHealth
sfc /scannow
```

#### Hard Disk not detected when installing windows from usb

!\[\[windows-hdd-notfound-installinng-windows.jpg]] Press shift+F10 to start the command promopt. Execute the below command to start DISKPART

```
DISKPART
```

Then list volumes using the below command

```
list volume
```

Select the volume to which you want to install windows and execute the below commands

```
select disk [disknumber]
clean
convert mbr
create partition primary
active
format quick fs=ntfs
```

#### Java Error 1603

This error happens when you attempt to install/update JAVA for Windows. There are multiple options/steps to take to resolve this issue.

**Choose earlier version to install**

First uninstall any prior version

```
https://www.java.com/en/download/uninstalltool.jsp
```

Then simply go the below link and choose prior version

```
https://www.oracle.com/tr/java/technologies/javase/javase8-archive-downloads.html
```

**Disable The current AV**

Try to disable your AV solution whether it's Windows defender or any third party AV.

**Use Microsoft install/uninstall troubleshooter**

Download the tool from the below link

```
https://support.microsoft.com/en-gb/help/17588/fix-problems-that-block-programs-from-being-installed-or-removed
```

**Delete KB2918614 Update**

This was update was known to cause conflict with Java. Simple go to  **Programs in Features** then click on **View installed updates** link in the left pane. You will see the list of installed updates. Search for KB2918614. Click on the KB2918614 Windows update and click **Uninstall** button.

**Fix System corrupted files**

Run CMD as admin and execute the below commands

```
DISM /Online /Cleanup-Image /ScanHealth
DISM /Online /Cleanup-Image /ScanHealth
DISM /Online /Cleanup-Image /RestoreHealth
sfc/scannow
```

### Windows Security and Hardening

#### Disable Always Install Elevated

Navigate to the below configs in group policy and make sure/set the value is `Disabled.`

```
Computer Configuration\Administrative Templates\Windows Components\Windows Installer

User Configuration\Administrative Templates\Windows Components\Windows Installer
```

#### Anti-KeyLoggers

* Zemana AntiLogger (Free) This "free" version is a bare-bones keylogger-detector. In fact, it's quite stripped down but if all you require is being alerted then this might be for you.
* SpyShelter STOP-LOGGER The Free version offers more than Zemana does in that you get screenshot capture. It will also alert you to any code that tries to swipe your keystrokes from you but the Free version is not 64-bit compatible. It is $24.99.

#### Windows Defender and Windows Firewall

These two come pre-installed in nearly all new and modern Windows operating systems. An average user can safely rely on them for security given that they practice safety controls when downloading files from the internet or when dealing with email attachments.

On server editions of Windows, make sure to block inbounds ports 135,137,138,139 if have file shares whether the PCs are on a workgroup or domain. You can simply do that by creating an inbound rule in Windows firewall and block the aforementioned ports.

**Firewall Operations**

Auditing current firewall rules

```
C:\> netsh advfirewall firewall show rule name=all
```

Turn off/on the firewall

```
C:\> netsh advfirewall set allprofile state on
C:\> netsh advfirewall set allprof ile state off
```

Block inbound and allow outbound traffic. This rule can be used on workstations that don't play the role of a server

```
C:\> netsh advfirewall set currentprofile
firewallpolicy blockinboundalways,allowoutbound
```

Open port 80 and allow inbound http traffic. Usually it's applied on machines that play the role of a webserver

```
C:\> netsh advfirewall firewall add rule name="Open
Port 80" dir=in action=allow protocol=TCP
localport=80
```

Allow an application to receive inbound traffic.

```
C:\> netsh advfirewall firewall add rule name="My
Application" dir=in action=allow
program="C:\MyApp\MyApp.exe" enable=yes
```

Allow an application to receive inbound traffic and specify the profile, remote IP and subnet. The profile value can be `public`, `private` or `domain`

```
netsh advfirewall firewall add rule name="My
Application" dir=in action=allow
program="C:\MyApp\MyApp.exe" enable=yes
remoteip=ip1,172.16.0.0/16,LocalSubnet
profile=domain
```

Delete a rule

```
C:\> netsh advfirewall firewall delete rule
name=rule name program="C:\MyApp\MyApp.exe"
```

Setting up the logging location

```
C:\> netsh advfirewall set currentprofile logging
C:\<LOCATION>\<FILE NAME>
```

Firewall logs location

```
C:\>%systemroot%\system32\LogFiles\Firewall\pfirewa
ll. log
```

You can also disable logging using Powershell

```
PS C:\> Get-Content
$env:systemroot\system32\LogFiles\Firewall\pfirewal.log
```

#### Disable Modifying Scheduled Tasks

Useful if applied on non-admin endpoints \[1]

```
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Task Scheduler5.0" /v DragAndDrop /t REG_DWORD /d 1
```

\[2]

```
reg add "
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Task Scheduler5.0" /v Execution /t REG_DWORD /d 1
```

\[3]

```
reg add "
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Task Scheduler5.0" /v Task Creation /t REG_DWORD /d 1
```

\[4]

```
reg add "
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Task Scheduler5.0" /v Task Deletion /t REG_DWORD /d 1
```

#### Disable RunOnce

Useful to fight against rootkits and malwares

```
reg add
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v DisableLocalMachineRunOnce /t REG_DWORD /d 1
```

#### Enabling Credential Guard

Prevent credential dumping in Windows 10 by enabling windows credential guard. Execute the below commands to modify the registry \[1]

```
reg add
"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /d 1 /t REG_DWORD
```

\[2]

```
reg add
"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /d 1 /t REG_DWORD
```

\[3]

```
reg add
"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA" /v "LsaCfgFlags" /d 1 /t REG_DWORD
```

#### Enable UAC

User Account Control (UAC) is a feature that enforces enhanced access control and ensures that all services and applications execute in non-administrator accounts. It helps mitigate malware's impact and minimizes privilege escalation by bypassing UAC. Actions requiring elevated privileges will automatically prompt for administrative user account credentials if the logged-in user does not already possess these. To access UAC, go to `Control Panel -> User Accounts` and click on `Change User Account Control Setting`. Keep the notification level "**Always Notify**" in the User Account Control Settings.

#### Setting a Password Policy

Open group policy editor and Go to `Security settings > Account Policies > Password policy`

#### Setting a lockout policy

To protect your system password from being guessed by an attacker, we can set out a lockout policy so the account will automatically lock after certain invalid attempts. To set a lockout policy, go to `Local Security Policy > Windows Settings > Account Policies > Account Lockout Policy` and configure values to lock out hackers after three invalid attempts.

#### Disabling RDP and SMB

if you don't need remote assistance through RDP protocol and you don't host file sharing server through SMB then it would be better from a security standpoint to disable them **Disabling RDP** In Windows, settings > Remote Desktop and tick the box `Don't allow remote connections to this computer` **Disabling SMB** Execute the below in Powershell

```
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

#### Application Security

**Installing apps only from Microsoft store**

Go to `Setting > Select Apps and Features` and then select `The Microsoft Store only`

**Running Applications from a sandbox**

To run applications safely, we can use a temporary, isolated, lightweight desktop environment called Windows Sandbox. We can install software inside this safe environment, and this software will not be a part of our host machine, it will remain sandboxed. Once the Windows Sandbox is closed, everything, including files, software, and states will be deleted. We would require Virtualization enabled on our OS to run this feature. for enabling the Sandbox feature are as below: `Click Start > Search for 'Windows Features' and turn it on > Select Sandbox > Click OK to restar`

#### Enabling Microsoft Smartscreen

Microsoft SmartScreen helps to protect you from phishing/malware sites and software when using Microsoft Edge. It helps to make informed decisions for downloads and lets you browse safely in Microsoft Edge. To turn on the Smart Screen, go to `Settings > Windows Security > App and Browser Control > Reputation-based Protection`. Scroll down and turn on the `SmartScreen option`.

#### Boot Security

Secure boot – an advanced security standard checks that your system is running on trusted hardware and firmware before booting, which ensures that your system boots up safely while preventing unauthorised software access from taking control of your PC, like malware. You are already in a secure boot environment if you run a modern PC with Unified Extensible Firmware Interface UEFI (the best replacement for BIOS) or Windows 10. To check if secure boot is enabled, type the below command below in `run`

```
msinfo32
```

and locate the row where it says `secure boot state` You can enable secure boot from BIOS by following the below steps

```
1. - You can often access this menu by pressing a key while your PC is booting, such as F1, F2, F12, or Esc.
Or
- From Windows, hold the Shift key while selecting Restart. 
- Go to Troubleshoot > Advanced Options: UEFI Firmware Settings.
        
2. Find the Secure Boot setting in your BIOS menu. If possible, set it to Disabled. 
3. This option is usually in either the Security tab, the Boot tab, or the Authentication tab.
    
3. Save changes and exit. The PC reboots.
```

#### Virus and Malware Removal

**Automated Removal with Removal Tools**

**GMER** GMER will attempt to find any rootkits by scanning files, registry entries, drives and processes.

```
http://www2.gmer.net/
```

**Windows Defender** Performing an offline scan with windows security is another method of detecting rootkits and viruses on your window operating system.

### Backup and Recovery

#### Group Policy Update and Recovery

Backup GPO Audit Policy to backup file

```
C:\> auditpol /backup /file:C\auditpolicy.csv
```

Restore GPO Audit Policy from backup file

```
C:\> auditpol /restore /file:C:\auditpolicy.csv
```

Backup All GPOs in domain and save to Path

```
PS C:\> Backup-Gpo -All -Path \\<SERVER>\<PATH TO BACKUPS>
```

Restore All GPOs in domain and save to Path

```
PS C:\> Restore-GPO -All -Domain <INSERT DOMAIN
NAME> -Path \\Serverl\GpoBackups
```

#### Volume Shadow Service

VSS is used to create snapshots of files/entire volumes while they are still in use. You can create or store shadow copies on a local disk, external hard drive, or network drive. Every time a system restore point is created, you will have a valid shadow copy. Shadow Copy maintains snapshots of the entire volumes, so you can also use shadow copies to recover deleted files besides restoring system. **Enabling and Creating Shadow Copies and system restore points** Steps

```
Step 1. Type **Create a restore point** in the search box and select it. Then, in the System Properties, **choose a drive** and click **Configure**.

Step 2. In the new window, tick **Turn on system protection** and click **Apply** to enable.

Step 3. Click **Create** to enable volume shadow copy in Windows 10.
```

**Creating Shadow Copies and Restore Points using Task Scheduler** By using task scheduler, you can create shadow copies and restore points at a regular time intervals. Steps

```
Step 1. Open Task Scheduler. You can click **Start**, type **task scheduler** and select it from the list.

Step 2. Click **Create Task** and then specify a name for the task (eg: ShadowCopy).

Step 3. Create a new trigger. You can click the **Triggers** tab and **New...** option at the lower location, then select one setting among one time, daily, weekly, monthly.

Step 4. Enable shadow copy. You can click the **Actions** tab and **New... option**, type **wmic** under the Program or script option, input the argument **shadowcopy call create Volume=C:\** at the blank box on the right side.
```

**Restoring Shadow Copies using previous versions** Steps

```
Step 1. **Navigate to the file or folder** you want to restore in a previous state and right-click it, then select Restore Previous Versions from the drop-down menu. In addition, you still can select **Properties** and click the **Previous Versions** tab.

Step 2. Select the correct version of file or folder to restore.

In this window, you can see 3 options, including **Open**, **Copy**, **Restore**.  
● The Open button will navigate to the location where the file or folder is stored.   
● The Copy button allows you to copy file or folder to another location on the computer, even on external hard drive.  
● The Restore button gives you a chance to restore the file or folder to the same location and replace the existing version.
```

**Restore Snapshots and Shadow Copies using Shadow Explorer Tool** Download the tool from the below link

```
https://www.shadowexplorer.com/downloads.html
```

**Managing Shadow Copies From The Command Line** Start Volume Shadow Service

```
C:\> net start VSS
```

List all shadow files and storage

```
C:\> vssadmin List ShadowStorage
```

List all shadow files

```
C:\> vssadmin List Shadows
```

Browse Shadow Copy for files/folders

```
C:\> mklink /d c:\<CREATE FOLDER>\<PROVIDE FOLDER NAME BUT DO NOT CREATE> \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyl\
```

Revert back to a selected shadow file on Windows Server

```
C:\> vssadmin revert shadow /shadow={<SHADOW COPYID>} /ForceDismount
```

List a files previous versions history using `volrest.exe`

```
C:\> "\Program Files (x86)\Windows Resource
Kits\Tools\volrest.exe" "\\localhost\c$\<PATH TO FILE>\<FILE NAME>"
```

Revert back to a selected previous file version or @GMT file name for specific previous version using volrest.exe

```
C:\> subst Z: \\localhost\c$\$\<PATH TO FILE>

C:\> "\Program Files (x86)\Windows Resource
Kits\Tools\volrest.exe" "\\localhost\c$\<PATH TO FILE>\<CURRENT FILE NAME OR @GMT FILE NAME FROM LIST COMMAND ABOVE>" /R:Z:\

C:\> subst Z: /0
```

Revert back a directory and subdirectory files previous version using volrest.exe

```
C: \> "\Program Files (x86) \Windows Resource
Kits\Tools\volrest.exe" \\localhost\c$\<PATH TO
FOLDER\*·* /5 /r:\\localhost\c$\<PATH TO FOLDER>\
```

Link to \`volrest.exe

```
Ref. https://www.microsoft.com/enus/
download/details.aspx?id=17657
```

**Managing Shadow Copies using wmic and PowerShell** Revert back to a selected shadow file on Windows Server and Windows 7 and 10 using wmic

```
C:\> wmic shadowcopy call create Volume='C:\'
```

Create a shadow copy of volume C on Windows 7 and 10

```
PS C:\> (gwmi -list win32_shadowcopy).Create('C:\','ClientAccessible')
```

Create a shadow copy of volume C on Windows Server 2003 and 2008:

```
C:\> vssadmin create shadow /for=c:
```

Create restore point on Windows

```
C:\> wmic.exe /Namespace:\\root\default Path
SystemRestore Call CreateRestorePoint "%DATE%", 100,7
```

List of restore points

```
PS C:\> Get-ComputerRestorePoint
```

Restore from a specific restore point

```
PS C:\> Restore-Computer -RestorePoint <RESTORE
POINT#> -Confirm
```

### BIOS Management

#### BIOS Update

Updating BIOS is a very sensitive task and may break your system therefore only update the BIOS when you encounter the below reasons

* System keeps crashing
* Current version of the BIOS is vulnerable
* Current BIOS is causing conflict with new hardware you have just added.
* Find your BIOS version and model You can use the system information tool

```
msinfo32.exe
```

Navigate ---> System Summary and then take a note of the below

```
System Model
BIOS version/date
BIOS Mode
```

* Next step is to check the manufacturer website for the current BIOS model you have above (Use Google) and then download the latest update.
* Extract the contents of the Zipped file and move it to an external USB flash drive
* Restart your PC and access your BIOS by entering `F12` It may change according to your PC model.
* Navigate to **settings** --> **Update & Security > Recovery > Restart Now (under Advanced startup)**. In the window that pops up, select **Troubleshoot > Advanced options > UEFI Firmware Settings > Restart**.
* If you see **Backup** tab in BIOS settings, simply choose to backup your BIOS to the USB flash before proceeding.
* After you have restarted, go to BIOS again and choose **Update** then choose the update tool that you have stored in your USB in the previous steps.

### Resources and Links

#### Utilities and programs

```
https://www.snapfiles.com/
https://www.bytesin.com/
https://www.soft32.com/
http://www.kcsoftwares.com/?download#SUMo
https://portableapps.com/
https://sharewareonsale.com/
https://www.cnet.com/
https://www.howtogeek.com/
https://filehippo.com
```

#### Network Tools

**Network Monitor**

```
https://www.bvsystems.be/netmon.php
```

**Anonymous SMS Senders**

```
https://txtemnow.com/
https://www.afreesms.com/freesms/
```

**Anonymous Email Senders**

```
http://www.send-email.org/
```

#### Video Tools

```
https://en.savefrom.net/391GA/
https://youtube-mp3-online.com/en
```

#### File Processing Tools

```
http://www.cutepdf.com/products/cutepdf/writer.asp
https://www.sodapdf.com/
```

#### Email Tools

```
https://www.massmailsoftware.com/
```

#### Security Tools

```
https://www.ciphershed.org/
https://securityxploded.com/
https://packetstormsecurity.com
https://kidlogger.net/
```

#### Backup and Recovery Tools

```
https://filehippo.com/download_recuva/
```

#### AVs

```
https://filehippo.com/download_avira/

https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/safety-scanner-download?view=o365-worldwide

```

#### Collaboration and Sharing Tools

```
https://www.box.com/
```
