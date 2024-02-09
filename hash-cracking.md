# HASH Cracking

base64 decode

```bash
base64 -d test.txt
```

Metasploit

```bash
migrate -N lsass.exe
#first must be able to use hashdump
#then this will try to crack from creds command
use auxiliary/analyze/crack_windows
use auxiliary/analyze/crack_linux
```
