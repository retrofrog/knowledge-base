# Metasploit

### Database

```bash
#preparing the database
service postgresql start
msfdb init
msfconsole -q
db_status
help search
```

### Workspace

```bash
workspace -h
```

## Renaming sessions

```bash
sessions -n name -i 1
```

### Vulnerability Assesment

```bash
#type info for more detail about the exploit
use auxiliary/scanner/ssh/ssh_login # Just for example
info
show targets
```

### Searchsploit

```bash
searchsploit "microsoft windows smb" | grep -e "Metasploit"
```

### Metasploit Autopwn (Deprecated)

```bash
https://github.com/hahwul/metasploit-autopwn
#example usage
load db_autopwn
db_autopwn -p -t -PI 445
analyze
```

### WMAP (Web APP Vuln Scanning)

```bash
load wmap
wmap_sites -a 192.157.89.3
wmap_targets -t http://192.157.89.3/
wmap_run -t
wmap_run -e
```

#### Meterpreter quick tips

```bash
#dont forget to migrate after gaining meterpreter shell
migrate -N explorer.exe
```
