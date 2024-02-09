# Pivoting With Metasploit

## Pivoting With Metasploit

## Pivoting

```bash
run autoroute -s 10.0.23.0/20
```

#### Running the port scanner on the second machine

```bash
background
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.0.27.99
set PORTS 1-100
exploit
```

**We have discovered port 80 on the pivot machine. Now, we will forward the remote port 80 to local port 1234 and grab the banner using Nmap**

```bash
sessions -i 1
portfwd add -l 1234 -p 80 -r 10.0.27.99
portfwd list
```

