# Metasploit Information Gathering

### Importing Nmap result into metasploit

```bash
#create new workspace
workspace -a new_workspace
db_import /home/kali/nmap.xml
#to check the result
hosts
services
vulns
analyze
```

#### Nmap with Metasploit Database

```bash
#do the prep like above
db_nmap -Pn -sV 10.1.100.11
```
