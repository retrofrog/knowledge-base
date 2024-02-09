# Enumeration With Metasploit

## 21 - FTP Enumeration With Metasploit

```bash
use auxiliary/scanner/ftp/ftp_version
#We can also check if anonymous logons are allowed on the FTP server, this can be done by loading the following command:
use auxiliary/scanner/ftp/anonymous
#We can perform a brute-force on the FTP server to identify legitimate credentials that we can use for authentication, this can be done by loading the ftp_login module as follows:
use auxiliary/scanner/ftp/ftp_login
#We can now login to the FTP server with the credentials we obtained from the FTP brute force, this can be done through the use of the FTP client on Kali Linux.
ftp 192.51.147.3
```

## 22 - SSH Enumeration With Metasploit

```bash
auxiliary/scanner/ssh/libssh_auth_bypass
```

## 25 - SMTP Enumeration With Metasploit

```bash
auxiliary/scanner/smtp/smtp_enum
exploit/linux/smtp/haraka
```

## 80 - HTTP Enumeration With Metasploit

```bash
auxiliary/scanner/http/http_version
auxiliary/scanner/http/http_header
auxiliary/scanner/http/robots_txt
auxiliary/scanner/http/brute_dirs
auxiliary/scanner/http/dir_scanner
auxiliary/scanner/http/dir_listing
auxiliary/scanner/http/files_dir
auxiliary/scanner/http/http_put
auxiliary/scanner/http/http_login
auxiliary/scanner/http/apache_userdir_enum
```

## 139,445 - Samba Enumeration WIth Metasploit

```bash
exploit/linux/samba/is_known_pipename
```

## 3306 - MySQL Enumeration With Metasploit

```bash
auxiliary/scanner/mysql/mysql_version
auxiliary/scanner/mysql/mysql_login
auxiliary/admin/mysql/mysql_enum
auxiliary/admin/mysql/mysql_sql
auxiliary/scanner/mysql/mysql_file_enum
auxiliary/scanner/mysql/mysql_hashdump
auxiliary/scanner/mysql/mysql_schemadump
auxiliary/scanner/mysql/mysql_writable_dirs
```
