# Google Dorks

### Exact KW Search

To search for content that contains an exact match of the KW, we use quotation marks. In search engine, we type the KW between double quotes.

```
“Penetration Testing Training“
```

### Site Search

To return results about specific website, we use the \[site:] operator followed by the website domain

```
site:google.com
```

Another option is to return results with specific keyword such as below

```
site:google.com careers
```

The above query would return results only from google.com where there is mention of the word \[careers]

### File search

#### By extension

we can search for specific file using its extension as below.

```
filetype:pdf
```

Example would be giving a keyword and searching for pdf files containing this keyword.

```
Hacking filetype:pdf
```

### Viewing cached results

We can retrieve cached versions of a specific website using the operator \[cache:]. An example is below

```
cache:facebook.com
```

### Searching by title

We can retrieve results that contain a specific title that matches our keyword. For example, we can look for results where the title is \[Google Dorks]

```
intitle:“Google Dorks“
```

Another example combining both title and in-page search such as below

```
intitle:“dorks“ google
```

This will return results with \[dorks] in the title and \[google] anywhere in the page.

### Google Cache

If a website/page is down, you can still view its contents using Google cache.

```
cache:example.com
```

### Locating text within a page

Consider this as searching and looking for a string or keyword in a page. We can use the \[allintext:] operator to search for a keyword within a page text.

```
allintext:“password is“
```

Will return all search results where pages contain the phrase \[password is]

### Searching by strings in the URL

We can look for strings in the URLs using \[inurl:] operator. Below query Will return all results containing \[login.php] in their URLs.

```
inurl:login.php
```

This next query will return URLS containing both \[admin] and \[login].

```
allinurl:admin login
```

Another example is using the `cpath` or `category path` to reveal POTENTIAL vulnerable web servers

```
allinurl:"index.php?cpath"
```

You can also combine the above one with `inurl` to tell google to find another word in the URL

```
allinurl:"index.php?cpath" inurl:"/catalog"
```

This will find URLs that contain both `index.php?cpath` and `/catalog` in the URL.

### Finding links

In some scenarios, we may need to find HTML links to a specified domain. Below query will return all results where there is HTML link in the page pointing to google.com

```
link:www.google.com
```

### Finding anchors

If we want to search for anchor texts, we can use the \[inanchor:] operator.

```
inanchor:click
```

### Finding sites with directory listing enabled

The below dorks can be used.

```
intitle:index.of “parent directory”
intitle:index.of name size.
```

### Finding admin pages if directory listing was enabled

```
intitle:index.of inurl:admin
intitle:index.of.admin
```

### Finding server version if directory listing was enabled

```
intitle:index.of “server at”
```

Or we could look for exact server name and version

```
intitle:index.of “Apache/1.3.27 Server at”.
```

### Searching for wordpress config file

```
filetype:php inurl:wp-config
```

### Locating generic firewall configuration files

```
filetype:conf inurl:firewall
```

### Locating phpmyadmin configuration files.

```
inurl:conf OR inurl:config OR inurl:cfg phpmyadmin
```

### Locating Log files

```
filetype:log inurl:log
ext:log log
```

### Locating office files containing passwords

```
inurl:xls OR inurl:doc OR inurl:mdb password
```

### Locating database files

Database files are of many extensions but lets say we want to locate \[mdb] then the below query can be used

```
filetype:mdb inurl:com
```

### Locating websites that could vulnerable to SQL,IDOR,SSRF or LFI,RFI

```
'keyword' inurl:.php? inurl:id=
```

### Using Google Hacking Database

Combining advanced Google searches with specific terms, documents containing sensitive information or vulnerable web servers can be found. Websites such as [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) (GHDB) collect such search terms and are publicly available. Let's take a look at some of the GHDB queries to see if our client has any confidential information exposed via search engines. GHDB contains queries under the following categories:

* **Footholds**\
  Consider [GHDB-ID: 6364](https://www.exploit-db.com/ghdb/6364) as it uses the query `intitle:"index of" "nginx.log"` to discover Nginx logs and might reveal server misconfigurations that can be exploited.
* **Files Containing Usernames**\
  For example, [GHDB-ID: 7047](https://www.exploit-db.com/ghdb/7047) uses the search term `intitle:"index of" "contacts.txt"` to discover files that leak juicy information.
* **Sensitive Directories**\
  For example, consider [GHDB-ID: 6768](https://www.exploit-db.com/ghdb/6768), which uses the search term `inurl:/certs/server.key` to find out if a private RSA key is exposed.
* **Web Server Detection**\
  Consider [GHDB-ID: 6876](https://www.exploit-db.com/ghdb/6876), which detects GlassFish Server information using the query `intitle:"GlassFish Server - Server Running"`.
* **Vulnerable Files**\
  For example, we can try to locate PHP files using the query `intitle:"index of" "*.php"`, as provided by [GHDB-ID: 7786](https://www.exploit-db.com/ghdb/7786).
* **Vulnerable Servers**\
  For instance, to discover SolarWinds Orion web consoles, [GHDB-ID: 6728](https://www.exploit-db.com/ghdb/6728) uses the query `intext:"user name" intext:"orion core" -solarwinds.com`.
* **Error Messages**\
  Plenty of useful information can be extracted from error messages. One example is [GHDB-ID: 5963](https://www.exploit-db.com/ghdb/5963), which uses the query `intitle:"index of" errors.log` to find log files related to errors.

### Online Tools

```
https://www.googleguide.com/advanced_operators_reference.html
```
