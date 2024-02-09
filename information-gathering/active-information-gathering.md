# Active Information Gathering

IP address from subdomains

```sh
for i in $(cat subdomains.txt); do dig $i | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | grep -vE "10.*"; done
```

Search for all leaked keys/secrets using one regex

```sh
(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]
```

## DNS Zone Transfer

### dnsenum

```sh
dnsenum zonetransfer.me
```

### dig

```sh
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

### fierce

```sh
fierce --domain zonetransfer.me
```

## Shodan queries – osintme.com

{% embed url="https://www.osintme.com/index.php/2021/01/16/ultimate-osint-with-shodan-100-great-shodan-queries/" %}
Shodan queries
{% endembed %}

You can experiment with making Shodan search queries, or you can take this shortcut and use some of my ones.

Each of the 100+ queries has been manually tested and (at the time of writing at least) it delivers tangible results.

If you find something else useful that is not covered here, please drop it in the comments below.

#### Webcam searches

1. [title:camera](https://www.shodan.io/search?query=title%3Acamera) – general search for anything matching the “camera” keyword.
2. [webcam has\_screenshot:true](https://www.shodan.io/search?query=webcam+has\_screenshot%3Atrue) – a general search for any IoT device identified as a webcam that has screenshots available.
3. [has\_screenshot:true IP Webcam](https://www.shodan.io/search?query=has\_screenshot%3Atrue+IP+Webcam) – another version of the above search, see how the results might differ?
4. [server: webcampxp](https://www.shodan.io/search?query=server%3A+webcamxp) – webcamXP is one of the most popular and commonly encountered network camera software for Windows OS.&#x20;
5. [server: “webcam 7”](https://www.shodan.io/search?query=server%3A+%22webcam+7%22) – webcam 7 cameras; not as popular as the above type, but still they are still popular and encountered out there.
6. [title:”blue iris remote view”](https://www.shodan.io/search?query=title%3A%22blue+iris+remote+view%22) – webcams identified as belonging to the [Blue Iris](https://blueirissoftware.com/) webcam remote management and monitoring service.
7. [title:”ui3 -“](https://www.shodan.io/search?query=title%3A%22ui3+-%22) – UI3 is a  HTML5 web interface for Blue Iris mentioned above.
8. [title:”Network Camera VB-M600″](https://www.shodan.io/search?query=title%3A%22Network+Camera+VB-M600%22) – Canon manufactured megapixel security cameras.
9. [product:”Yawcam webcam viewer httpd”](https://www.shodan.io/search?query=product%3A%22Yawcam+webcam+viewer+httpd%22) – Yawcam stands for Yet Another WebCAM, free live streaming and webcam software.
10. [title:”IPCam Client”](https://www.shodan.io/search?query=title%3A%22IPCam+Client%22) – IPCam Client webcam devices.
11. [server: GeoHttpServer](https://www.shodan.io/search?query=Server%3A+GeoHttpServer) – GeoVision (GeoHttpServer) Webcams, older webcam software with some had well documented vulnerabilities.
12. [server: VVTK-HTTP-Server](https://www.shodan.io/search?query=server%3A+VVTK-HTTP-Server) – Vivotek IP cameras.
13. [title:”Avigilon”](https://www.shodan.io/search?query=title%3A%22Avigilon%22) – access to the Avigilion brand camera and monitoring devices.
14. [ACTi](https://www.shodan.io/search?query=ACTi) – various IP camera and video management system products.
15. [WWW-Authenticate: “Merit LILIN Ent. Co., Ltd.”](https://www.shodan.io/search?query=WWW-Authenticate%3A+%22Merit+LILIN+Ent.+Co.%2C+Ltd.%22) – a UK-based house automation / IP camera provider.
16. [title:”+tm01+”](https://www.shodan.io/search?query=title%3A%22%2Btm01%2B%22) – unsecured Linksys webcams, a lot of them with screenshots.
17. [server: “i-Catcher Console”](https://www.shodan.io/search?query=server%3A+%22i-Catcher+Console%22) – another example of an IP-based CCTV system.
18. [Netwave IP Camera Content-Length: 2574](https://www.shodan.io/search?query=Netwave+IP+Camera+Content-Length%3A+2574) – access to the Netwave make IP cameras.
19. [200 ok dvr port:”81″](https://www.shodan.io/search?query=200+ok+dvr+port%3A%2281%22) – DVR CCTV cameras accessible via http.
20. [WVC80N](https://www.shodan.io/search?query=WVC80N) – Linksys WVC80N cameras.

Explore further by these tags:

WEBCAM: [https://www.shodan.io/explore/tag/webcam](https://www.shodan.io/explore/tag/webcam)

CAM: [https://www.shodan.io/explore/tag/cam ](https://www.shodan.io/explore/tag/cam)

CAMERA: [https://www.shodan.io/explore/tag/camera](https://www.shodan.io/explore/tag/camera)

<figure><img src="https://www.osintme.com/wp-content/uploads/2020/10/webcam-shodan-search-osint.png" alt="" height="556" width="905"><figcaption></figcaption></figure>

#### VOIP communication devices

1. [device:”voip”](https://www.shodan.io/search?query=device%3A%22voip%22) – general search for Voice over IP devices.
2. [device:”voip phone”](https://www.shodan.io/search?query=device%3A%22voip+phone%22) – more specific search for anything VoIP containing a “phone” keyword.
3. [server: snom](https://www.shodan.io/search?query=server%3A+snom) – Snom is a VoIP provider with some legacy devices online.
4. [“snom embedded 200 OK”](https://www.shodan.io/search?query=%22snom+embedded+200+OK%22) – Snom devices with enabled authentication.
5. [AddPac](https://www.shodan.io/search?query=AddPac) – an older VoIP provider, nearly exclusively legacy devices.
6. [mcu: tandberg](https://www.shodan.io/search?query=mcu%3A+tandberg) – Tandberg is a hardware manufacturer of multi-point control units for video conferencing.
7. [title:”polycom”](https://www.shodan.io/search?query=title%3A%22polycom%22) – Polycom is another VoIP communication brand.
8. [title:”openstage”](https://www.shodan.io/search?query=title%3A%22openstage%22) – Siemens Openstage brand IP phones.
9. [39 voip](https://www.shodan.io/search?query=39+voip) – some more VoIP services, mostly behind login screens
10. [Server: MSOS/2.0 mawebserver/1.1](https://www.shodan.io/search?query=Server%3A+MSOS%2F2.0+mawebserver%2F1.1) – VoIP media gateway, commonly used by services such as Patton SN4112 FXO.

Explore further by the VOIP tag: [https://www.shodan.io/explore/tag/voip](https://www.shodan.io/explore/tag/voip)

![](https://www.osintme.com/wp-content/uploads/2021/01/Patton-VoIP.png)

#### Database searches

![](https://www.osintme.com/wp-content/uploads/2020/10/kibana-shodan-search-osint.png)

#### Maritime devices

1. [maritime](https://www.shodan.io/search?query=maritime) – general search for anything related to maritime devices.
2. [sailor](https://www.shodan.io/search?query=sailor) – another wide search, could yield unrelated results!
3. [org:marlink](https://www.shodan.io/search?query=org%3Amarlink) – general search; Marlink is the world’s largest maritime satellite communications provider.
4. [satcom](https://www.shodan.io/search?query=satcom) – another maritime satellite communications services provider.
5. [inmarsat](https://www.shodan.io/search?query=inmarsat) – as above, but a slightly less known equipment vendor.
6. [vsat](https://www.shodan.io/search?query=vsat) – abbreviation for “very-small-aperture terminal”, a data transmitter / receiver commonly used by maritime vessels.
7. [ECDIS](https://www.shodan.io/search?query=ECDIS) – abbreviation for Electronic Chart Display and Information Systems, used in navigation and autopilot systems.
8. [uhp vsat terminal software -password](https://www.shodan.io/search?query=uhp+vsat+terminal+software+-password) – satellite network router without a password.
9. [ssl:”Cobham SATCOM”](https://www.shodan.io/search?query=ssl%3A%22Cobham+SATCOM%22) – maritime radio and locations systems.
10. [title:”Slocum Fleet Mission Control”](https://www.shodan.io/search?query=title%3A%22Slocum+Fleet+Mission+Control%22) – maritime mission control software.

Explore further by the VSAT tag: [https://www.shodan.io/explore/tag/vsat](https://www.shodan.io/explore/tag/vsat)

#### Files & directories

#### Legacy Windows operating systems

#### Default / generic credentials

1. [admin 1234](https://www.shodan.io/search?query=admin+1234) – basic very unsecure credentials.
2. [“default password”](https://www.shodan.io/search?query=%22default+password%22) – speaks for itself…
3. [test test port:”80″](https://www.shodan.io/search?query=test+test+port%3A%2280%22) – generic test credentials over HTTP.
4. [“authentication disabled” “RFB 003.008”](https://www.shodan.io/search?query=%22authentication+disabled%22+%22RFB+003.008%22) – no authentication necessary.
5. “[root@” port:23 -login -password -name -Session](https://www.shodan.io/search?query=%22root%40%22+port%3A23+-login+-password+-name+-Session) – accounts already logged in with root privilege over Telnet, port 23.
6. [port:23 console gateway](https://www.shodan.io/search?query=port%3A23+console+gateway) – remote access via Telnet, no password required.
7. [html:”def\_wirelesspassword”](https://www.shodan.io/search?query=html%3A%22def\_wirelesspassword%22) – default login pages for routers.
8. [“polycom command shell”](https://www.shodan.io/search?query=%22polycom+command+shell%22) – possible authentication bypass to Polycom devices.
9. [“authentication disabled” port:5900,5901](https://www.shodan.io/search?query=%22authentication+disabled%22+port%3A5900%2C5901) – VNC services without authentication.
10. [“server: Bomgar” “200 OK”](https://www.shodan.io/search?query=%22server%3A+Bomgar%22+%22200+OK%22) – Bomgar remote support service.

Explore further by the VNC tag: [https://www.shodan.io/explore/tag/vnc](https://www.shodan.io/explore/tag/vnc)

![](https://www.osintme.com/wp-content/uploads/2021/01/Bomgar-remote-not-secure.png)

#### Printers

#### Compromised devices and websites

1. [hacked](https://www.shodan.io/search?query=hacked) – general search for the ‘hacked’ label.
2. [“hacked by”](https://www.shodan.io/search?query=%22hacked+by%22) – another variation of the above search.
3. [http.title:”Hacked by”](https://www.shodan.io/search?query=http.title%3A%22Hacked+by%22) – another variation of the same search filter.
4. [http.title:”0wn3d by”](https://www.shodan.io/search?query=http.title%3A%220wn3d+by%22) – resourced labelled as ‘owned’ by a threat agent, hacker group, etc.
5. [“HACKED-ROUTER”](https://www.shodan.io/search?query=%22HACKED-ROUTER%22) – compromised routers, labelled accordingly.
6. [port:”27017″ “send\_bitcoin\_to\_retrieve\_the\_data”](https://www.shodan.io/search?query=port%3A%2227017%22+%22send\_bitcoin\_to\_retrieve\_the\_data%22) – databases affected by ransomware, with the ransom demand still associated with them.
7. [bitcoin has\_screenshot:true](https://www.shodan.io/search?query=bitcoin+has\_screenshot%3Atrue) – searches for the ‘bitcoin’ keyword, where a screenshot is present (useful for RDP screens of endpoints infected with ransomware).
8. [port:4444 system32](https://www.shodan.io/search?query=port%3A4444+system32) – compromised legacy operating systems. Port 4444 is the default port for Meterpreter – a Metasploit attack payload with an interactive shell for remote code execution.
9. [“attention”+”encrypted”+port:3389](https://www.shodan.io/search?query=%22attention%22%2B%22encrypted%22%2Bport%3A3389) – ransomware infected RDP services.
10. [“HACKED-ROUTER-HELP-SOS-HAD-DEFAULT-PASSWORD”](https://www.shodan.io/search?query=%22HACKED-ROUTER-HELP-SOS-HAD-DEFAULT-PASSWORD%22) – compromised hosts with the name changed to that phrase.
11. [“HACKED FTP server”](https://www.shodan.io/search?query=%22HACKED+FTP+server%22+) – compromised FTP servers.

Explore further by the HACKED tag: [https://www.shodan.io/explore/tag/hacked ](https://www.shodan.io/explore/tag/hacked)

![](https://www.osintme.com/wp-content/uploads/2021/01/ransomware-osint-shodan.png)

#### Miscellaneous

1. [solar](https://www.shodan.io/search?query=solar) – controls for solar panels and similar solar devices.
2. [“ETH – Total speed”](https://www.shodan.io/search?query=%22ETH+-+Total+speed%22) – Ethereum cryptocurrency miners.
3. [http.html:”\* The wp-config.php creation script uses this file”](https://www.shodan.io/search?query=http.html%3A%22\*+The+wp-config.php+creation+script+uses+this+file%22) – misconfigured WordPress websites.
4. [http.title:”Nordex Control”](https://www.shodan.io/search?query=http.title%3A%22Nordex+Control%22) – searches for Nordex wind turbine farms.
5. [“Server: EIG Embedded Web Server” “200 Document follows”](https://www.shodan.io/search?query=%22Server%3A+EIG+Embedded+Web+Server%22+%22200+Document+follows%22) – EIG electricity meters.
6. [“DICOM Server Response” port:104](https://www.shodan.io/search?query=%22DICOM+Server+Response%22+port%3A104) – DICOM medical machinery.
7. [http.title:”Tesla”](https://www.shodan.io/search?query=http.title%3A%22Tesla%22) –  anything with the term “Tesla” in the banner.
8. [“in-tank inventory” port:10001](https://www.shodan.io/search?query=%22in-tank+inventory%22+port%3A10001) – petrol pumps, including their physical addresses.
9. [http.title:”dashboard”](https://www.shodan.io/search?query=http.title%3A%22dashboard%22) – literally anything labelled ‘dashboard’, with many not accessible due to security by default.
10. [http.title:”control panel”](https://www.shodan.io/search?query=http.title%3A%22control+panel%22) – as above, but whatever is labelled as control panels.
