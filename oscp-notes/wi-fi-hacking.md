# Wi Fi Hacking

### Wireless Basics

**Wireless Access Point** A wireless access point (AP) connects wireless clients to a wired network. However, many APs also have routing capabilities. Note the below • `All wireless routers are APs`: These are APs with an extra capability ;routing. • `Not all APs are wireless routers`: Many APs do not have any additional capabilities. They provide connectivity for wireless clients to a wired network but do not have routing capabilities. **MAC Filtering** MAC filtering can restrict access to a wireless network to specific clients. However, an attacker can use a sniffer to discover allowed MAC addresses and circumvent this form of network access control. It’s relatively simple for an attacker to spoof a MAC address using a MAC address changer. **Site Survey** A site survey examines the wireless environment to identify potential problem areas using `Wi-Fi Analyzers`. A heat map shows wireless coverage and dead spots if they exist. Wireless footprinting gives you a detailed diagram of wireless access points, hotspots, and dead spots within an organization. **WEP (Wired Equivalent Privacy)**: WEP is an older wireless security protocol that is no longer considered secure. WEP uses a shared key to authenticate users and encrypt data. However, WEP is vulnerable to security breaches, and its encryption can be easily cracked. **WPA (Wi-Fi Protected Access):** WPA is a wireless security protocol that provides stronger encryption and authentication than the older WEP standard. WPA uses a passphrase or key to authenticate users and encrypt data. WPA2 is the latest version of WPA and is considered the most secure wireless security protocol. **WPA2** WPA2 uses strong cryptographic protocols such as Advanced Encryption Standard (AES) and Counter-mode/CBC-MAC Protocol (CCMP). WPA2 can operate in either open, pre-shared key (PSK), or Enterprise modes. `Open mode` doesn’t use any security. Instead, all data is transferred in cleartext, making it easy for anyone who captured it to read it. In `PSK mode`, users access the wireless network anonymously with a PSK or passphrase which provides authorization but not authentication (username+password). `Enterprise mode` forces users to authenticate with unique credentials before granting them access to the wireless network. Enterprise mode uses a RADIUS server, which accesses a database of accounts. If users don’t have the proper credentials, Enterprise mode blocks their access. In order to configure enterprise mode, we need to enter the IP address of the RADIUS server, the port the server is using and the shared secret to access the server. After configuring WPA2 Enterprise on an AP, it redirects all attempts to connect to the RADIUS server to authenticate. After users authenticate, the RADIUS server tells the AP to grant them access. **WPA3** Wi-Fi Protected Access 3 (WPA3) is the newest wireless cryptographic protocol. It uses Simultaneous Authentication of Equals (SAE) instead of the PSK used with WPA2. **EAP-TLS (Extensible Authentication Protocol-Transport Layer Security):** EAP-TLS is a wireless security protocol that is widely used in enterprise-level networks. It provides strong security by using digital certificates to authenticate users and encrypt data. EAP-TLS is considered one of the most secure wireless security protocols available. **Wireless Authentication Protocols** Some of the wireless authentication protocols are

```
- Extensible Authentication Protocol (EAP)
- Protected EAP (PEAP). PEAP provides an extra layer of protection
for EAP.
- EAP-FAST
- EAP-TLS
- EAP-TTLS
- RADIUS Federation
```

**Wi-Fi Captive Portal** A captive portal is a technical solution that forces clients using web browsers to complete a specific process before it allows them access to the network. we commonly use it as a hotspot that requires users to log on or agree to specific terms before they can access the Internet. Captive portals are used heavily in free-internet access networks such as in hospitals, hotels, resorts or it can be used instead of setting up a RADIUS server to reduce cost and overhead. Attacking captive portals is simply done by using simple wireless MAC address cloning to gain access to the network while appearing like an authorized system.Kali Linux provides a built-in captive portal tool called hack-captive- portals. The tool sniffs wireless networks for authorized wireless hosts and uses the information captured to spoof both the authorized system’s IP and MAC addresses, providing easy access to the network.

### Wireless Attacks

**Disassociation Attacks** A disassociation attack effectively removes a wireless client from a wireless network by sending a `de-auth` packets to the client. Attackers send a disassociation frame to the AP with a spoofed MAC address of the victim. The AP receives the frame and shuts down the connection. The victim is now disconnected from the AP and must go through the authentication process again to reconnect. **Rogue AP** A rogue access point (rogue AP) is an AP placed within a network without official authorization. This can be as simple as a printer, IOT device, or router that gets plugged in and provides access to the network or it might be an employee who is bypassing security or installed by an attacker to sniff packets. Attackers may connect a rogue access point to network devices in wireless closets that lack adequate physical security. The primary aim of a rogue AP is to connect to the network and do illegitimate actions such as sniffing data or even exfiltrate data that reside in the network. **Evil Twin** An evil twin is a rogue access point with the same SSID (or similar) as a legitimate access point. You can think of the SSID of the evil twin as a twin of the legitimate AP’s SSID. Evil Twin attacks allow attackers to easily conduct on-path (MTIM) attacks to sniff credentials. Steps below:

1. Capture traffic to determine the SSID and MAC addresses of a legitimate access point.
2. Clone that access point using `airbase-ng`.
3. Conduct a de-authentication attack.
4. Ensure that the fake AP is more powerful (or closer!) and thus will be selected by the client when they try to reconnect.
5. Conduct attacks, including on-path attacks. Another way to conduct evil twin attacks is to use EAPHammer, a purpose-built tool designed to conduct evil twin attacks on WPA2 Enterprise mode networks.

```
https://github.com/s0lst1c3/eaphammer
```

Another example below is using Bettercap to listen and use HTTPS traffic to determine possible targets. **Setup Bettercap to capture HTTPS traffic**

```
bettercap -I <int> -O bettercap-https.log -S ARP -X --proxyhttps
--gateway X.X.X.X --target Y.Y.Y.Y
```

Then find an open network AP SSID and broadcast your Evil Twin with the same SSID. **Jamming Attacks** A Jamming attack is a type of a DDOS attack that eventually prevents user from connecting to the wireless network. Attackers can transmit noise or another radio signal on the same frequency used by a wireless network. This interferes with the wireless transmissions and can seriously degrade performance. **ARP Spoofing and Poisoning** The Address Resolution Protocol (ARP) is used to map IP addresses to physical machine addresses (MAC, or Media Access Control, addresses). Since systems rely on ARP to identify other systems on their local network, falsifying responses to ARP queries about which address traffic should be sent to can allow attackers to conduct various attacks that rely on victims sending their traffic to the wrong system, including on-path attacks or MTIM. ARP spoofing occurs when an attacker sends falsified ARP messages on a local network, thus providing an incorrect MAC address–to–IP address pairing for the deceived system or systems. This information is written to the target machine’s ARP cache, and the attacker can then either intercept or capture and forward traffic. **IV Attacks** An initialization vector (IV) is a number used by encryption systems, and a wireless IV attack attempts to discover the pre-shared key after first discovering the IV. Some wireless protocols use an IV by combining it with the pre-shared key to encrypt data in transit. When an encryption system reuses the same IV, an IV attack can discover the IV easily. **NFC Attacks** Near field communication (NFC) is a group of standards used on mobile devices that allow them to communicate with other mobile devices when they are close to them. Many point-of-sale card readers support NFC technologies with credit cards. Instead of swiping your card or inserting it to read the chip data, you wave your card over the reader. It is often advertised as a contactless payment method. Some smartphone applications support payments with NFC-enabled smartphones. Users wave their smartphones over the reader to make a payment. During a near field communication attack, an attacker uses an NFC reader to capture data from another NFC device. One method is an eavesdropping attack. The NFC reader uses an antenna to boost its range and intercepts the data transfer between two other devices. For example, imagine Marge is making a purchase at a store, and Bart is behind her with his own NFC reader. If Bart can boost the receiving range of his NFC reader, he can capture Marge’s transaction. The primary indication of an NFC attack is unauthorized charges on a credit card statement. **RFID Attacks** Radio-frequency identification (RFID) systems include an RFID reader and RFID tags placed on objects. They are used to track and manage inventory, and any type of valuable assets, including objects and animals. One difference between RFID and NFS is that RFID transmitters can send to and from tags from a much greater distance than proximity readers. For example sniffing is an effective attack to capture data transmitted over the air through RFID. Because RFID transmits data over the air, an attacker can collect it by listening. A key requirement is to know the RFID system’s frequency and have a receiver tuned to that frequency. The attacker also needs to know the protocols used by the RFID system to interpret the data. It’s also possible to launch a jamming or interference attack, flooding the frequency with noise. This prevents the RFID system from operating normally. **Wireless replay attack** In a replay attack, an attacker captures data sent between two entities, modifies it, and then attempts to impersonate one of the parties by replaying the data. Its worth nothing that WPA2 and WPA3 are resistant to replay attacks. **Bluejacking** Bluejacking is the practice of sending unsolicited messages to nearby Bluetooth devices. Bluejacking messages are typically text but can also be images or sounds. Bluejacking is relatively harmless but does cause some confusion when users start receiving messages. **Bluesnarfing** Bluesnarfing refers to the unauthorized access to, or theft of information from, a Bluetooth device. A bluesnarfing attack can access information, such as email, contact lists, calendars, and text messages. Kali includes the bluesnarfer package, which allows phonebook contact theft via Bluetooth, given a device ID or address. SpoofTooph can scan for Bluetooth devices, clone them, generate and act like a randomized Bluetooth device, and it can log the information it finds. Such tools can be used to hide a Bluetooth device that will be used to gather information from Bluetooth devices in an environment, and where those devices are trusted it can help with information gathering.

```
https://sourceforge.net/projects/spooftooph/
```

**Bluebugging** In addition to gaining full access to the phone as in Bluesnarfing, the attacker installs a backdoor. The attacker can have the phone call the attacker at any time, allowing the attacker to listen in on conversations within a room. Attackers can also listen in on phone conversations, enable call forwarding, send messages, and more. **War Driving** War driving is the practice of looking for a wireless network. Although war driving is more common in cars, you can just as easily do it by walking around in a large city. Attackers use war driving to discover wireless networks that they can exploit and often use directional antennas to detect wireless networks with weak signals. **War Flying** Same as war driving but conducted when someone is flying in the air in airplanes or private planes. **MITM Attacks** MITM attacks enable the attacker to sit in the middle of the path between the sender and the receiver and in order to achieve that, attacker usually compromise the network device handling the traffic such as a router or a switch. Another method is by performing de-auth attacks and ARP poisoning so that hosts think that the attacker is the main router or gateway. **WPS Attacks** Wi-Fi Protected Setup (WPS) has been a known issue for years, but it remains in use for ease of setup, particularly for consumer wireless devices. WPS requires an 8-digit PIN, which is easily cracked because WPS uses an insecure method of validating PINs. WPS passwords can be attacked using a pixie dust attack, a type of attack that brute-forces the key for WPS. Vulnerable routers can be attacked by leveraging the fact that many have poor selection algorithms for their preshared key random numbers. Reaver is one of the tools to perform WPS attacks

```
https://github.com/t6x/reaver-wps-fork-t6x
```

### Cracking Wi-Fi Security Key

#### Aircrack-ng

**starting the wireless interface on monitor mode** In the second command, note down the name of the interface of your wireless network card.

```
sudo airmon-ng check kill
sudo airmon-ng
sudo airmon-ng start [name-of-the-interface]
```

and then run the below command to make sure that the NIC is on monitor mode

```
iwconfig
```

**Capturing traffic and beacons of nearby WIFI networks \[terminal 1]**

```
airodump-ng wlan0mon
```

\[wlan0mon] is the name of the interface in monitor mode. It could be different in your case so make sure it's correct. **Narrowing down on specific network \[terminal 2]** In the previous step, we select the \[bssid] and \[channel] of the network that we want to target and on A SEPARATE TERMINAL (leave the terminal from the previous step open) type the below command

```
airodump-ng --bssid [bssid-goes-here] -c [CH] --write [outputfile] wlan0mon
```

**Sending Deauthentication frames \[terminal 3]** In this step, we want to disconnect one of the already connected devices from target network and force it to re-connect to be able to capture the 4-way WPA handshake

```
aireplay-ng --deauth [number-of-frames] -a [bssid] wlan0mon
```

The number of deauh frames can range from 50 till 300. **Capturing the handshake** Now its time to monitor \[terminal 1] and \[terminal 2] for the phrase \[WPA Handshake]. Once you find it proceed to the following step **Cracking The wireless key** In this step, we select a powerfull wordlist and we choose the output file created in step 3 \[terminal 2]

```
aircrack-ng output.cap -w [path-to-wordlist]
```

### MAC Spoofing

You can use MAC address spoofing to bypass network access controls, captive portals, and security filters that rely on a system’s MAC to identify it. You can also use it as part of on-path and other attacks that rely on systems thinking they’re sending traffic to a legitimate host. **Linux**

```
ip link set dev <interface> down
ip link set dev <interface> address XX:XX:XX:XX:XX:XX
ip link set dev <interface> up
```

**Windows** #Method-1-Registry First we find the network ID card under the below registry key

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\C
ontrol\Class\{4D36E972-E325-11CE-BFC1-
08002BE10318}
```

Look in DriverDesc field to ensure you have correct network card. Then we modify the below registry location and replace `XXXX` with the desired MAC address

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Co
ntrol\Class\{4D36E972-E325-11CE-BFC1-
08002BE10318}\_YYYY /v NetworkAddress /d
<XXXXXXXXXXXX> /f
```

Replace XX with desired mac address, replace YYYY with network card ID. #Method-1-Powershell

```
Set-NetAdapter -Name "Ethernet 1" -MacAddress "XX-XXXX-XX-XX-XX"
```

Replace XX with desired mac address.

### Security Recommendations

**Remember to change the default username and password**: The first and foremost step to secure your Wi-Fi network is to change the default username and password of your router. Default login credentials are easily available online, and cybercriminals can use them to gain access to your network. **Always use strong encryption**: It’s essential to enable WPA2 (Wi-Fi Protected Access II) encryption on your router to secure your wireless network. WPA2 is one of the most widely supported encryption methods currently available and provides a high level of security for your network. **Set up a guest network**: If you frequently have visitors who need to use your Wi-Fi, set up a guest network with a different password to keep your main network secure. **Enable the MAC address filtering**: MAC address filtering allows you to restrict access to your network by only allowing specific devices with pre-approved MAC addresses to connect. **Keep your router firmware up to date**: Router manufacturers regularly release firmware updates to address security vulnerabilities. Make sure you keep your router's firmware up to date by checking for updates regularly. **Disable remote management**: Unless you need it, disable remote management on your router. It’s a security risk as it allows cybercriminals to access your router's settings from outside your network.
