# Host Discovery From The Outside

## ICMP

This is the **easiest** and **fastest** way to discover if a host is up or not. You could try to send some **ICMP** packets and **expect responses**. The easiest way is just sending an **echo request** and expect from the response. You can do that using a simple `ping`or using `fping`for **ranges**. You could also use **nmap** to send other types of ICMP packets (this will avoid filters to common ICMP echo request-response).

```bash
ping -c 1 199.66.11.4    # 1 echo request to a host
fping -g 199.66.11.0/24  # Send echo requests to ranges
nmap -PE -PM -PP -sn -n 199.66.11.0/24 #Send echo, timestamp requests and subnet mask requests
```

## TCP Port Discovery

It's very common to find that all kind of ICMP packets are being filtered. Then, all you can do to check if a host is up is **try to find open ports**. Each host has **65535 ports**, so, if you have a "big" scope you **cannot** test if **each port** of each host is open or not, that will take too much time. Then, what you need is a **fast port scanner** [masscan](https://github.com/robertdavidgraham/masscan) and a list of the **ports more used:**

```bash
#Using masscan to scan top20ports of nmap in a /24 range (less than 5min)
masscan -p20,21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 199.66.11.0/24
```

You could also perform this step with `nmap`, but it slower and somewhat `nmap`has problems identifying hosts up.

## UDP Port Discovery

You could also try to check for some **UDP port open** to decide if you should **pay more attention** to a **host.** As UDP services usually **don't respond** with **any data** to a regular empty UDP probe packet it is difficult to say if a port is being filtered or open. The easiest way to decide this is to send a packet related to the running service, and as you don't know which service is running, you should try the most probable based on the port number:

```bash
nmap -sU -sV --version-intensity 0 -F -n 199.66.11.53/24
# The -sV will make nmap test each possible known UDP service packet
# The "--version-intensity 0" will make nmap only test the most probable
```

The nmap line proposed before will test the **top 1000 UDP ports** in every host inside the **/24** range but even only this will take **>20min**. If need **fastest results** you can use [udp-proto-scanner](https://github.com/portcullislabs/udp-proto-scanner):

`./udp-proto-scanner.pl 199.66.11.53/24` This will send these **UDP probes** to their **expected port** (for a /24 range this will just take 1 min): _DNSStatusRequest, DNSVersionBindReq, NBTStat, NTPRequest, RPCCheck, SNMPv3GetRequest, chargen, citrix, daytime, db2, echo, gtpv1, ike,ms-sql, ms-sql-slam, netop, ntp, rpc, snmp-public, systat, tftp, time, xdmcp._
