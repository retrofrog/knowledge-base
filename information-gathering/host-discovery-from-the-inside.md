# Host Discovery From The Inside

## Host Discovery From The Inside

If you are inside the network one of the first things you will want to do is to **discover other hosts**. Depending on **how much noise** you can/want to do, different actions could be performed:

### Passive

You can use these tools to passively discover hosts inside a connected network:

```bash
netdiscover -p
p0f -i eth0 -p -o /tmp/p0f.log
# Bettercap
net.recon on/off #Read local ARP cache periodically
net.show
set net.show.meta true #more info
```

### Active

Note that the techniques commented in \[\[Host Discovery From The Outside]] (_TCP/HTTP/UDP/SCTP Port Discovery_) can be also **applied here**. But, as you are in the **same network** as the other hosts, you can do **more things**:

```bash
#ARP discovery
nmap -sn <Network> #ARP Requests (Discover IPs)
netdiscover -r <Network> #ARP requests (Discover IPs)

#NBT discovery
nbtscan -r 192.168.0.1/24 #Search in Domain

# Bettercap
net.probe on/off #Discover hosts on current subnet by probing with ARP, mDNS, NBNS, UPNP, and/or WSD
set net.probe.mdns true/false #Enable mDNS discovery probes (default=true)
set net.probe.nbns true/false #Enable NetBIOS name service discovery probes (default=true)
set net.probe.upnp true/false #Enable UPNP discovery probes (default=true)
set net.probe.wsd true/false #Enable WSD discovery probes (default=true)
set net.probe.throttle 10 #10ms between probes sent (default=10)

#IPv6
alive6 <IFACE> # Send a pingv6 to multicast.
```

### Active ICMP

Note that the techniques commented in _Discovering hosts from the outside (ICMP)_ can be also **applied here**. But, as you are in the **same network** as the other hosts, you can do **more things**:

* If you **ping** a **subnet broadcast address** the ping should be arrive to **each host** and they could **respond** to **you**: `ping -b 10.10.5.255`
* Pinging the **network broadcast address** you could even find hosts inside **other subnets**: `ping -b 255.255.255.255`
* Use the `-PE`, `-PP`, `-PM` flags of `nmap`to perform host discovery sending respectively **ICMPv4 echo**, **timestamp**, and **subnet mask requests:** `nmap -PE -PM -PP -sn -vvv -n 10.12.5.0/24`

## Wake On Lan

Wake On Lan is used to **turn on** computers through a **network message**. The magic packet used to turn on the computer is only a packet where a **MAC Dst** is provided and then it is **repeated 16 times** inside the same paket.

Then this kind of packets are usually sent in an **ethernet 0x0842** or in a **UDP packet to port 9**. If **no \[MAC]** is provided, the packet is sent to **broadcast ethernet** (and the broadcast MAC will be the one being repeated).

```bash
# Bettercap (if no [MAC] is specificed ff:ff:ff:ff:ff:ff will be used/entire broadcast domain)
wol.eth [MAC] #Send a WOL as a raw ethernet packet of type 0x0847
wol.udp [MAC] #Send a WOL as an IPv4 broadcast packet to UDP port 9
```
