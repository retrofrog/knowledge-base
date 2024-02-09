# Troubleshooting

## Restart Network (Debian)

```sh
ip a # cheking the network interfaces
sudo nano /etc/network/interface
###
auto ens33 # change depend on the interface detected before
iface ens33 inet static
	address 192.168.120.130
	netmask 255.255.255.0
	gateway 192.168.1.1
###
ifdown ens33
ifup ens33
```

## Find newly spawned VM IP

```sh
sudo netdiscover -i eth0
```
