
# ROOM 1  
#### NetworkMiner  
"*NetworkMiner is an open-source Network Forensic Analysis Tool (NFAT) for Windows (but also works in Linux / macOS / FreeBSD). NetworkMiner can be used as a passive network sniffer/packet-capturing tool to detect operating systems, sessions, hostnames, open ports, etc., without putting any traffic on the network. NetworkMiner can also parse PCAP files for offline analysis and to regenerate/reassemble transmitted files and certificates from PCAP files.*"  

#### Network Data Types:  
- Live Traffic  
- Traffic Captures  
- Log Files  

**NetworkMiner in a Nutshell**  

| **Capability**             | **Description**                                                                                                                                                               |  
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |  
| Traffic Sniffing           | It can intercept the traffic, sniff it, and collect and log packets that pass through the network.                                                                            |  
| Parsing PCAP Files         | It can parse PCAP files and show the content of the packets in detail.                                                                                                        |  
| Protocol Analysis          | It can identify the used protocols from the parsed PCAP file.                                                                                                                 |  
| OS Fingerprinting          | It can identify the used OS by reading the PCAP file. This feature strongly relies on [Satori](https://github.com/xnih/satori/) and [p0f](https://lcamtuf.coredump.cx/p0f3/). |  
| File Extraction            | It can extract images, HTML files, and emails from the parsed PCAP file.                                                                                                      |  
| Credential Grabbing        | It can extract credentials from the parsed PCAP file.                                                                                                                         |  
| Clear Text Keyword Parsing | It can extract cleartext keywords and strings from the parsed PCAP file.                                                                                                      |  

NetworkMiner has two main modes:  
- **Sniffer mode**: Not reliable.  
- **Packet parsing/processing mode**.  

**Pros**  
- OS Fingerprinting  
- Easy file extraction  
- Credential grabbing  
- Clear text keyword parsing  
- Overall overview  

**Cons**  
- Not useful for active sniffing  
- Not useful for large PCAP investigations  
- Limited filtering  
- Not built for manual traffic investigation  

---

# ROOM 2  
#### Zeek  
Zeek is an open-source traffic analysis tool.  

**Zeek vs. Snort**  

| **Tool**            | **Zeek**                                                                                                                                                                                                           | **Snort**                                                                                                                                               |  
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- |  
| **Capabilities**    | NSM and IDS framework. It is heavily focused on network analysis. It is more focused on specific threats to trigger alerts. The detection mechanism is focused on events.                                          | An IDS/IPS system. It is heavily focused on signatures to detect vulnerabilities. The detection mechanism is focused on signature patterns and packets. |  
| **Cons**            | Hard to use. The analysis is done outside of Zeek, manually or by automation.                                                                                                                                      | Hard to detect complex threats.                                                                                                                         |  
| **Pros**            | It provides in-depth traffic visibility. Useful for threat hunting. Ability to detect complex threats. It has a scripting language and supports event correlation. Easy-to-read logs.                               | Easy to write rules. Cisco-supported rules. Community support.                                                                                          |  
| **Common Use Case** | Network monitoring. In-depth traffic investigation. Intrusion detection in chained events.                                                                                                                         | Intrusion detection and prevention. Stop known attacks/threats.                                                                                         |  

**Zeek Parameters**  
Main Zeek command-line parameters are explained below:  

| **Parameter** | **Description**                           |  
| ------------- | ----------------------------------------- |  
| **-r**        | Reading option; read/process a PCAP file. |  
| **-C**        | Ignore checksum errors.                   |  
| **-v**        | Version information.                      |  
| **zeekctl**   | Zeek control module.                      |  

---

# ROOM 3  
#### Brim  
Brim is an open-source desktop application that processes PCAP files and log files, with a primary focus on providing search and analytics. It uses the Zeek log processing format. It also supports Zeek signatures and Suricata rules for detection.  

**The common best practice is handling medium-sized PCAPs with Wireshark, creating logs and correlating events with Zeek, and processing multiple logs in Brim.**  

|                          | Brim                                                  | Wireshark                                                           | Zeek                                                 |  
| ------------------------ | ----------------------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------- |  
| **Purpose**              | PCAP processing; event/stream and log investigation.  | Traffic sniffing. PCAP processing; packet and stream investigation. | PCAP processing; event/stream and log investigation. |  
| **GUI**                  | ✔                                                    | ✔                                                                   | ✖                                                    |  
| **Sniffing**             | ✖                                                    | ✔                                                                   | ✔                                                    |  
| **PCAP Processing**      | ✔                                                    | ✔                                                                   | ✔                                                    |  
| **Log Processing**       | ✔                                                    | ✖                                                                   | ✔                                                    |  
| **Packet Decoding**      | ✖                                                    | ✔                                                                   | ✔                                                    |  
| **Filtering**            | ✔                                                    | ✔                                                                   | ✔                                                    |  
| **Scripting**            | ✖                                                    | ✖                                                                   | ✔                                                    |  
| **Signature Support**    | ✔                                                    | ✖                                                                   | ✔                                                    |  
| **Statistics**           | ✔                                                    | ✔                                                                   | ✔                                                    |  
| **File Extraction**      | ✖                                                    | ✔                                                                   | ✔                                                    |  
| **Handling PCAPs >1GB** | Medium performance                                   | Low performance                                                     | Good performance                                     |  
| **Ease of Management**   | 4/5                                                  | 4/5                                                                 | 3/5                                                  |  

---

# ROOM 4  
## Wireshark  

### Packet Filter  
- **Scope**: host, net, port, and portrange.  
- **Direction**: src, dst, src or dst, src and dst.  
- **Protocol**: ether, wlan, ip, ip6, arp, rarp, tcp, and udp.  
- **Sample filter to capture port 80 traffic**: `tcp port 80`.  

**Comparison Operators**  

You can create display filters using different comparison operators to find the event of interest. The primary operators are shown in the table below.  

| **English**       | **C-Like** | **Description**               | **Example**                     |  
| ----------------- | ---------- | ----------------------------- | ------------------------------- |  
| eq                | ==         | Equal                         | `ip.src == 10.10.10.100`        |  
| ne                | !=         | Not equal                     | `ip.src != 10.10.10.100`        |  
| gt                | >          | Greater than                  | `ip.ttl > 250`                  |  
| lt                | <          | Less than                     | `ip.ttl < 10`                   |  
| ge                | >=         | Greater than or equal to      | `ip.ttl >= 0xFA`                |  
| le                | <=         | Less than or equal to         | `ip.ttl <= 0xA`                 |  

**Note**: Wireshark supports decimal and hexadecimal values in filtering. You can use any format you want according to the search you conduct.  

**Logical Expressions**  

Wireshark supports boolean syntax. You can create display filters using logical operators as well.  

| **English** | **C-Like** | **Description** | **Example**                                                                 |  
| ----------- | ---------- | --------------- | --------------------------------------------------------------------------- |  
| and         | &&         | Logical AND     | `(ip.src == 10.10.10.100) && (ip.src == 10.10.10.111)`                      |  
| or          | \|\|       | Logical OR      | `(ip.src == 10.10.10.100) \|\| (ip.src == 10.10.10.111)`                   |  
| not         | !          | Logical NOT     | `!(ip.src == 10.10.10.222)`                                                |  

**Note**: The usage of `!=value` is deprecated; using it could provide inconsistent results. Using the `!(value)` style is suggested for more consistent results.  

### Common Filters  

| **Filter**                     | **Description**                                      |  
| ------------------------------ | ---------------------------------------------------- |  
| `ip`                           | Show all IP packets.                                 |  
| `ip.addr == 10.10.10.111`      | Show all packets containing IP address 10.10.10.111. |  
| `ip.addr == 10.10.10.0/24`     | Show all packets from the 10.10.10.0/24 subnet.      |  
| `ip.src == 10.10.10.111`       | Show all packets originating from 10.10.10.111.      |  
| `ip.dst == 10.10.10.111`       | Show all packets sent to 10.10.10.111.               |  

**Note**: `ip.addr` filters traffic without considering packet direction, while `ip.src`/`ip.dst` filters based on direction.  

### TCP/UDP Port Filters  

| **Filter**               | **Description**                              | **Filter**               | **Description**                              |  
| ------------------------ | -------------------------------------------- | ------------------------ | -------------------------------------------- |  
| `tcp.port == 80`         | Show all TCP packets with port 80.           | `udp.port == 53`         | Show all UDP packets with port 53.           |  
| `tcp.srcport == 1234`    | Show all TCP packets from port 1234.         | `udp.srcport == 1234`    | Show all UDP packets from port 1234.         |  
| `tcp.dstport == 80`      | Show all TCP packets sent to port 80.        | `udp.dstport == 5353`    | Show all UDP packets sent to port 5353.      |  

### Application-Level Protocol Filters (HTTP and DNS)  

| **Filter**                      | **Description**                          | **Filter**                      | **Description**                          |  
| ------------------------------- | ---------------------------------------- | ------------------------------- | ---------------------------------------- |  
| `http`                          | Show all HTTP packets.                   | `dns`                           | Show all DNS packets.                    |  
| `http.response.code == 200`     | Show packets with HTTP response code 200.| `dns.flags.response == 0`       | Show all DNS requests.                   |  
| `http.request.method == "GET"`  | Show all HTTP GET requests.              | `dns.flags.response == 1`       | Show all DNS responses.                  |  
| `http.request.method == "POST"` | Show all HTTP POST requests.             | `dns.qry.type == 1`             | Show all DNS "A" records.                |  

### Advanced Filtering  

#### Filter: "contains"  

| **Filter**      | **Description**                                                                                          |  
| --------------- | -------------------------------------------------------------------------------------------------------- |  
| **Type**        | Comparison Operator                                                                                      |  
| **Description** | Searches for a value inside packets. Case-sensitive. Similar to the "Find" option but focuses on a field.|  
| **Example**     | Find all "Apache" servers.                                                                               |  
| **Usage**       | `http.server contains "Apache"`                                                                          |  

#### Filter: "matches"  

| **Filter**      | **Description**                                                                                          |  
| --------------- | -------------------------------------------------------------------------------------------------------- |  
| **Type**        | Comparison Operator                                                                                      |  
| **Description** | Searches for a pattern using regular expressions. Case-insensitive.                                      |  
| **Example**     | Find all .php and .html pages.                                                                           |  
| **Usage**       | `http.host matches "\.(php\|html)"`                                                                      |  

#### Filter: "in"  

| **Filter**      | **Description**                                                                                          |  
| --------------- | -------------------------------------------------------------------------------------------------------- |  
| **Type**        | Set Membership                                                                                           |  
| **Description** | Searches for a value or field within a specific scope/range.                                             |  
| **Example**     | Find all packets using ports 80, 443, or 8080.                                                           |  
| **Usage**       | `tcp.port in {80 443 8080}`                                                                              |  

#### Filter: "upper"  

| **Filter**      | **Description**                                                                                          |  
| --------------- | -------------------------------------------------------------------------------------------------------- |  
| **Type**        | Function                                                                                                 |  
| **Description** | Converts a string value to uppercase.                                                                    |  
| **Example**     | Find all "APACHE" servers.                                                                               |  
| **Usage**       | `upper(http.server) contains "APACHE"`                                                                   |  

#### Filter: "lower"  

| **Filter**      | **Description**                                                                                          |  
| --------------- | -------------------------------------------------------------------------------------------------------- |  
| **Type**        | Function                                                                                                 |  
| **Description** | Converts a string value to lowercase.                                                                    |  
| **Example**     | Find all "apache" servers.                                                                               |  
| **Usage**       | `lower(http.server) contains "apache"`                                                                   |  

#### Filter: "string"  

| **Filter**      | **Description**                                                                                          |  
| --------------- | -------------------------------------------------------------------------------------------------------- |  
| **Type**        | Function                                                                                                 |  
| **Description** | Converts a non-string value to a string.                                                                 |  
| **Example**     | Find all frames with odd numbers.                                                                        |  
| **Usage**       | `string(frame.number) matches "[13579]$"`                                                                |  

### TCP Scan  

- `nmap -sT` for TCP scan.  
- `nmap -sS` for SYN scan.  
- `nmap -sU` for UDP scan.  

**TCP Flags in a Nutshell**  

| **Flag** | **Bit Position** | **Decimal Value** | **Hex Value** |  
| -------- | ---------------- | ----------------- | ------------- |  
| **FIN**  | 0                | 1                 | 0x01          |  
| **SYN**  | 1                | 2                 | 0x02          |  
| **RST**  | 2                | 4                 | 0x04          |  
| **PSH**  | 3                | 8                 | 0x08          |  
| **ACK**  | 4                | 16                | 0x10          |  
| **URG**  | 5                | 32                | 0x20          |  
| **ECE**  | 6                | 64                | 0x40          |  
| **CWR**  | 7                | 128               | 0x80          |  

### Wireshark Filters for TCP Flags  

| **Notes**                                                                                | **Wireshark Filters**                                                          |  
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |  
| Global search.                                                                           | - `tcp`<br>- `udp`                                                             |  
| Only SYN flag. SYN flag is set; the rest of the bits are not important.                  | - `tcp.flags == 2`<br>- `tcp.flags.syn == 1`                                   |  
| Only ACK flag. ACK flag is set; the rest of the bits are not important.                  | - `tcp.flags == 16`<br>- `tcp.flags.ack == 1`                                  |  
| Only SYN and ACK flags. SYN and ACK are set; the rest of the bits are not important.     | - `tcp.flags == 18`<br>- `(tcp.flags.syn == 1) && (tcp.flags.ack == 1)`        |  
| Only RST flag. RST flag is set; the rest of the bits are not important.                  | - `tcp.flags == 4`<br>- `tcp.flags.reset == 1`                                 |  
| Only RST and ACK flags. RST and ACK are set; the rest of the bits are not important.     | - `tcp.flags == 20`<br>- `(tcp.flags.reset == 1) && (tcp.flags.ack == 1)`      |  
| Only FIN flag. FIN flag is set; the rest of the bits are not important.                  | - `tcp.flags == 1`<br>- `tcp.flags.fin == 1`                                   |  

### UDP Scan  

`icmp.type==3 and icmp.code==3` for showing closed UDP ports.  

### ARP Scan  

| **Notes**                                                                                                                                                                                                                                                    | **Wireshark Filter**                                                                                                                                                                                                                                   |  
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |  
| Global search                                                                                                                                                                                                                                      | - `arp`                                                                                                                                                                                                                                                |  
| "ARP" options for grabbing low-hanging fruits:<br>- Opcode 1: ARP requests.<br>- Opcode 2: ARP responses.<br>- **Hunt:** ARP scanning.<br>- **Hunt:** Possible ARP poisoning detection.<br>- **Hunt:** Possible ARP flooding detection. | - `arp.opcode == 1`<br>- `arp.opcode == 2`<br>- `arp.dst.hw_mac==00:00:00:00:00:00`<br>- `arp.duplicate-address-detected or arp.duplicate-address-frame`<br>- `((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address)` |  

### ARP Cases  

| **Notes**                          | **Detection Notes**                                                                                                                | **Findings**                                                |  
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------- |  
| Possible IP address match.     | 1 IP address announced from a MAC address.                                                                                     | - MAC: 00:0c:29:e2:18:b4<br>- IP: 192.168.1.25          |  
| Possible ARP spoofing attempt. | 2 MAC addresses claimed the same IP address (192.168.1.1).<br>The "192.168.1.1" IP address is a possible gateway address.      | - MAC1: 50:78:b3:f3:cd:f4<br>- MAC2: 00:0c:29:e2:18:b4 |  
| Possible ARP spoofing attempt. | The MAC address ending with "b4" claims to have a different/new IP address.                                                    | - MAC: 00:0c:29:e2:18:b4<br>- IP: 192.168.1.1           |  
| Possible ARP flooding attempt. | The MAC address ending with "b4" crafted multiple ARP requests against a range of IP addresses.                                | - MAC: 00:0c:29:e2:18:b4<br>- IP: 192.168.1.xxx         |  

### DHCP Analysis  

**DHCP Investigation in a Nutshell:**  

| **Notes**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | **Wireshark Filter**                                                                                                                                                                                                                    |  
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |  
| Global search.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | - `dhcp` or `bootp`                                                                                                                                                                                                                     |  
| Filtering DHCP packet options is vital for finding events of interest.<br>- **"DHCP Request"** packets contain hostname information.<br>- **"DHCP ACK"** packets represent accepted requests.<br>- **"DHCP NAK"** packets represent denied requests.<br>Only "Option 53" (request type) has predefined static values. Filter the packet type first, then filter other options by "applying as column" or using advanced filters like "contains" and "matches". | - Request: `dhcp.option.dhcp == 3`<br>- ACK: `dhcp.option.dhcp == 5`<br>- NAK: `dhcp.option.dhcp == 6`                                                                                                                          |  
| **"DHCP Request"** options for grabbing low-hanging fruits:<br>- **Option 12:** Hostname.<br>- **Option 50:** Requested IP address.<br>- **Option 51:** Requested IP lease time.<br>- **Option 61:** Client's MAC address.                                                                                                                                                                                                                                                                                                                                      | - `dhcp.option.hostname contains "keyword"`                                                                                                                                                                                             |  
| **"DHCP ACK"** options for grabbing low-hanging fruits:<br>- **Option 15:** Domain name.<br>- **Option 51:** Assigned IP lease time.                                                                                                                                                                                                                                                                                                                                                                                                                            | - `dhcp.option.domain_name contains "keyword"`                                                                                                                                                                                          |  
| **"DHCP NAK"** options for grabbing low-hanging fruits:<br>- **Option 56:** Message (rejection details/reason).                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Read the message instead of filtering it, as it is case-specific. Analysts can create more reliable hypotheses by understanding the event circumstances.                                                                                 |  

### NBNS Investigation  

| **Notes**                                                                                                                                                                       | **Wireshark Filter**             |  
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |  
| Global search.                                                                                                                                                                  | - `nbns`                         |  
| "NBNS" options for grabbing low-hanging fruits:<br>- **Queries:** Query details.<br>- Query details could contain **"name, Time to Live (TTL), and IP address details"**. | - `nbns.name contains "keyword"` |  

### Kerberos Investigation  

Kerberos is the default authentication service for Microsoft Windows domains. It is responsible for authenticating service requests between two or more computers over an untrusted network. The ultimate aim is to prove identity securely.  

| **Notes**                                                                                                                                                                                                                                                                                                                                                                           | **Wireshark Filter**                                                                                               |  
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |  
| Global search.                                                                                                                                                                                                                                                                                                                                                                      | - `kerberos`                                                                                                       |  
| User account search:<br>- **CNameString:** The username.<br>**Note:** Some packets may provide hostname information in this field. To avoid confusion, filter the **"$"** value. Values ending with **"$"** are hostnames; those without are usernames.                                                                                                  | - `kerberos.CNameString contains "keyword"`<br>- `kerberos.CNameString and !(kerberos.CNameString contains "$")` |  
| "Kerberos" options for grabbing low-hanging fruits:<br>- **pvno:** Protocol version.<br>- **realm:** Domain name for the generated ticket.<br>- **sname:** Service and domain name for the generated ticket.<br>- **addresses:** Client IP address and NetBIOS name.<br>**Note:** The "addresses" information is only available in request packets. | - `kerberos.pvno == 5`<br>- `kerberos.realm contains ".org"`<br>- `kerberos.SNameString == "krbtg"`       |  

### ICMP Investigation  

| **Notes**                                                                                                                                                                | **Wireshark Filters**      |  
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- |  
| Global search.                                                                                                                                                            | - `icmp`                   |  
| "ICMP" options for grabbing low-hanging fruits:<br>- Packet length.<br>- ICMP destination addresses.<br>- Encapsulated protocol signs in ICMP payload. | - `data.len > 64 and icmp` |  

### DNS Investigation  

| **Notes**                                                                                                                                                                                                                                                                                                                                                                                 | **Wireshark Filter**                                                 |  
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |  
| Global search.                                                                                                                                                                                                                                                                                                                                                                             | - `dns`                                                              |  
| "DNS" options for grabbing low-hanging fruits:<br>- Query length.<br>- Anomalous and non-regular names in DNS addresses.<br>- Long DNS addresses with encoded subdomain addresses.<br>- Known patterns like dnscat and dns2tcp.<br>- Statistical analysis like anomalous volumes of DNS requests for a particular target.<br>**!mdns:** Disable local link device queries. | - `dns contains "dnscat"`<br>- `dns.qry.name.len > 15 and !mdns` |  

### FTP Investigation  

| **Notes**                                                                                                                                                                                                                                               | **Wireshark Filter**                                                                                                                                                                          |  
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |  
| Global search.                                                                                                                                                                                                                                           | - `ftp`                                                                                                                                                                                       |  
| **"FTP"** options for grabbing low-hanging fruits:<br>- **x1x series:** Information request responses.<br>- **x2x series:** Connection messages.<br>- **x3x series:** Authentication messages.<br>**Note:** "200" means command successful. | **---**                                                                                                                                                                                       |  
| "x1x" series options for grabbing low-hanging fruits:<br>- **211:** System status.<br>- **212:** Directory status.<br>- **213:** File status.                                                                                                    | - `ftp.response.code == 211`                                                                                                                                                                  |  
| "x2x" series options for grabbing low-hanging fruits:<br>- **220:** Service ready.<br>- **227:** Entering passive mode.<br>- **228:** Long passive mode.<br>- **229:** Extended passive mode.                                                   | - `ftp.response.code == 227`                                                                                                                                                                  |  
| "x3x" series options for grabbing low-hanging fruits:<br>- **230:** User login.<br>- **231:** User logout.<br>- **331:** Valid username.<br>- **430:** Invalid username or password.<br>- **530:** No login, invalid password.                   | - `ftp.response.code == 230`                                                                                                                                                                  |  
| "FTP" commands for grabbing low-hanging fruits:<br>- **USER:** Username.<br>- **PASS:** Password.<br>- **CWD:** Current work directory.<br>- **LIST:** List.                                                                                    | - `ftp.request.command == "USER"`<br>- `ftp.request.command == "PASS"`<br>- `ftp.request.arg == "password"`                                                                           |  
| Advanced usage examples for grabbing low-hanging fruits:<br>- **Bruteforce signal:** List failed login attempts.<br>- **Bruteforce signal:** List target username.<br>- **Password spray signal:** List targets for a static password.             | - `ftp.response.code == 530`<br>- `(ftp.response.code == 530) && (ftp.response.arg contains "username")`<br>- `(ftp.request.command == "PASS") && (ftp.request.arg == "password")` |  

### HTTP Investigation  

| **Notes**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | **Wireshark Filter**                                                                                                                                                                                                   |  
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |  
| Global search.<br>**Note:** HTTP/2 is a revision of the HTTP protocol for better performance and security. It supports binary data transfer and request/response multiplexing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | - `http`<br>- `http2`                                                                                                                                                                                              |  
| "HTTP Request Methods" for grabbing low-hanging fruits:<br>- GET<br>- POST<br>- Request: Listing all requests                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | - `http.request.method == "GET"`<br>- `http.request.method == "POST"`<br>- `http.request`                                                                                                                      |  
| "HTTP Response Status Codes" for grabbing low-hanging fruits:<br>- **200 OK:** Request successful.<br>- **301 Moved Permanently:** Resource moved to a new URL/path (permanently).<br>- **302 Moved Temporarily:** Resource moved to a new URL/path (temporarily).<br>- **400 Bad Request:** Server didn't understand the request.<br>- **401 Unauthorized:** URL needs authorization (login, etc.).<br>- **403 Forbidden:** No access to the requested URL.<br>- **404 Not Found:** Server can't find the requested URL.<br>- **405 Method Not Allowed:** Used method is not suitable or blocked.<br>- **408 Request Timeout:** Request took longer than server wait time.<br>- **500 Internal Server Error:** Request not completed; unexpected error.<br>- **503 Service Unavailable:** Request not completed; server or service is down. | - `http.response.code == 200`<br>- `http.response.code == 401`<br>- `http.response.code == 403`<br>- `http.response.code == 404`<br>- `http.response.code == 405`<br>- `http.response.code == 503` |  
| "HTTP Parameters" for grabbing low-hanging fruits:<br>- **User agent:** Browser and operating system identification for a web server application.<br>- **Request URI:** Points to the requested resource from the server.<br>- **Full URI:** Complete URI information.<br>**URI:** Uniform Resource Identifier.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | - `http.user_agent contains "nmap"`<br>- `http.request.uri contains "admin"`<br>- `http.request.full_uri contains "admin"`                                                                                     |  
| "HTTP Parameters" for grabbing low-hanging fruits:<br>- **Server:** Server service name.<br>- **Host:** Hostname of the server.<br>- **Connection:** Connection status.<br>- **Line-based text data:** Cleartext data provided by the server.<br>- **HTML Form URL Encoded:** Web form information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | - `http.server contains "apache"`<br>- `http.host contains "keyword"`<br>- `http.host == "keyword"`<br>- `http.connection == "Keep-Alive"`<br>- `data-text-lines contains "keyword"`                   |  

### User Agent Analysis  

| **Notes**                                                                                                                                                                                                                                                                                                                                                                                                            | **Wireshark Filter**                                                                                                                                     |  
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |  
| Global search.                                                                                                                                                                                                                                                                                                                                                                                                       | - `http.user_agent`                                                                                                                                      |  
| Research outcomes for grabbing low-hanging fruits:<br>- Different user agent information from the same host in a short time.<br>- Non-standard and custom user agent info.<br>- Subtle spelling differences. **("Mozilla" is not the same as "Mozlilla" or "Mozlila")**<br>- Audit tools info like Nmap, Nikto, Wfuzz, and sqlmap in the user agent field.<br>- Payload data in the user agent field. | - `(http.user_agent contains "sqlmap") || (http.user_agent contains "Nmap") || (http.user_agent contains "Wfuzz") || (http.user_agent contains "Nikto")` |  

### Log4j Vulnerability Analysis  

| **Notes**                                                                                                                                                                                     | **Wireshark Filters**                                                                                                                                                                                                                                                           |  
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |  
| **Research outcomes** for grabbing low-hanging fruits:<br>- The attack starts with a "POST" request.<br>- Known cleartext patterns: "**jndi:ldap**" and "**Exploit.class**". | - `http.request.method == "POST"`<br>- `(ip contains "jndi") || (ip contains "Exploit")` (starting phase of the attack)<br>- `(frame contains "jndi") || (frame contains "Exploit")`<br>- `(http.user_agent contains "$") || (http.user_agent contains "==")` |  

### HTTPS Investigation  

| **Notes**                                                                                                                                                                                                                                                                                                                                                        | **Wireshark Filter**                                                                                                      |  
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |  
| "HTTPS Parameters" for grabbing low-hanging fruits:<br>- **Request:** Listing all requests.<br>- **TLS:** Global TLS search.<br>- TLS Client Request.<br>- TLS Server response.<br>- Local Simple Service Discovery Protocol (SSDP).<br>**Note:** SSDP is a network protocol that provides advertisement and discovery of network services. | - `http.request`<br>- `tls`<br>- `tls.handshake.type == 1`<br>- `tls.handshake.type == 2`<br>- `ssdp` |  
