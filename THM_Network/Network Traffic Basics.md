Network Traffic Analysis (NTA) is a process that encompasses capturing, inspecting, and analyzing data as it flows in a network. Its goal is to have complete visibility and understand what is communicated inside and outside the network. It is important to stress that NTA is not a synonym for the tool Wireshark. It is more than that: It is a combination of correlating several logs, deep packet inspection, and network flow statistics with specific outlined goals (which we will discuss later on).

Knowing how to analyze network traffic is an essential skill, not only for an aspiring SOC L1 analyst but also for many other blue and red team roles. As an L1 analyst, you need to be able to navigate through the sea of network information and understand what is normal and what deviates from the baseline.

In this room, we will focus on defining network traffic analysis, why you need it, what and how you can observe network traffic, and some of the sources and flows of network traffic you need to be aware of.

# What is the purpose of Network Traffic Analysis

**Why should we analyze network traffic? Before we answer this question, let's look ==at== the following scenario.**

## ==DNS Tunneling and Beaconing==
You are an SOC analyst, and you receive an alert stating that an unusual number of DNS queries are coming from a host named WIN-016 with IP 192.168.1.16. The DNS logs on the firewall show multiple DNS queries going to the same TLD, each time using a different subdomain.

```bash
2025-10-03 09:15:23    SRC=192.168.1.16      QUERY=aj39skdm.malicious-tld.com    QTYPE=A      
2025-10-03 09:15:31    SRC=192.168.1.16      QUERY=msd91azx.malicious-tld.com    QTYPE=A     
2025-10-03 09:15:45    SRC=192.168.1.16      QUERY=cmd01.malicious-tld.com       QTYPE=TXT     
2025-10-03 09:15:45    SRC=192.168.1.16      QUERY=cmd01.malicious-tld.com       QTYPE=TXT     
```

Based on DNS logs, we can retrieve the following information:

- Query and querytype
- Subdomain and top-level domain: We can check tools like abuseDB or VirusTotal to check if the domain is malicious
- Host IP: We can identify the system sending out the DNS queries
- Destination IP: We can use tools like [AbuseIPDB](https://www.abuseipdb.com/) or [VirusTotal](https://virustotal.com) to verify if the IP is flagged as malicious
- Timestamp: We can build a timeline mapping out the different suspicious queries

The DNS logs don't contain more information than that, so it is hard to draw a conclusion based on that information alone. We will need to inspect the DNS traffic more thoroughly and check the content of the DNS queries and replies. This will allow us to determine the nature of these queries and replies. 

This scenario is a prime example of why we need network traffic analysis. Firewalls and other devices register DNS queries and their responses but not their content. Threat actors could, for example, use TXT records to send Command and Control instructions to a compromised system. We can discover this by inspecting the content of the DNS queries. The packet capture fragnment below shows the content of a DNS reply that contains C2 commands.

```json
Domain Name System (response)
    Transaction ID: 0x4a2b
    Flags: 0x8180 Standard query response, No error
        1... .... .... .... = Response: Message is a response
        .... .... .... 0000 = RCODE: No error (0)
    Questions: 1
    Answer RRs: 1
    Authority RRs: 0
    Additional RRs: 0
    Queries
        cmd1.evilc2.com: type TXT, class IN
    Answers
        cmd1.evilc2.com: type TXT, class IN, TTL 60, TXT length: 20
            TXT: "SSBsb3ZlIHlvdXIgY3VyaW91c2l0eQ=="
```

## Why should we analyse network traffic?

Generally, we will use network traffic analysis to:

- Monitor network performance
- Check for abnormalities in the network. E.g., sudden performance peaks, slow network, etc
- Inspect the content of suspicious communication internally and externally. E.g., exfiltration via DNS, download of a malicious ZIP file over HTTP, lateral movement, etc

From a SOC perspective, network traffic analysis helps:

- Detecting suspicious or malicious activity
- Reconstructing attacks during incident response
- Verifying and validating alerts

Below are two more scenarios that illustrate the importance of network traffic analysis:

- Based on the logs for an end-user system, the system began to deviate from its normal behavior around 4 PM UTC. Analyzing the network traffic going to and from this system, we found a suspicious HTTP request and were able to extract a suspicious ZIP-file
- We received an alert that an end-user system is sending many DNS requests in comparison to baseline of the network. After inspecting the DNS requests, we discovered that data was being exfiltrated using a technique called ==**DNS tunneling**==

Now that we know **why** we need network traffic analysis, let's continue with the next task to discover **what** exactly we can monitor.

## What Netwrok Traffic Can We Observe?
The best way to showcase the traffic we can observe in the network is by using the architecture implemented in nearly every device with a network interface: the TCP/IP stack. The image below shows the different layers of the TCP/IP model. Each layer describes the required information (headers) to pass the data to the next layer. The information included in each header, together with the application data, is precisely what we want to observe. Logs often include bits and pieces of these headers, but never the full packet details. This is why we need to do network traffic analysis.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/66c44fd9733427ea1181ad58/room-content/66c44fd9733427ea1181ad58-1760351911672.png)

**Application**  
On the application layer, we can find two important information structures: the application header information and the application data itself (payload). This information will change depending on which application layer protocol is used. Let's look at an example of HTTP.

The code snippets below show the application headers of a client sending a GET request and the server's response. Most web proxies and firewalls log this header data. What they don't log is the application data or payload. From the GET request, you can determine that the client is requesting a file named `suspicious_package.zip`. The server's response includes a 200 code, which means the request was accepted. However, what you can't see in the logs is the content of the ZIP file (highlighted in yellow).  
_Request_

```json
GET /downloads/suspicious_package.zip HTTP/1.1
Host: www.tryhackrne.thn
User-Agent: curl/7.85.0
Accept: */*
Connection: close
```

_Response_

```json
HTTP/1.1 200 OK
Date: Mon, 29 Sep 2025 10:15:30 GMT
Server: nginx/1.18.0
Content-Type: application/zip
Content-Length: 10485760
Content-Disposition: attachment; filename="suspicious_package.zip"
Last-Modified: Mon, 29 Sep 2025 09:54:00 GMT
ETag: "5d8c72-9f8a1c-3a2b4c"
Accept-Ranges: bytes
Connection: close

[binary ZIP file bytes follow — 10,485,760 bytes]
```

**Transport**  
The application data and header are segmented and encapsulated at the transport layer into smaller pieces. Each piece includes a transport header, in most cases TCP or UDP. Let's have a look at the firewall log entries below:

```json
2025-10-13 09:15:32 ACCEPT TCP src=192.168.1.45 dst=172.217.22.14 sport=51432 dport=443 flags=SYN len=60
2025-10-13 09:15:32 ACCEPT TCP src=172.217.22.14 dst=192.168.1.45 sport=443 dport=51432 flags=SYN,ACK len=60
```

Firewall logs often include the source and destination ports and the flags, but all the other fields are often not included. However, they are valuable for detecting certain types of attacks, such as session hijacking. ==**Session hijacking**== can be detected by analyzing the **sequence numbers** included in the header. If the sequence numbers are suddenly far apart, further investigation is warranted. The output below shows a series of packets captured with Wireshark. 

```json
No.     Time        Source          Destination     Protocol Length  Info
1       0.000000    192.168.1.45    172.217.22.14   TCP      74      51432 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460
2       0.000120    172.217.22.14   192.168.1.45    TCP      74      80 → 51432 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460
3       0.000220    192.168.1.45    172.217.22.14   TCP      66      51432 → 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0
4       0.010500    192.168.1.45    172.217.22.14   TCP      1514    51432 → 80 [PSH, ACK] Seq=1 Ack=1 Win=64240 Len=1460
5       0.010620    172.217.22.14   192.168.1.45    TCP      66      80 → 51432 [ACK] Seq=1 Ack=1461 Win=65535 Len=0
6       0.020100    192.168.99.200  172.217.22.14   TCP      74      51432 → 80 [PSH, ACK] Seq=34567232 Ack=1 Win=64240 Len=20  
```

- The first 3 lines show a normal TCP 3-way handshake
- Lines 4 and 5 show legitimate data transfer
- Line 6 shows a packet from another source trying to inject itself into the session. Note the massive jump in the sequence number

==**Internet**
 <p>
When the transport layer sends down a segment, the internet layer also adds its header. If the segment is larger than the Maximum Transmission Unit (MTU), it will be divided into fragments, and a header will be added to each of them. The fields that are most often logged are the source and destination IP and TTL. This is sufficient for most use cases. But, if we want to, for example, detect fragmentation attacks, we will need to inspect the fragment offset and total length fields as well. There are different variations of a fragmentation attack. For example, an attacker can create tiny fragments to evade the IDS or mess up the reassembly of fragments by using overlapping byte ranges. The example below shows overlapping byte ranges. The offset in line 3 (highlighted in yellow) overlaps with the one in line 2. This means that the complete packet can be reassembled one way or another. Attackers can use this technique to bypass an IDS, for example.
</p> 

```json
No.   Time       Source        Destination   Protocol Length Info
1     0.000000   203.0.113.45  192.168.1.10  UDP      1514    Fragmented IP protocol (UDP) (id=0x1a2b) [MF] Offset=0, Len=1480
2     0.000015   203.0.113.45  192.168.1.10  UDP      1514    Fragmented IP protocol (UDP) (id=0x1a2b) [MF] Offset=1480, Len=1480
3     0.000030   203.0.113.45  192.168.1.10  UDP       600    Fragmented IP protocol (UDP) (id=0x1a2b) Offset=1480, Len=64   <-- Overlap
4     0.000045   192.168.1.10  203.0.113.45  ICMP      98     Destination unreachable (Fragment reassembly time exceeded)
```

**Link**  
Once the internet layer finishes encapsulation, the IP packet is sent to the link layer. The link layer adds its header as well, containing more addressing information. Most logs will display the source and destination MAC addresses. For certain types of attacks, for example, ARP poisoning or spoofing, the information in the logs won't be sufficient. For these types of attacks, we need the full packet and context. What you, for example, can't see in a log is when the MAC address appears from multiple interfaces or when many gratuitous ARP packets are sent out with conflicting MAC addresses. The example below shows a packet capture detailing an ARP poisoning attack. The host with IP 192.168.1.200 is replying to each ARP request with the same MAC.

```json
No.   Time       Source           Destination      Protocol Length Info
1     0.000000   192.168.1.1      Broadcast        ARP      60     Who has 192.168.1.10? Tell 192.168.1.1
2     0.000025   192.168.1.10     192.168.1.1      ARP      60     192.168.1.10 is at 00:11:22:33:44:55
3     1.002010   192.168.1.200    192.168.1.1      ARP      60     192.168.1.10 is at aa:bb:cc:dd:ee:ff  <-- Attacker spoof
4     1.002015   192.168.1.200    192.168.1.10     ARP      60     192.168.1.1 is at aa:bb:cc:dd:ee:ff  <-- Attacker spoof
5     1.100000   192.168.1.10     172.217.22.14    TCP      74     54433 → 80 [SYN] Seq=0 Win=64240 Len=0
6     1.100120   192.168.1.200    172.217.22.14    TCP      74     54433 → 80 [SYN] Seq=0 Win=64240 Len=0  <-- Relayed via attacker
```

# Network Traffic Sources & Flows
In the previous task, we discussed what we can observe theoretically based on the TCP/IP stack. Practically, it is more helpful to focus on specific sources and flows. A corporate network typically has some predetermined network flows and sources. We can group the sources into two categories:

- Intermediary
- Endpoint

The flows we can also group into two categories:

- North-South: Traffic that exits or enters the LAN and passes the firewall
- East-West: Traffic that stays within the LAN (including LAN that extends to the cloud)

Let's explore each of them below.

## Sources

As mentioned, two network traffic sources exist: endpoint and intermediary devices. These devices can be found within the LAN and WAN.

**Intermediary Sources**  
These are devices through which traffic mostly passes. While they generate some traffic, it is significantly lower than what endpoint devices generate. Under this category, we can find firewalls, switches, web proxies, IDS, IPS, routers, access points, wireless LAN controllers, and many more. Maybe less relevant for us, but all the infrastructure of Internet Service Providers is also considered part of this category.

The traffic that originates from these devices comes from services like routing protocols (EIGRP, OSPF, BGP), management protocols (SNMP, PING), logging protocols (SYSLOG), and other supporting protocols (ARP, STP, DHCP).

**Endpoint Sources**  
These are devices where traffic originates and ends. Endpoint devices take the bulk of the network bandwidth. Devices that fall under this category are servers, hosts, IoT devices, printers, virtual machines, cloud resources, mobile phones, tablets, and many more.

## Flows

A network traffic flow is typically determined by the services available in the network, such as Active Directory, SMB, HTTPS, and so on. In a typical corporate network, we can group these flows into North-South and East-West traffic.

**North-South Traffic**  
NS traffic is often monitored closely as it flows from the LAN to the WAN and vice versa. The most well-known services in this category are client-server protocols like HTTPS, DNS, SSH, VPN, SMTP, RDP, and many more. Each of these protocols has two streams: ingress (inbound) and egress (outbound). All of this traffic passes the firewall in one way or another. Configuring firewall rules and logging properly are key to visibility.

**East-West Traffic**  
EW traffic stays within the corporate LAN, so it is often monitored less. However, it is important to keep track of these flows. When the network is compromised, an attacker will often exploit different services internally to move laterally within the network. As we see below, there are many services within this category. Click on each category to see which services it contains.

**Directory, Authentication & Identity Services**

- Kerberos / LDAP: Authentication/queries to Active Directory
- RADIUS / TACACS+: Network access control
- Certificate Authority issuing internal certifications

File shares & print services

- SMB/CIFS: Accessing network drives
- IPP/LPD: Printing over the network

Router, switching, and infrastructure services

- DHCP traffic between hosts and the DHCP server
- ARP broadcast messages
- Internal DNS
- Routing protocol messages

Application Communication

- Database Connections: SQL over TCP
- Microservices APIs: REST or gRPC calls between services

Backup & Replication

- File Replication: Between data centers or to backup servers
- Database Replication: MySQL binlog replication, PostgreSQL streaming, and more

Monitoring & Management

- SNMP: Device health metrics
- Syslog: Centralized logging
- NetFlow/IPFIX: Traffic flow telemetry
- Other endpoint logs sent to a central logging server

## Flow Examples

Let's have a visual look at some of the network flows mentioned above.

<u><b>HTTPS</b> </u>
<p>
There are different variations of HTTPS network traffic flows. Let's examine a flow where the web proxy does TLS inspection:  
A host requests a website; this request is sent to the NGFW, which includes a web proxy. The web proxy will act as the web server and simultaneously establish a new TCP session with the actual web server and forward the clients' requests. When the web proxy receives the answer from the web server, it inspects its contents and then forwards it to the host if deemed safe. To summarize, we have two sessions, one between the client and the proxy and the other between the proxy and the web server. From the client's point of view, it has established a session with the web server.
</p>

![HTTPS Network Flow](https://tryhackme-images.s3.amazonaws.com/user-uploads/66c44fd9733427ea1181ad58/room-content/66c44fd9733427ea1181ad58-1760459431334.svg)

**External DNS**  
DNS traffic within a corporate network starts when a host sends a DNS query. The host sends the query to the internal DNS server on port 53, which will then act on behalf of the host. First, it will check if it has an answer to the query in its cache; if not, it will send the query via the router, through the firewall, to the configured DNS servers. The answer will then follow the same path to the internal DNS server, which will then forward it to the host. The network diagram below shows a simplified flow.

![DNS Network Flow](https://tryhackme-images.s3.amazonaws.com/user-uploads/66c44fd9733427ea1181ad58/room-content/66c44fd9733427ea1181ad58-1760460288845.svg)

**SMB with Kerberos**  
When a host opens a share to, for example, \\FILESERVER\MARKETING, an SMB session is set up. First, authentication is done via Kerberos. When a user logged in on the host, it **authenticated** with the Key Distribution Center on the Domain Controller and received a Ticket Granting Ticket to request **"service authentication tickets"**. Now, the host requests a service ticket using the Ticket Granting Ticket it received earlier. The host then uses this ticket to establish the SMB connection. Once the SMB session is set up, the host can access the share. Below we see a simplified network diagram of the flow.

![HTTPS Flow](https://tryhackme-images.s3.amazonaws.com/user-uploads/66c44fd9733427ea1181ad58/room-content/66c44fd9733427ea1181ad58-1760459778270.svg)

