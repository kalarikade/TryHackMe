# Network Traffic Analysis

---

`Network Traffic Analysis (NTA)` can be described as the act of examining network traffic to characterize common ports and protocols utilized, establish a baseline for our environment, monitor and respond to threats, and ensure the greatest possible insight into our organization's network.

This process helps security specialists determine anomalies, including security threats in the network, early and effectively pinpoint threats. Network Traffic Analysis can also facilitate the process of meeting security guidelines. Attackers update their tactics frequently to avoid detection and leverage legitimate credentials with tools that most companies allow in their networks, making detection and, subsequently, response challenging for defenders. In such cases, Network Traffic Analysis can again prove helpful. Everyday use cases of NTA include:

||
|---|
|`Collecting` real-time traffic within the network to analyze upcoming threats.|
|`Setting` a baseline for day-to-day network communications.|
|`Identifying` and analyzing traffic from non-standard ports, suspicious hosts, and issues with networking protocols such as HTTP errors, problems with TCP, or other networking misconfigurations.|
|`Detecting` malware on the wire, such as ransomware, exploits, and non-standard interactions.|
|NTA is also useful when investigating past incidents and during threat hunting.|

Try to picture a threat actor targeting and infiltrating our network. If they wish to breach the network, attackers must inevitably interact and communicate with our infrastructure. Network communication takes place over many different ports and protocols, all being utilized concurrently by employees, equipment, and customers. To spot malicious traffic, we would need to use our knowledge of typical network traffic within our enclave. Doing so will narrow down our search and help us quickly find and disrupt adversarial communication.

For example, if we detect many `SYN` packets on ports that we never (or rarely) utilize in our network, we can conclude that this is most likely someone trying to determine what ports are open on our hosts. Actions like this are typical markers of a `portscan`. Performing such an analysis and coming to such conclusions requires specific skills and knowledge.

---

## Required Skills and Knowledge

The skills we are about to list and describe require theoretical and practical knowledge acquired over time. We do not have to know everything by heart, but we should know what to look for when certain aspects of the content seem unfamiliar. This applies not only to NTA but also to most other topics we will deal with in cybersecurity.

#### TCP/IP Stack & OSI Model

This understanding will ensure we grasp how networking traffic and the host applications interact.

#### Basic Network Concepts

Understanding what types of traffic we will see at each level includes an understanding of the individual layers that make up the TCP/IP and OSI model and the concepts of switching and routing. If we tap a network on a backbone link, we will see much more traffic than usual, and it will be vastly different from what we find tapping an office switch.

#### Common Ports and Protocols

Identifying standard ports and protocols quickly and having a functional understanding of how they communicate will ensure we can identify potentially malicious or malformed network traffic.

#### Concepts of IP Packets and the Sublayers

Foundational knowledge of how TCP and UDP communicate will, at a minimum, ensure we understand what we see or are searching for. TCP, for example, is stream-oriented and allows us to follow a conversation between hosts easily. UDP is quick but not concerned with completeness, so it would be harder to recreate something from this packet type.

#### Protocol Transport Encapsulation

Each layer will encapsulate the previous. Being able to read or dissect when this encapsulation changes will help us move through data quicker. It is easy to see hints based on encapsulation headers.

---

## Environment and Equipment

The list below contains many different tools and equipment types that can be utilized to perform network traffic analysis. Each will provide a different way to capture or dissect the traffic. Some offer ways to copy and capture, while others read and ingest. This module will explore just a few of these ([Wireshark](https://www.wireshark.org/) and [tcpdump](https://www.tcpdump.org/) mostly). Keep in mind these tools are not strictly geared for admins. Many of these can be used for malicious reasons as well.

#### Common Traffic Analysis Tools

|**Tool**|**Description**|
|---|---|
|`tcpdump`|[tcpdump](https://www.tcpdump.org/) is a command-line utility that, with the aid of LibPcap, captures and interprets network traffic from a network interface or capture file.|
|`Tshark`|[TShark](https://www.wireshark.org/docs/man-pages/tshark.html) is a network packet analyzer much like TCPDump. It will capture packets from a live network or read and decode from a file. It is the command-line variant of Wireshark.|
|`Wireshark`|[Wireshark](https://www.wireshark.org/) is a graphical network traffic analyzer. It captures and decodes frames off the wire and allows for an in-depth look into the environment. It can run many different dissectors against the traffic to characterize the protocols and applications and provide insight into what is happening.|
|`NGrep`|[NGrep](https://github.com/jpr5/ngrep) is a pattern-matching tool built to serve a similar function as grep for Linux distributions. The big difference is that it works with network traffic packets. NGrep understands how to read live traffic or traffic from a PCAP file and utilize regex expressions and BPF syntax. This tool shines best when used to debug traffic from protocols like HTTP and FTP.|
|`tcpick`|[tcpick](http://tcpick.sourceforge.net/index.php?p=home.inc) is a command-line packet sniffer that specializes in tracking and reassembling TCP streams. The functionality to read a stream and reassemble it back to a file with tcpick is excellent.|
|`Network Taps`|Taps ([Gigamon](https://www.gigamon.com/), [Niagra-taps](https://www.niagaranetworks.com/products/network-tap)) are devices capable of taking copies of network traffic and sending them to another place for analysis. These can be in-line or out of band. They can actively capture and analyze the traffic directly or passively by putting the original packet back on the wire as if nothing had changed.|
|`Networking Span Ports`|[Span Ports](https://en.wikipedia.org/wiki/Port_mirroring) are a way to copy frames from layer two or three networking devices during egress or ingress processing and send them to a collection point. Often a port is mirrored to send those copies to a log server.|
|`Elastic Stack`|The [Elastic Stack](https://www.elastic.co/elastic-stack) is a culmination of tools that can take data from many sources, ingest the data, and visualize it, to enable searching and analysis of it.|
|`SIEMS`|`SIEMS` (such as [Splunk](https://www.splunk.com/en_us)) are a central point in which data is analyzed and visualized. Alerting, forensic analysis, and day-to-day checks against the traffic are all use cases for a SIEM.|
|and others.||

---

## BPF Syntax

Many of the tools mentioned above have their syntax and commands to utilize, but one that is shared among them is [Berkeley Packet Filter (BPF)](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter) syntax. This syntax is the primary method we will use. In essence, BPF is a technology that enables a raw interface to read and write from the Data-Link layer. With all this in mind, we care for BPF because of the filtering and decoding abilities it provides us. We will be utilizing BPF syntax through the module, so a basic understanding of how a BPF filter is set up can be helpful. For more information on BPF syntax, check out this [reference](https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters).

---

## Performing Network Traffic Analysis

Performing analysis can be as simple as watching live traffic roll by in our console or as complex as capturing data with a tap, sending it back to a SIEM for ingestion, and analyzing the pcap data for signatures and alerts related to common tactics and techniques.

At a minimum, to listen passively, we need to be connected to the network segment we wish to listen on. This is especially true in a switched environment where VLANS and switch ports will not forward traffic outside their broadcast domain. With that in mind, if we wish to capture traffic from a specific VLAN, our capture device should be connected to that same network. Devices like network taps, switch or router configurations like span ports, and port mirroring can allow us to get a copy of all traffic traversing a specific link, regardless of what network segment or destination it belongs to.

#### NTA Workflow

Traffic analysis is not an exact science. NTA can be a very dynamic process and is not a direct loop. It is greatly influenced by what we are looking for (network errors vs. malicious actions) and where we have visibility into our network. Performing traffic analysis can distill down to a few basic tenants.

#### NTA Workflow

![Cycle diagram showing four steps: 1. Ingest Traffic, 2. Reduce Noise by Filtering, 3. Analyze and Explore, 4. Detect and Alert.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/workflow.png)

#### 1. Ingest Traffic

Once we have decided on our placement, begin capturing traffic. Utilize capture filters if we already have an idea of what we are looking for.

#### 2. Reduce Noise by Filtering

Capturing traffic of a link, especially one in a production environment, can be extremely noisy. Once we complete the initial capture, an attempt to filter out unnecessary traffic from our view can make analysis easier. (Broadcast and Multicast traffic, for example.)

#### 3. Analyze and Explore

Now is the time to start carving out data pertinent to the issue we are chasing down. Look at specific hosts, protocols, even things as specific as flags set in the TCP header. The following questions will help us:

1. Is the traffic encrypted or plain text? Should it be?
    
2. Can we see users attempting to access resources to which they should not have access?
    
3. Are different hosts talking to each other that typically do not?
    

#### 4. Detect and Alert

1. Are we seeing any errors? Is a device not responding that should be?
    
2. Use our analysis to decide if what we see is benign or potentially malicious.
    
3. Other tools like IDS and IPS can come in handy at this point. They can run heuristics and signatures against the traffic to determine if anything within is potentially malicious.
    

#### 5. Fix and Monitor

Fix and monitor is not a part of the loop but should be included in any workflow we perform. If we make a change or fix an issue, we should continue to monitor the source for a time to determine if the issue has been resolved.

# Networking Primer - Layers 1-4

---

This section serves as a quick refresher on networking and how some standard protocols we can see while performing traffic captures work. These concepts are at the core of capturing and dissecting traffic. Without a fundamental understanding of typical network flow and what ports and protocols are used, we cannot accurately analyze any traffic we capture. If this is the first time you encounter some of these terms or concepts, we suggest completing the [Introduction to Networking](https://academy.hackthebox.com/course/preview/introduction-to-networking) Module first.

---

## OSI / TCP-IP Models

#### Networking Models

![Comparison of OSI and TCP/IP models: OSI has 7 layers including Application, Presentation, Session, Transport, Network, Data-Link, and Physical. TCP/IP has 4 layers: Application, Transport, Internet, and Link.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/net_models4.png)

The image above gives a great view of the Open Systems Interconnect (`OSI`) model and the Transmission Control Protocol - Internet Protocol (`TCP-IP`) model side by side. The models are a graphical representation of how communication is handled between networked computers. Let's take a second to compare the two:

#### Model Traits Comparison.

|Trait|OSI|TCP-IP|
|---|---|---|
|Layers|Seven|Four|
|Flexibility|Strict|Loose|
|Dependency|Protocol independent & generic|Based on common communication protocols|

When examining these two models, we can notice that the OSI model is segmented more than the TCP-IP model. This is because it is broken down into small functional chunks. Layers one through four of the OSI model are focused on controlling the transportation of data between hosts. This control includes everything from the physical medium used for transmission to the protocol utilized to manage the conversation or lack thereof when transporting data. Layers five through seven handle the interpretation, management, and presentation of the encapsulated data presented to the end-user. Think of the OSI model as the theory behind how everything works, whereas the TCP-IP model is more closely aligned with the actual functionality of networking. The TCP-IP model is a bit more blended, and the rules are flexible. The TCP-IP model comprises four layers where layers five, six, and seven of the OSI model align with layer four of the TCP-IP model. Layer three deals with transportation, layer two is the internet layer which aligns with the network layer in OSI, and layer one is the link-layer which covers layers two and one of the OSI model.

Throughout this module, we will examine many different Protocol Data Units (`PDU`), so a functional understanding of how it appears in theory and on the wire is required. A PDU is a data packet made up of control information and data encapsulated from each layer of the OSI model. The breakout below will show how the layers in the two models match up to a PDU.

#### PDU Example

![Comparison of OSI and TCP/IP models: OSI has 7 layers including Application, Presentation, Session, Transport, Network, Data-Link, and Physical. TCP/IP has 4 layers: Application, Transport, Internet, and Link. PDU types are Data, Segment/Datagram, Packet, Frame, and Bit.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/net_models_pdu2.png)

When inspecting a PDU, we need to keep the idea of encapsulation in mind. As our data moves down the protocol stack, each layer will wrap the previous layers' data in a new bubble we call encapsulation. This bubble adds the necessary information of that layer into the header of the PDU. This information can vary by level, but it includes what is held by the previous layer, operational flags, any options required to negotiate communications, the source and destination IP addresses, ports, transport, and application layer protocols.

#### PDU Packet Breakdown

![Diagram showing PDU types: Data, Segment/Datagram, Packet, Frame, Bit. Network packet details include Ethernet II, IPv4, and UDP headers with source and destination addresses.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/pdu-wireshark.png)

The image above shows us the makeup of a PDU side by side with a packet breakout from Wireshark's Packet Details pane. Please take note that when we see the breakout in Wireshark, it is in reverse order. Wireshark shows us the PDU in reverse because it is in the order that it was unencapsulated.

---

## Addressing Mechanisms

Now that we have gone over the basic concepts driving networking behavior let us take some time to discuss the addressing mechanisms that enable the delivery of our packets to the correct hosts. We will begin with Media Access Control addresses first.

#### MAC-Addressing

Each logical or physical interface attached to a host has a Media Access Control (`MAC`) address. This address is a 48-bit `six octet` address represented in hexadecimal format. If we look at the image below, we can see an example of one by the `red` arrow.

#### Mac-Address

![Network interface configuration for en0: flags, MAC address, IPv6 and IPv4 addresses, netmask, and status details.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/Addressing.png)

MAC-addressing is utilized in Layer two ( `the data-link or link-layer depending on which model you look at` ) communications between hosts. This works through host-to-host communication within a broadcast domain. If layer two traffic needs to cross a layer three interface, that PDU is sent to the layer three egress interface, and it is routed to the correct network. At layer two, this looks as though the PDU is addressed to the router interface, and the router will take the layer three address into account when determining where to send it next. Once it makes a choice, it strips the encapsulation at layer two and replaces it with new information that indicates the next physical address in the route.

---

## IP Addressing

The Internet Protocol (`IP`) was developed to deliver data from one host to another across network boundaries. IP is responsible for routing packets, the encapsulation of data, and fragmentation and reassembly of datagrams when they reach the destination host. By nature, IP is a connectionless protocol that provides no assurances that data will reach its intended recipient. For the reliability and validation of data delivery, IP relies on upper-layer protocols such as TCP. Currently, there exist two main versions of IP. IPv4, which is the current dominant standard, and IPv6, which is intended to be the successor of IPv4.

#### IPv4

The most common addressing mechanism most are familiar with is the Internet Protocol address version 4 (`IPv4`). IPv4 addressing is the core method of routing packets across networks to hosts located outside our immediate vicinity. The image below shows us an example of an IPv4 address by the `green` arrow.

#### IP Address

![Network interface configuration for en0: flags, MAC address, IPv6 and IPv4 addresses, netmask, and status details.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/Addressing.png)

An IPv4 address is made up of a 32-bit `four octet` number represented in decimal format. In our example, we can see the address `192.168.86.243`. Each octet of an IP address can be represented by a number ranging from `0` to `255`. When examining a PDU, we will find IP addresses in layer three (`Network`) of the OSI model and layer two (`internet`) of the TCP-IP model. We will not deep dive into IPv4 here, but for the sake of this module, understand what these addresses are, what they do for us, and at which layer they are used.

#### IPv6

After a little over a decade of utilizing IPv4, it was determined that we had quickly exhausted the pool of usable IP addresses. With such large chunks sectioned off for special use or private addressing, the world had quickly used up the available space. To help solve this issue, two things were done. The first was implementing variable-length subnet masks (`VLSM`) and Classless Inter-Domain Routing (`CIDR`). This allowed us to redefine the useable IP addresses in the v4 format changing how addresses were assigned to users. The second was the creation and continued development of `IPv6` as a successor to IPv4.

IPv6 provides us a much larger address space that can be utilized for any networked purpose. IPv6 is a 128-bit address `16 octets` represented in Hexadecimal format. We can see an example of a shortened IPv6 address in the image below by the blue arrow.

#### IPv6 Address

![Network interface configuration for en0: flags, MAC address, IPv6 and IPv4 addresses, netmask, and status details.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/Addressing.png)

Along with a much larger address space, IPv6 provides: Better support for Multicasting (sending traffic from one to many) Global addressing per device Security within the protocol in the form of IPSec Simplified Packet headers allow for easier processing and move from connection to connection without being re-assigned an address.

IPv6 uses four main types of addresses within its schema:

#### IPv6 Addressing Types

|**Type**|**Description**|
|---|---|
|`Unicast`|Addresses for a single interface.|
|`Anycast`|Addresses for multiple interfaces, where only one of them receives the packet.|
|`Multicast`|Addresses for multiple interfaces, where all of them receive the same packet.|
|`Broadcast`|Does not exist and is realized with multicast addresses.|

When thinking about each address type, it is helpful to remember that Unicast traffic is host to host, while Multicast is one to many, and Anycast is one to many in a group where only one will answer the packet. (think load balancing).

Even with its current state providing many advantages over IPv4, the adoption of IPv6 has been slow to catch on.

#### Adoption of IPv6

![World map showing IPv6 adoption: Darker green indicates higher deployment and fewer connectivity issues; lighter green indicates less deployment.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/ipv6-adoption.png)

At the time of writing, according to statistics published by Google, the adoption rate is only around 40 percent globally.

---

## TCP / UDP, Transport Mechanisms

The Transport Layer has several mechanisms to help ensure the seamless delivery of data from source to destination. Think about the Transport layer as a control hub. Application data from the higher layers have to traverse down the stack to the Transport layer. This layer directs how the traffic will be encapsulated and thrown to the lower layer protocols ( IP and MAC ). Once the data reaches its intended recipient, the Transport layer, working with the Network / Internet layer protocols, is responsible for reassembling the encapsulated data back in the correct order. The two mechanisms used to accomplish this task are the Transmission Control (`TCP`) and the User Datagram Protocol (`UDP`).

#### TCP vs. UDP

Let us take a second to examine these two protocols side by side.

#### TCP VS. UDP

|**Characteristic**|**TCP**|**UDP**|
|---|---|---|
|`Transmission`|Connection-oriented|Connectionless. Fire and forget.|
|`Connection Establishment`|TCP uses a three-way handshake to ensure that a connection is established.|UDP does not ensure the destination is listening.|
|`Data Delivery`|Stream-based conversations|packet by packet, the source does not care if the destination is active|
|`Receipt of data`|Sequence and Acknowledgement numbers are utilized to account for data.|UDP does not care.|
|`Speed`|TCP has more overhead and is slower because of its built-in functions.|UDP is fast but unreliable.|

By looking at the table above, we can see that TCP and UDP provide two very different data transmission methods. TCP is considered a more reliable protocol since it allows for error checking and data acknowledgment as a normal function. In contrast, UDP is a quick, fire, and forget protocol best utilized when we care about speed over quality and validation.

To put this into perspective, TCP is utilized when moving data that requires completeness over speed. For example, when we use Secure Shell (`SSH`) to connect from one host to another, a connection is opened that stays active while you issue commands and perform actions. This is a function of TCP, ensuring our conversation with the distant host is not interrupted. If it does get interrupted for some reason, TCP will not reassemble a partial fragment of a packet and send it to the application. We can avoid errors this way. What would happen if we issued a command like `sudo passwd user` to change the user's password on a remote host, and during the change, part of the message drops. If this were over UDP, we would have no way of knowing what happened to the rest of that message and potentially mess up the user's password or worse. TCP helps prevent this by acknowledging each packet received to ensure the destination host has acquired each packet before assembling the command and sending it to the application for action.

On the other hand, when we require quick responses or utilize applications that require speed over completeness, UDP is our answer. Take streaming a video, for example. The user will not notice a pixel or two dropped from a streaming video. We care more about watching the video without it constantly stopping to buffer the next piece. Another example of this would be DNS. When a host requests a record entry for inlanefreight.com, the host is looking for a quick response to continue the process it was performing. The worst thing that happens if a DNS request is dropped is that it is reissued. No harm, no foul. The user will not receive corrupted data because of this drop.

UDP traffic appears like regular traffic; it is a single packet, with no response or acknowledgment that it was sent or received, so there is not much to show here. However, we can take a look at TCP and how it establishes connections.

---

## TCP Three-way Handshake

One of the ways TCP ensures the delivery of data from server to client is the utilization of sessions. These sessions are established through what is called a three-way handshake. To make this happen, TCP utilizes an option in the TCP header called flags. We will not deep dive into TCP flags now; know that the common flags we will see in a three-way handshake are Synchronization (`SYN`) and acknowledgment (`ACK`). When a host requests to have a conversation with a server over TCP;

1. The `client` sends a packet with the SYN flag set to on along with other negotiable options in the TCP header.
    
    1. This is a synchronization packet. It will only be set in the first packet from host and server and enables establishing a session by allowing both ends to agree on a sequence number to start communicating with.
    2. This is crucial for the tracking of packets. Along with the sequence number sync, many other options are negotiated in this phase to include window size, maximum segment size, and selective acknowledgments.
2. The `server` will respond with a TCP packet that includes a SYN flag set for the sequence number negotiation and an ACK flag set to acknowledge the previous SYN packet sent by the host.
    
    1. The server will also include any changes to the TCP options it requires set in the options fields of the TCP header.
3. The `client` will respond with a TCP packet with an ACK flag set agreeing to the negotiation.
    
    1. This packet is the end of the three-way handshake and established the connection between client and server.

Let us take a quick look at this in action to be familiar with it when it appears in our packet output later on in the module.

#### TCP Three-way Handshake

![Network packet capture showing TCP connections between IPs 192.168.1.140 and 174.143.213.184, with protocols TCP and HTTP, displaying sequence and acknowledgment numbers.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/three-way-handshake.png)

When examining this output, we can see the start of our handshake on line one. Looking at the information highlighted in the `red box`, we can see our initial Syn flag is set. If we look at the port numbers underlined in `green`, we can see two numbers, `57678` and `80`. The first number is the random high port number in use by the client, and the second is the well-known port for HTTP used by the server to listen for incoming web request connections. In line 2, we can see the server's response to the client with an `SYN / ACK` packet sent to the same ports. On line 3, we can see the client acknowledge the server's synchronization packet to establish the connection.

Packet 4 shows us that the HTTP request was sent, and a session is established to stream the data for the image requested. We can see as the stream continues that TCP sends acknowledgments for each chunk of data sent. This is an example of typical TCP communication.

We have seen how a session is established with TCP; now, let us examine how a session is concluded.

#### TCP Session Teardown

![Network packet capture showing TCP connections between IPs 192.168.1.140 and 174.143.213.184, with protocols TCP and HTTP, displaying sequence and acknowledgment numbers, including SYN, ACK, and FIN flags.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/81/session-teardown.png)

In the image above, a set of packets similar to our three-way handshake visible at the end of the output. This is how TCP gracefully shuts connections. Another flag we will see with TCP is the `FIN` flag. It is used for signaling that the data transfer is finished and the sender is requesting termination of the connection. The client acknowledges the receipt of the data and then sends a `FIN` and `ACK` to begin session termination. The server responds with an acknowledgment of the FIN and sends back its own FIN. Finally, the client acknowledges the session is complete and closes the connection. Before session termination, we should see a packet pattern of:

1. `FIN, ACK`
2. `FIN, ACK`,
3. `ACK`

If we look at the image above detailing a session, we will see that this is the case. An output similar to this is considered an adequately terminated connection.