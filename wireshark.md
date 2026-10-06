# Wireshark and tshark

Display filters go in the filter bar. Capture filters (BPF syntax) are set before the capture starts. They are two different languages, do not mix them.

## Operators

```
==  !=  >  <  >=  <=
&&  ||  !
contains          substring match, case sensitive
matches           regex, add (?i) to ignore case
in {80 443}       value is in a set
```

To exclude a host use `!(ip.addr == 10.0.0.5)`. The form `ip.addr != 10.0.0.5` gives odd results on older versions.

## Hosts and ports

| Filter | Shows |
|---|---|
| `ip.addr == 10.0.0.5` | traffic to or from the host |
| `ip.src == 10.0.0.5` | host as source only |
| `ip.addr == 10.0.0.0/24` | a whole subnet |
| `tcp.port == 443` | either side uses port 443 |
| `tcp.dstport == 22` | destination port only |
| `udp.port == 53` | DNS over UDP |
| `tcp.port in {80 443 8080}` | any of the ports |
| `eth.addr == aa:bb:cc:dd:ee:ff` | one MAC address |

Protocol names also work as filters: `http`, `dns`, `tls`, `ssh`, `smb2`, `ftp`, `smtp`, `icmp`, `arp`, `dhcp`, `kerberos`.

## TCP

| Filter | Shows |
|---|---|
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN only, new connection attempts. One source hitting many ports looks like a port scan |
| `tcp.flags.reset == 1` | resets. Lots of them can mean probing of closed ports |
| `tcp.analysis.flags` | everything Wireshark marks as unusual |
| `tcp.analysis.retransmission` | retransmissions only |
| `tcp.stream eq 5` | one conversation (the stream number is in packet details) |
| `tcp.len > 0` | packets that carry data |

## HTTP

| Filter | Shows |
|---|---|
| `http.request` | all requests |
| `http.request.method == "POST"` | form submits, logins, uploads |
| `http.response.code >= 400` | client and server errors |
| `http.host contains "example"` | requests to a host |
| `http.user_agent contains "curl"` | scripts and tools often have a plain user agent |
| `http.request.uri contains "admin"` | admin paths |
| `frame contains "password"` | raw text search in any packet |

For a case insensitive search: `frame matches "(?i)passw"`.
To save files from a capture: File > Export Objects > HTTP.

## DNS

| Filter | Shows |
|---|---|
| `dns.flags.response == 0` | queries only |
| `dns.qry.name contains "example"` | lookups for a name |
| `dns.flags.rcode == 3` | NXDOMAIN. Many from one host can mean DGA malware or just typos |
| `dns.qry.type == 16` | TXT queries |
| `dns.qry.name.len > 50` | very long names, check for DNS tunnelling |

## TLS

| Filter | Shows |
|---|---|
| `tls.handshake.type == 1` | Client Hello |
| `tls.handshake.extensions_server_name contains "example"` | SNI, the site name, even when the traffic is encrypted |
| `tls.handshake.type == 11` | server certificates |

## Other

| Filter | Shows |
|---|---|
| `icmp.type == 8` | echo requests. Many to many hosts is a ping sweep |
| `icmp.type == 0` | echo replies, so which hosts are alive |
| `arp.duplicate-address-detected` | one IP claimed by two MACs, possible ARP spoofing |
| `ftp.request.command == "PASS"` | FTP passwords in clear text |

## Menus worth opening first

- Statistics > Protocol Hierarchy: what is in the capture at all
- Statistics > Conversations: top talkers, sort by bytes
- Statistics > Endpoints: every host in the file
- Follow TCP Stream: right click a packet, or Ctrl+Alt+Shift+T
- File > Export Objects: pull files out of HTTP or SMB
- View > Time Display Format: switch to UTC when you compare with logs

## Capture filters (BPF)

```
host 10.0.0.5
net 10.0.0.0/24
port 53
tcp port 22
src host 10.0.0.5 and dst port 80
not arp
```

## tshark

```
# who requested what over HTTP
tshark -r file.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri

# conversations and protocol hierarchy
tshark -r file.pcap -q -z conv,tcp
tshark -r file.pcap -q -z io,phs

# most requested DNS names
tshark -r file.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head

# capture only DNS to a file
tshark -i eth0 -f "port 53" -w dns.pcap
```

## Order I would follow on an unknown pcap

1. Protocol Hierarchy, to see what protocols are there
2. Conversations, to find the top talkers
3. DNS names
4. HTTP requests and TLS SNI
5. Export Objects
6. Follow stream on the suspicious hosts
