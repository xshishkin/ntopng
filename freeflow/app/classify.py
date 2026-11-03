"""
Protocol classification inspired by ntopng's approach:
 - port-based mapping (similar to ntopng's known_tcp/udp_ports map)
 - DNS name extraction (ntopng resolves names from DNS traffic)
 - SNI extraction from TLS ClientHello (ntopng uses this for https hosts)
The heavy lifting of DPI in ntopng is done by nDPI; here we implement a
lightweight, fully-free subset.
"""

import re
from collections import namedtuple

# Well-known service ports (subset of ntopng's protocol/port table)
TCP_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 119: "NNTP",
    143: "IMAP", 161: "SNMP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP", 636: "LDAPS",
    7001: "AFS3", 8080: "HTTP Alt", 8443: "HTTPS Alt", 993: "IMAPS",
    995: "POP3S", 1194: "OpenVPN", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5060: "SIP", 5061: "SIPS", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 9050: "Tor",
    9200: "Elasticsearch", 11211: "Memcached",
}

UDP_PORTS = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 161: "SNMP",
    500: "ISAKMP", 514: "Syslog", 1194: "OpenVPN", 1900: "SSDP",
    3478: "STUN", 4500: "IPsec NAT-T", 5353: "mDNS", 5355: "LLMNR",
    137: "NetBIOS", 138: "NetBIOS",
}

QUIC_PORTS = {443, 8080}

FlowInfo = namedtuple("FlowInfo", ["protocol", "hostname"])

_SNI_RE = None  # parsed lazily below


def guess_service_by_port(proto, src_port, dst_port):
    """Port-based classification, like ntopng's getProtocolByPort()."""
    table = TCP_PORTS if proto == "TCP" else UDP_PORTS if proto == "UDP" else {}
    # server side is usually the well-known port
    for port in (dst_port, src_port):
        name = table.get(port)
        if name:
            return name
    if proto == "ICMP":
        return "ICMP"
    return "Unknown"


def hostname_from_dns_packet(raw_bytes):
    """Extract the queried domain from a DNS query (like ntopng does)."""
    try:
        # skip UDP header -> DNS payload passed in raw_bytes already
        if len(raw_bytes) < 13:
            return None
        qdcount = int.from_bytes(raw_bytes[4:6], "big")
        if qdcount == 0:
            return None
        i = 12
        labels = []
        while i < len(raw_bytes):
            length = raw_bytes[i]
            if length == 0:
                break
            if length & 0xC0 == 0xC0:  # compression pointer
                i += 2
                break
            i += 1
            labels.append(raw_bytes[i:i + length].decode("ascii", "ignore"))
            i += length
        name = ".".join(labels)
        if name and re.search(r"\.[A-Za-z]{2,}$", name):
            return name.lower()
    except Exception:
        pass
    return None


def hostname_from_tls_clienthello(payload):
    """Extract SNI from a TLS ClientHello (ntopng relies on this heavily)."""
    try:
        b = payload
        if len(b) < 45 or b[0] != 0x16:  # handshake record
            return None
        # record: type(1) version(2) len(2) -> handshake at offset 5
        hs_type = b[5]
        if hs_type != 0x01:  # ClientHello
            return None
        # handshake header: type(1) len(3) version(2) random(32)
        pos = 5 + 1 + 3 + 2 + 32
        sid_len = b[pos]; pos += 1 + sid_len
        if pos + 2 > len(b):
            return None
        cs_len = int.from_bytes(b[pos:pos + 2], "big"); pos += 2 + cs_len
        comp_len = b[pos]; pos += 1 + comp_len
        if pos + 2 > len(b):
            return None
        ext_total = int.from_bytes(b[pos:pos + 2], "big"); pos += 2
        end = min(pos + ext_total, len(b))
        while pos + 4 <= end:
            ext_type = int.from_bytes(b[pos:pos + 2], "big")
            ext_len = int.from_bytes(b[pos + 2:pos + 4], "big")
            ext_data = b[pos + 4:pos + 4 + ext_len]
            if ext_type == 0x0000:  # server_name
                if len(ext_data) >= 5:
                    name_len = int.from_bytes(ext_data[3:5], "big")
                    return ext_data[5:5 + name_len].decode("ascii", "ignore").lower()
            pos += 4 + ext_len
    except Exception:
        pass
    return None


def classify_flow(proto, sport, dport, payload_samples):
    """
    Full classification pipeline for a flow.
    payload_samples: list of bytes objects (client->server payloads).
    Returns FlowInfo.
    """
    service = guess_service_by_port(proto, sport, dport)
    hostname = None

    for sample in payload_samples:
        if not sample:
            continue
        if proto == "UDP" and (53 in (sport, dport)):
            hostname = hostname_from_dns_packet(sample) or hostname
        if proto == "TCP" and dport == 443:
            hostname = hostname_from_tls_clienthello(sample) or hostname
        if proto == "TCP" and dport == 80:
            m = re.search(rb"\r\nHost: ([^\r\n]+)", sample[:2048])
            if m:
                hostname = m.group(1).decode("ascii", "ignore").lower()
            elif sample.startswith(b"GET") or sample.startswith(b"POST"):
                service = "HTTP"

    if service == "Unknown" and hostname:
        service = "TLS" if proto == "TCP" and dport == 443 else service

    return FlowInfo(protocol=service, hostname=hostname)
