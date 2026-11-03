"""
Traffic capture engine for FreeFlow.

Design inspired by ntopng (see /workspace/src/Flow.cpp, Host.cpp):
 - a background sniffer thread ingests packets (live interface via scapy,
   or a pcap file),
 - packets are aggregated into FLOWS keyed by the classic 5-tuple
   (src, dst, proto, sport, dport) with direction normalization so that
   both directions map to one flow (like ntopng's reverse-key lookup),
 - per-host statistics are maintained (bytes/packets seen as source and
   as destination), like ntopng's Host counters,
 - a global timeseries of bytes/packets per second is kept, similar to
   ntopng's RRDTimeseriesExporter but held in memory.

Everything here is free software: no license checks anywhere.
"""

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from scapy.all import PcapReader, AsyncSniffer
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

from .classify import classify_flow


@dataclass
class Flow:
    key: tuple
    src_ip: str
    dst_ip: str
    proto: str
    sport: int
    dport: int
    first_seen: float
    last_seen: float
    packets_a2b: int = 0
    bytes_a2b: int = 0
    packets_b2a: int = 0
    bytes_b2a: int = 0
    protocol_name: str = "Unknown"
    hostname: str = None
    _samples: list = field(default_factory=list, repr=False)

    @property
    def total_bytes(self):
        return self.bytes_a2b + self.bytes_b2a

    @property
    def total_packets(self):
        return self.packets_a2b + self.packets_b2a

    def to_dict(self):
        return {
            "src": self.src_ip, "dst": self.dst_ip, "proto": self.proto,
            "sport": self.sport, "dport": self.dport,
            "protocol": self.protocol_name, "hostname": self.hostname,
            "bytes_up": self.bytes_a2b, "bytes_down": self.bytes_b2a,
            "packets": self.total_packets, "total_bytes": self.total_bytes,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
        }


@dataclass
class HostStats:
    ip: str
    pkts_sent: int = 0
    bytes_sent: int = 0
    pkts_recv: int = 0
    bytes_recv: int = 0
    local: bool = False
    protocols: dict = field(default_factory=lambda: defaultdict(int))
    last_seen: float = 0.0

    def to_dict(self):
        return {
            "ip": self.ip,
            "pkts_sent": self.pkts_sent, "bytes_sent": self.bytes_sent,
            "pkts_recv": self.pkts_recv, "bytes_recv": self.bytes_recv,
            "total_bytes": self.bytes_sent + self.bytes_recv,
            "local": self.local,
            "protocols": dict(self.protocols),
            "last_seen": self.last_seen,
        }


class TrafficEngine:
    """Background packet capture + aggregation."""

    MAX_FLOWS = 5000          # ring buffer cap (ntopng does something similar)
    SAMPLE_WINDOW = 1.0       # seconds per timeseries bucket

    def __init__(self):
        self.lock = threading.Lock()
        self.flows = {}                       # key -> Flow
        self.flow_order = deque(maxlen=self.MAX_FLOWS)
        self.hosts = {}                       # ip -> HostStats
        self.timeseries = deque(maxlen=3600)  # (t, bytes, packets)
        self.total_bytes = 0
        self.total_packets = 0
        self.started_at = None
        self.source = None          # "iface:eth0" / "file:x.pcap"
        self.running = False
        self._sniffer = None
        self._thread = None
        self._bucket_t = None
        self._bucket_bytes = 0
        self._bucket_pkts = 0

    # ------------------------------------------------------------------ start
    def start_interface(self, iface):
        self.stop()
        self._reset()
        self.source = f"iface:{iface}"
        self.running = True
        self._sniffer = AsyncSniffer(iface=iface, prn=self._handle_packet)
        self._sniffer.start()
        self.started_at = time.time()

    def start_pcap(self, path):
        self.stop()
        self._reset()
        self.source = f"file:{path}"
        self.running = True
        self.started_at = time.time()

        def _reader():
            try:
                for pkt in PcapReader(path):
                    if not self.running:
                        break
                    self._handle_packet(pkt)
            finally:
                self.running = False
                self._thread = None

        self._thread = threading.Thread(target=_reader, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    def _reset(self):
        with self.lock:
            self.flows.clear()
            self.flow_order.clear()
            self.hosts.clear()
            self.timeseries.clear()
            self.total_bytes = 0
            self.total_packets = 0

    # ----------------------------------------------------------------- ingest
    def _handle_packet(self, pkt):
        if IP not in pkt and IPv6 not in pkt:
            return
        ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
        src, dst = ip_layer.src, ip_layer.dst
        payload_len = len(ip_layer.payload)

        proto, sport, dport, payload = "IP", 0, 0, b""
        if TCP in pkt:
            proto = "TCP"; l4 = pkt[TCP]
            sport, dport = int(l4.sport), int(l4.dport)
            payload = bytes(l4.payload)
        elif UDP in pkt:
            proto = "UDP"; l4 = pkt[UDP]
            sport, dport = int(l4.sport), int(l4.dport)
            payload = bytes(l4.payload)
        elif ICMP in pkt:
            proto = "ICMP"

        now = time.time()
        size = len(pkt)

        with self.lock:
            self.total_bytes += size
            self.total_packets += 1
            self._accumulate_timeseries(now, size)

            # --- flow key normalization (both directions -> same flow) ---
            forward = (src <= dst) or (src == dst and sport <= dport)
            if forward:
                key = (src, dst, proto, sport, dport)
            else:
                key = (dst, src, proto, dport, sport)

            flow = self.flows.get(key)
            if flow is None:
                flow = Flow(key=key, src_ip=src, dst_ip=dst, proto=proto,
                            sport=sport, dport=dport,
                            first_seen=now, last_seen=now)
                if len(self.flows) >= self.MAX_FLOWS:
                    old_key = self.flow_order.popleft()
                    self.flows.pop(old_key, None)
                self.flows[key] = flow
                self.flow_order.append(key)

            flow.last_seen = now
            same_dir = (src == flow.src_ip and sport == flow.sport)
            if same_dir:
                flow.packets_a2b += 1
                flow.bytes_a2b += size
                if proto in ("TCP", "UDP") and payload and len(flow._samples) < 8:
                    flow._samples.append(payload[:2048])
            else:
                flow.packets_b2a += 1
                flow.bytes_b2a += size

            # lightweight classification (re-runs until we learn something,
            # like ntopng re-probing flows whose protocol is still Unknown)
            if proto in ("TCP", "UDP") and (
                    flow.protocol_name == "Unknown" or flow.hostname is None):
                info = classify_flow(flow.proto, flow.sport, flow.dport,
                                     flow._samples)
                if info.protocol != "Unknown":
                    flow.protocol_name = info.protocol
                if info.hostname:
                    flow.hostname = info.hostname

            # --- host stats ---
            self._host(src).pkts_sent += 1
            self._host(src).bytes_sent += size
            self._host(src).last_seen = now
            self._host(src).protocols[flow.protocol_name] += size
            self._host(dst).pkts_recv += 1
            self._host(dst).bytes_recv += size
            self._host(dst).last_seen = now

    def _host(self, ip):
        h = self.hosts.get(ip)
        if h is None:
            h = HostStats(ip=ip)
            self.hosts[ip] = h
        return h

    def _accumulate_timeseries(self, now, size):
        bucket = int(now // self.SAMPLE_WINDOW) * self.SAMPLE_WINDOW
        if self._bucket_t is None:
            self._bucket_t = bucket
        if bucket != self._bucket_t:
            self.timeseries.append((self._bucket_t, self._bucket_bytes,
                                    self._bucket_pkts))
            self._bucket_t = bucket
            self._bucket_bytes = 0
            self._bucket_pkts = 0
        self._bucket_bytes += size
        self._bucket_pkts += 1

    # ------------------------------------------------------------------- read
    def snapshot_flows(self, limit=200, search=None):
        with self.lock:
            flows = sorted(self.flows.values(),
                           key=lambda f: f.last_seen, reverse=True)
            out = []
            for f in flows:
                d = f.to_dict()
                if search:
                    hay = f"{d['src']} {d['dst']} {d['proto']} " \
                          f"{d['protocol']} {d['hostname'] or ''} " \
                          f"{d['sport']} {d['dport']}".lower()
                    if search.lower() not in hay:
                        continue
                out.append(d)
                if len(out) >= limit:
                    break
            return out

    def snapshot_hosts(self, limit=200):
        with self.lock:
            hosts = sorted(self.hosts.values(),
                           key=lambda h: h.bytes_sent + h.bytes_recv,
                           reverse=True)[:limit]
            return [h.to_dict() for h in hosts]

    def snapshot_protocols(self):
        agg = defaultdict(lambda: {"flows": 0, "bytes": 0})
        with self.lock:
            for f in self.flows.values():
                a = agg[f.protocol_name]
                a["flows"] += 1
                a["bytes"] += f.total_bytes
        return sorted(
            [{"protocol": k, **v} for k, v in agg.items()],
            key=lambda x: x["bytes"], reverse=True)

    def status(self):
        with self.lock:
            ts = list(self.timeseries)
            if self._bucket_t is not None:
                ts.append((self._bucket_t, self._bucket_bytes,
                           self._bucket_pkts))
            return {
                "running": self.running,
                "source": self.source,
                "started_at": self.started_at,
                "uptime": (time.time() - self.started_at)
                          if self.started_at else 0,
                "total_bytes": self.total_bytes,
                "total_packets": self.total_packets,
                "active_flows": len(self.flows),
                "active_hosts": len(self.hosts),
                "timeseries": ts,
            }


def list_interfaces():
    try:
        from scapy.interfaces import get_if_list
        return get_if_list()
    except Exception:
        return []
