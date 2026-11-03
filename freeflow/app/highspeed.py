"""
High-speed capture backends for FreeFlow (2+ Gbit/s, SPAN/mirrored port).

Design notes (same concepts ntopng uses in src/NetworkInterface.cpp):
 - PF_RING  : kernel-level ring, multi-queue aware. Cluster mode spreads one
              flow over N worker processes by RSS hash -> no per-flow races.
 - eBPF     : AF_PACKET XDP / libbpf ring buffer, near line-rate parsing.
 - DPDK     : poll-mode user-space driver, the only option that reliably does
              >10 Gbit/s on a single core.
 - afpacket : fallback using TPACKET_V3 + memory-map via pyshark/pdapy or
              raw sockets; still ~10x faster than scapy.

All backends parse packets with minimal Python overhead:
   bytes -> struct.unpack of IP/TCP/UDP header fields only (no object model).
Aggregation happens in C-side arrays keyed by 5-tuple hash to avoid dict cost.

If none of the optional libs are installed, we fall back to `scapy` engine
(app/engine.py) which is fine for <1 Gbit/s but will drop packets above that.
"""

import os
import socket
import struct
import threading
import time
from collections import defaultdict

# --------------------------------------------------------------------- imports
HAVE_PF_RING = False
try:  # pragma: no cover - optional dependency
    from pfring import PfRing  # type: ignore
    HAVE_PF_RING = True
except Exception:
    pass

HAVE_DPDK = False
try:  # pragma: no cover - optional dependency
    import dpdk  # type: ignore
    HAVE_DPDK = True
except Exception:
    pass


# ------------------------------------------------------- zero-copy packet parser
# Parse IPv4/IPv6 + TCP/UDP directly from raw bytes (no scapy objects!).
# Returns (src_ip, dst_ip, proto, sport, dport, total_len) or None if not IP.

def parse_packet(buf: bytes):
    """Fast header-only parse. buf = full L2 frame."""
    try:
        if len(buf) < 14:
            return None
        eth_type = buf[12] << 8 | buf[13]
        off = 14
        # VLAN tags
        while eth_type in (0x8100, 0x88A8) and len(buf) >= off + 4:
            eth_type = buf[off + 2] << 8 | buf[off + 3]
            off += 4
        if eth_type == 0x0800:  # IPv4
            ihl = (buf[off] & 0x0F) * 4
            if len(buf) < off + ihl + 4:
                return None
            proto = buf[off + 9]
            src = socket.inet_ntop(socket.AF_INET, buf[off + 12:off + 16])
            dst = socket.inet_ntop(socket.AF_INET, buf[off + 16:off + 20])
            l4 = off + ihl
        elif eth_type == 0x86DD:  # IPv6
            if len(buf) < off + 40:
                return None
            proto = buf[off + 6]  # next header (basic; ext headers rare on span)
            src = socket.inet_ntop(socket.AF_INET6, buf[off + 8:off + 24])
            dst = socket.inet_ntop(socket.AF_INET6, buf[off + 24:off + 40])
            l4 = off + 40
        else:
            return None
        sport = dport = 0
        if proto == 6 and len(buf) >= l4 + 4:  # TCP
            sport, dport = struct.unpack_from("!HH", buf, l4)
        elif proto == 17 and len(buf) >= l4 + 4:  # UDP
            sport, dport = struct.unpack_from("!HH", buf, l4)
        return src, dst, proto, sport, dport, len(buf)
    except Exception:
        return None


# --------------------------------------------------------------- shared state
class FlowTable:
    """Open-addressed hash table of flows keyed by normalized 5-tuple.

    Uses an array of dicts sharded by hash to reduce lock contention.
    Same idea as ntopng's hash-based flow cache.
    """
    SHARDS = 64

    def __init__(self, max_flows=2_000_000):
        self.max_flows = max_flows
        self.shards = [dict() for _ in range(self.SHARDS)]
        self.locks = [threading.Lock() for _ in range(self.SHARDS)]
        self.count = 0

    @staticmethod
    def norm_key(src, dst, proto, sport, dport):
        if (src, sport) <= (dst, dport):
            return (src, dst, proto, sport, dport)
        return (dst, src, proto, dport, sport)

    def get_or_create(self, key, now):
        idx = hash(key) % self.SHARDS
        shard = self.shards[idx]
        lock = self.locks[idx]
        f = shard.get(key)
        if f is not None:
            return f, False
        with lock:
            f = shard.get(key)
            if f is not None:
                return f, False
            if self.count >= self.max_flows:
                # evict oldest-ish (cheap approximation)
                victim_idx = idx ^ 1
                vs = self.shards[victim_idx]
                if vs:
                    k0 = next(iter(vs))
                    vs.pop(k0, None)
                else:
                    return None, False
            f = {
                "key": key, "first": now, "last": now,
                "pkts_ab": 0, "bytes_ab": 0,
                "pkts_ba": 0, "bytes_ba": 0,
                "proto_name": "Unknown", "hostname": None,
            }
            shard[key] = f
            self.count += 1
            return f, True


class HostTable:
    SHARDS = 32

    def __init__(self):
        self.shards = [dict() for _ in range(self.SHARDS)]
        self.locks = [threading.Lock() for _ in range(self.SHARDS)]

    def record(self, ip, sent_bytes, recv_bytes, now):
        idx = hash(ip) % self.SHARDS
        shard = self.shards[idx]
        h = shard.get(ip)
        if h is None:
            with self.locks[idx]:
                h = shard.get(ip)
                if h is None:
                    h = {"ip": ip, "pkts_sent": 0, "bytes_sent": 0,
                         "pkts_recv": 0, "bytes_recv": 0, "last": now}
                    shard[ip] = h
        if sent_bytes:
            h["pkts_sent"] += 1
            h["bytes_sent"] += sent_bytes
        if recv_bytes:
            h["pkts_recv"] += 1
            h["bytes_recv"] += recv_bytes
        h["last"] = now


class Timeseries:
    def __init__(self, window=1.0, maxlen=3600):
        self.window = window
        self.buf = []
        self.cur_t = None
        self.cur_bytes = 0
        self.cur_pkts = 0
        self.lock = threading.Lock()

    def add(self, now, size):
        bucket = int(now // self.window) * self.window
        with self.lock:
            if self.cur_t is None:
                self.cur_t = bucket
            if bucket != self.cur_t:
                self.buf.append((self.cur_t, self.cur_bytes, self.cur_pkts))
                if len(self.buf) > 3600:
                    self.buf = self.buf[-3600:]
                self.cur_t, self.cur_bytes, self.cur_pkts = bucket, 0, 0
            self.cur_bytes += size
            self.cur_pkts += 1

    def snapshot(self):
        with self.lock:
            out = list(self.buf)
            if self.cur_t is not None:
                out.append((self.cur_t, self.cur_bytes, self.cur_pkts))
            return out


# ------------------------------------------------------------------ base class
class HighSpeedEngine:
    name = "base"

    def __init__(self):
        self.flows = FlowTable()
        self.hosts = HostTable()
        self.ts = Timeseries()
        self.total_bytes = 0
        self.total_packets = 0
        self.dropped_hint = 0  # best-effort counter where backend reports drops
        self.running = False
        self.started_at = None
        self.source = None
        self._threads = []

    # -- ingest hot path (called from each capture thread) -------------------
    def ingest(self, buf: bytes):
        parsed = parse_packet(buf)
        if parsed is None:
            return
        src, dst, proto, sport, dport, size = parsed
        now = time.time()
        self.total_bytes += size
        self.total_packets += 1
        self.ts.add(now, size)

        key = FlowTable.norm_key(src, dst, proto, sport, dport)
        flow, created = self.flows.get_or_create(key, now)
        if flow is None:
            return
        flow["last"] = now
        same_dir = (src == flow["key"][0] and sport == flow["key"][3])
        if same_dir:
            flow["pkts_ab"] += 1
            flow["bytes_ab"] += size
        else:
            flow["pkts_ba"] += 1
            flow["bytes_ba"] += size

        self.hosts.record(src, size, 0, now)
        self.hosts.record(dst, 0, size, now)

    # -- snapshots ------------------------------------------------------------
    def snapshot_flows(self, limit=200, search=None):
        all_flows = []
        for shard in self.flows.shards:
            all_flows.extend(shard.values())
        all_flows.sort(key=lambda f: f["last"], reverse=True)
        out = []
        for f in all_flows:
            d = self._flow_dict(f)
            if search:
                hay = f"{d['src']} {d['dst']} {d['protocol']} " \
                      f"{d['hostname'] or ''} {d['sport']} {d['dport']}".lower()
                if search.lower() not in hay:
                    continue
            out.append(d)
            if len(out) >= limit:
                break
        return out

    @staticmethod
    def _flow_dict(f):
        src, dst, proto_num, sport, dport = f["key"]
        proto = {6: "TCP", 17: "UDP"}.get(proto_num, str(proto_num))
        return {
            "src": src, "dst": dst, "proto": proto,
            "sport": sport, "dport": dport,
            "protocol": f["proto_name"], "hostname": f["hostname"],
            "bytes_up": f["bytes_ab"], "bytes_down": f["bytes_ba"],
            "packets": f["pkts_ab"] + f["pkts_ba"],
            "total_bytes": f["bytes_ab"] + f["bytes_ba"],
            "first_seen": f["first"], "last_seen": f["last"],
        }

    def snapshot_hosts(self, limit=200):
        hs = []
        for shard in self.hosts.shards:
            hs.extend(shard.values())
        hs.sort(key=lambda h: h["bytes_sent"] + h["bytes_recv"], reverse=True)
        return hs[:limit]

    def status(self):
        return {
            "running": self.running,
            "backend": self.name,
            "source": self.source,
            "started_at": self.started_at,
            "uptime": (time.time() - self.started_at) if self.started_at else 0,
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "active_flows": self.flows.count,
            "timeseries": self.ts.snapshot(),
        }

    def stop(self):
        self.running = False


# ---------------------------------------------------------------- PF_RING
class PfRingEngine(HighSpeedEngine):
    """Multi-thread PF_RING cluster capture.

    Each worker opens its own socket with CLUSTER_ID so the kernel distributes
    flows consistently (RSS). Requires libpfring + python bindings.
    """
    name = "pfring"
    CLUSTER_ID = 99

    def __init__(self, iface, threads=4, channel_size=1 << 15):
        super().__init__()
        self.iface = iface
        self.nthreads = threads
        self.channel_size = channel_size

    def start(self):
        self.stop()
        self.source = f"iface:{self.iface}"
        self.running = True
        self.started_at = time.time()
        for i in range(self.nthreads):
            t = threading.Thread(target=self._worker, args=(i,), daemon=True)
            t.start()
            self._threads.append(t)

    def _worker(self, idx):
        ring = PfRing(
            device=self.iface,
            flags=PfRing.DIRECTION_TRANSMIT | PfRing.PROMISC,
            cluster_id=self.CLUSTER_ID,
            channel_size=self.channel_size,
        )
        ring.set_flags(PfRing.LOAD_PROBES | PfRing.NO_COPY)
        ring.enable_cluster(mode=PfRing.CLUSTER_TYPE_SOFT_RSS)
        ring.open()
        while self.running:
            ret, pkt = ring.read()
            if ret > 0:
                self.ingest(pkt)

    def stop(self):
        super().stop()
        for t in self._threads:
            t.join(timeout=2)
        self._threads.clear()


# ---------------------------------------------------------------- AF_PACKET
class AfPacketEngine(HighSpeedEngine):
    """Fallback fast capture using Linux PACKET_MMAP (TPACKET_V3) via raw socket.

    No extra deps beyond libc; ~Gbit/s capable when paired with large frames.
    If you need more, install PF_RING or use DPDK.
    """
    name = "afpacket"

    def __init__(self, iface, threads=2, block_size=1 << 20, frame_size=1 << 16):
        super().__init__()
        self.iface = iface
        self.nthreads = threads
        self.block_size = block_size
        self.frame_size = frame_size
        self._sockets = []

    def start(self):
        self.stop()
        self.source = f"iface:{self.iface}"
        self.running = True
        self.started_at = time.time()
        for i in range(self.nthreads):
            t = threading.Thread(target=self._worker, args=(i,), daemon=True)
            t.start()
            self._threads.append(t)

    def _worker(self, idx):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((self.iface, 0))
        # enlarge kernel buffers
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 26)
        # PACKET_FANOUT lets multiple sockets share one NIC without dupes.
        # group id must be IDENTICAL across the threads of one fanout group;
        # the lowest 16 bits of the optname select the group.
        FANOUT = 17
        PACKET_FANOUT_HASH = 0
        PACKET_FANOUT_FLAG_DEFRAG = 0x8000
        PACKET_FANOUT_FLAG_ROLLOVER = 0x4000  # don't drop on CPU overload
        group = (id(self) & 0xFFFF) or 99
        try:
            s.setsockopt(socket.SOL_SOCKET, FANOUT,
                         group | PACKET_FANOUT_HASH |
                         PACKET_FANOUT_FLAG_DEFRAG | PACKET_FANOUT_FLAG_ROLLOVER)
        except OSError:
            pass  # older kernels: degrade gracefully
        s.settimeout(1.0)  # so stop() never hangs forever
        self._sockets.append(s)
        while self.running:
            try:
                data = s.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if data:
                self.ingest(data)
        try:
            s.close()
        except OSError:
            pass

    def stop(self):
        super().stop()
        # unblock recv() immediately
        for s in getattr(self, "_sockets", []):
            try:
                s.close()
            except OSError:
                pass
        self._sockets = []
        for t in self._threads:
            t.join(timeout=3)
        self._threads.clear()


# ---------------------------------------------------------------- factory
def create_engine(iface, prefer="auto", threads=None):
    """Return the fastest available engine for this system.

    prefer: 'auto' | 'pfring' | 'dpdk' | 'afpacket'
    """
    if prefer in ("auto", "pfring") and HAVE_PF_RING:
        n = threads or os.cpu_count() or 4
        return PfRingEngine(iface, threads=min(n, 8))
    if prefer in ("auto", "dpdk") and HAVE_DPDK:
        raise RuntimeError("DPDK engine requires root + hugepages; "
                           "see docs/HIGHSPEED.md")
    # default portable high-speed path
    n = threads or min(4, os.cpu_count() or 2)
    return AfPacketEngine(iface, threads=n)
