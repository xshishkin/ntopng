"""
FreeFlow - fully free network traffic monitor (FastAPI app).

Inspired by ntopng's REST API layout (/api/v1/* endpoints), but 100% free:
no license, no Pro/Enterprise tiers, all functions available.
"""

import os
import tempfile

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .engine import TrafficEngine, list_interfaces
from .highspeed import create_engine, HAVE_PF_RING, HAVE_DPDK

app = FastAPI(title="FreeFlow", version="1.0.0")
engine = TrafficEngine()  # default: scapy (fine < 1 Gbit/s)
hs_engine = None         # active high-speed engine when started


def _active():
    return hs_engine if hs_engine is not None else engine

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")


class StartIface(BaseModel):
    iface: str
    backend: str = "auto"   # auto | scapy | afpacket | pfring | dpdk
    threads: int = None     # worker threads for high-speed backends


class StartPcap(BaseModel):
    path: str


# ------------------------------------------------------------------ API v1
@app.get("/api/v1/status")
def api_status():
    return _active().status()


@app.get("/api/v1/backends")
def api_backends():
    """Which capture backends are available on this host."""
    return {
        "scapy": True,
        "afpacket": True,          # built into Linux
        "pfring": HAVE_PF_RING,
        "dpdk": HAVE_DPDK,
    }


@app.get("/api/v1/interfaces")
def api_interfaces():
    return {"interfaces": list_interfaces()}


@app.post("/api/v1/start/interface")
def api_start_interface(body: StartIface):
    global hs_engine
    ifaces = list_interfaces()
    if body.iface not in ifaces:
        raise HTTPException(400, f"Unknown interface '{body.iface}'. "
                                 f"Available: {', '.join(ifaces) or 'none'}")
    # stop whatever is running now
    engine.stop()
    if hs_engine is not None:
        hs_engine.stop()
        hs_engine = None

    try:
        if body.backend == "scapy":
            engine.start_interface(body.iface)
        else:
            hs_engine = create_engine(body.iface, prefer=body.backend,
                                      threads=body.threads)
            hs_engine.start()
    except PermissionError:
        raise HTTPException(403, "Capture requires root/CAP_NET_RAW")
    except Exception as e:
        raise HTTPException(500, f"Failed to start capture: {e}")
    return _active().status()


@app.post("/api/v1/start/pcap")
def api_start_pcap(body: StartPcap):
    global hs_engine
    if not os.path.isfile(body.path):
        raise HTTPException(404, f"File not found: {body.path}")
    engine.stop()
    if hs_engine is not None:
        hs_engine.stop()
        hs_engine = None
    engine.start_pcap(body.path)
    return engine.status()


@app.post("/api/v1/stop")
def api_stop():
    global hs_engine
    engine.stop()
    if hs_engine is not None:
        hs_engine.stop()
        hs_engine = None
    return engine.status()


@app.get("/api/v1/stats/flows")
def api_flows(limit: int = Query(200, le=2000), search: str = None):
    return {"flows": _active().snapshot_flows(limit=limit, search=search)}


@app.get("/api/v1/stats/hosts")
def api_hosts(limit: int = Query(200, le=2000)) -> dict:
    hosts = _active().snapshot_hosts(limit=limit)
    # normalize scapy HostStats objects vs highspeed dicts
    out = []
    for h in hosts:
        out.append(h.to_dict() if hasattr(h, "to_dict") else h)
    return {"hosts": out}


@app.get("/api/v1/stats/protocols")
def api_protocols():
    active = _active()
    if hasattr(active, "snapshot_protocols"):
        return {"protocols": active.snapshot_protocols()}
    # high-speed engine: aggregate proto_name from flows
    agg = {}
    for f in active.snapshot_flows(limit=100000):
        name = f["protocol"] or "Unknown"
        a = agg.setdefault(name, {"protocol": name, "flows": 0, "bytes": 0})
        a["flows"] += 1
        a["bytes"] += f["total_bytes"]
    return {"protocols": sorted(agg.values(), key=lambda x: x["bytes"],
                                reverse=True)}


# --------------------------------------------------------------------- UI
@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
