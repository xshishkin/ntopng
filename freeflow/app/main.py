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

app = FastAPI(title="FreeFlow", version="1.0.0")
engine = TrafficEngine()

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")


class StartIface(BaseModel):
    iface: str


class StartPcap(BaseModel):
    path: str


# ------------------------------------------------------------------ API v1
@app.get("/api/v1/status")
def api_status():
    return engine.status()


@app.get("/api/v1/interfaces")
def api_interfaces():
    return {"interfaces": list_interfaces()}


@app.post("/api/v1/start/interface")
def api_start_interface(body: StartIface):
    ifaces = list_interfaces()
    if body.iface not in ifaces:
        raise HTTPException(400, f"Unknown interface '{body.iface}'. "
                                 f"Available: {', '.join(ifaces) or 'none'}")
    try:
        engine.start_interface(body.iface)
    except PermissionError:
        raise HTTPException(403, "Capture requires root/CAP_NET_RAW")
    except Exception as e:
        raise HTTPException(500, f"Failed to start capture: {e}")
    return engine.status()


@app.post("/api/v1/start/pcap")
def api_start_pcap(body: StartPcap):
    if not os.path.isfile(body.path):
        raise HTTPException(404, f"File not found: {body.path}")
    engine.start_pcap(body.path)
    return engine.status()


@app.post("/api/v1/stop")
def api_stop():
    engine.stop()
    return engine.status()


@app.get("/api/v1/stats/flows")
def api_flows(limit: int = Query(200, le=2000), search: str = None):
    return {"flows": engine.snapshot_flows(limit=limit, search=search)}


@app.get("/api/v1/stats/hosts")
def api_hosts(limit: int = Query(200, le=2000)):
    return {"hosts": engine.snapshot_hosts(limit=limit)}


@app.get("/api/v1/stats/protocols")
def api_protocols():
    return {"protocols": engine.snapshot_protocols()}


# --------------------------------------------------------------------- UI
@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
