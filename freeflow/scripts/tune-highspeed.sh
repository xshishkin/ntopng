#!/usr/bin/env bash
# tune-highspeed.sh — sysctl/ethtool tuning for lossless 2+ Gbit/s SPAN capture.
# Run as root on the FreeFlow monitoring box. Adjust IFACE to your span NIC.
set -eu
IFACE="${1:-eth0}"

echo "== $IFACE: kernel ring buffers =="
# huge rx ring (max supported by most NICs)
ethtool -G "$IFACE" rx 4096 tx 4096 2>/dev/null || true
# enable multi-queue + RSS so fanout/PF_RING cluster can parallelize
ethtool -L "$IFACE" combined "$(nproc)" 2>/dev/null || true
ethtool -N "$IFACE" rx-flow-hash tcp4 sdfn 2>/dev/null || true
ethtool -K "$IFACE" gro on lro off 2>/dev/null || true   # LRO distorts stats, GRO is fine

echo "== net.core sysctls =="
sysctl -w net.core.rmem_max=268435456
sysctl -w net.core.rmem_default=16777216
sysctl -w net.core.netdev_max_backlog=250000
sysctl -w net.core.busy_poll=50
sysctl -w net.core.busy_read=50

echo "== ipv4/6 backlog (af_packet queues) =="
sysctl -w net.ipv4.tcp_rmem="4096 262144 67108864"

echo "== packet socket fanout CPU affinity hint =="
echo "Bind FreeFlow worker threads to separate cores with taskset/niceness:"
echo "  chrt -f 50 python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8300"

echo "== disable irqbalance and pin NIC IRQs to the same NUMA node =="
systemctl stop irqbalance 2>/dev/null || true
NUMA_NODE=$(cat /sys/class/net/"$IFACE"/device/numa_node 2>/dev/null || echo 0)
echo "NIC is on NUMA node $NUMA_NODE — pin worker threads there."

echo "Done. Verify drops with:  ethtool -S $IFACE | grep -i drop ;  cat /proc/net/softnet_stat"
