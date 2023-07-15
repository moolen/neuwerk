#!/usr/bin/env bash
set -exuo pipefail

echo "setting up neuwerk"

# internal IPs are hard-coded for now
echo "192.168.56.2" > /home/vagrant/proxy1
echo "192.168.56.3" > /home/vagrant/proxy2
echo "192.168.56.4" > /home/vagrant/proxy3

if [ "$(hostname)" == "client" ]; then
    exit 0
fi

MGMT_ADDR=$(cat /home/vagrant/$(hostname))
PEERS=$(cat /home/vagrant/proxy* | grep -v $MGMT_ADDR | sed -e 's/^/--peers /' | sed 'N;s/\n/ /')

NET_DEVICE=eth1

# cleanup old stuff
kill $(cat "$MGMT_ADDR.pid") || true
rm -rf /sys/fs/bpf/neuwerk || true
tc qdisc del dev "${NET_DEVICE}" clsact || true


# cluster bringup: first node should start without peers
# all subsequent nodes must start with peers
if [ "$(hostname)" == "proxy1" ]; then
    nohup /home/vagrant/neuwerk \
        --config /home/vagrant/config.yaml \
        --net-device "${NET_DEVICE}" \
        --memberlist-bind-addr "${MGMT_ADDR}" \
        --memberlist-advertise-addr "${MGMT_ADDR}" \
        --db-bind-addr "${MGMT_ADDR}" > "neuwerk.${MGMT_ADDR}.log" 2>&1 &
else
    nohup /home/vagrant/neuwerk \
        --config /home/vagrant/config.yaml \
        --net-device "${NET_DEVICE}" \
        $PEERS \
        --memberlist-bind-addr "${MGMT_ADDR}" \
        --memberlist-advertise-addr "${MGMT_ADDR}" \
        --db-bind-addr "${MGMT_ADDR}" > "neuwerk.${MGMT_ADDR}.log" 2>&1 &
fi

echo $! > "$MGMT_ADDR.pid"
echo "neuwerk runs in background"
