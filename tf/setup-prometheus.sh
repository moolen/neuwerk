#!/bin/bash
set -xeuo pipefail
NEUWERK_INTERNAL=${1}

PROM_VERSION="2.47.1"

if [ ! -d "prometheus-$PROM_VERSION.linux-amd64" ]; then
    wget https://github.com/prometheus/prometheus/releases/download/v$PROM_VERSION/prometheus-$PROM_VERSION.linux-amd64.tar.gz
    tar xvfz prometheus-*.tar.gz
fi

cd prometheus-*

cat > ./prometheus.yml <<EOF
global:
  scrape_interval:     15s
  evaluation_interval: 15s

rule_files: []

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets:
EOF

while IFS= read -r line; do
    echo "        - $line:3000" >> ./prometheus.yml
done <<< "$NEUWERK_INTERNAL"

sudo killall prometheus || true
echo "starting prometheus"
nohup ./prometheus > prometheus.log 2> prometheus.err < /dev/null &
sleep 2