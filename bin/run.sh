#!/usr/bin/env bash


/home/ubuntu/openvpn-exporter/openvpn-exporter-v0.3.0 \
    -openvpn.status_paths /var/log/openvpn/openvpn-status.log \
    -web.listen-address :9176 \
    -web.telemetry-path /metrics
