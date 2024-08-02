#!/usr/bin/env bash


sudo /home/ubuntu/openvpn-exporter/openvpn-exporter-v0.3.0 \
    -ignore.individuals \
    -openvpn.status_paths /var/log/openvpn/openvpn-status.log \
    -web.listen-address :9176 \
    -web.telemetry-path /metrics

# docker run \
#            --rm \
#            -v `pwd`:/go/src/app \
#            -w /go/src/app \
#            -e CGO_ENABLED=0 \
#            --env GOOS=linux \
#            --env GOARCH=amd64 \
#            golang:1.22 go build -o openvpn-exporter-v0.3.0 main.go