#!/usr/bin/env bash

set -e

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
BDIR="$( cd -P "$( dirname "$SOURCE" )/.." && pwd )"

mkdir -p ${BDIR}/dist_linux/
rm -f ${BDIR}/dist_linux/*
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -o "${BDIR}/dist_linux/docker-slim" "${BDIR}/cmd/docker-slim/main.go"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -o "${BDIR}/dist_linux/docker-slim-sensor" "${BDIR}/cmd/docker-slim-sensor/main.go"
