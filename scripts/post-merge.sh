#!/bin/bash
set -e

cd /home/runner/workspace

if [ -f "go.mod" ]; then
    go build -o dns-tool-server ./go-server/cmd/server/
fi
