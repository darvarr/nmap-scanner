#!/bin/bash

export MIN_RATE=500
export OUTPUT_FOLDER="/tmp/nmap_reports"
export LOG_DIR="/var/log/nmap_scanner"
export LOG_LEVEL=debug

EXECUTABLE_PATH="$(pwd)/nmap_scanner.py"
read -r -p "Target IP (e.g. 192.168.1.0/24,192.168.1.2): " TARGETS
read -r -p "IP to exclude (leave empty if it's the case, e.g. 192.168.1.1,192.168.1.2): " EXCLUSIONS

/path/to/.venv/bin/python3 "$EXECUTABLE_PATH" -t "$TARGETS" -e "$EXCLUSIONS" >> "/var/log/nmap_scanner/nmap_scanner.log" 2>&1
