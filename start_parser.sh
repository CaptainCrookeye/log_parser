#!/bin/bash

LOG_FILE="/path/to/file.log"

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: Log file not found" >&2
    exit 1
fi

tail -n 0 -F "$LOG_FILE" | python3 -u parser.py