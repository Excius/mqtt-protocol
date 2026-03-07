#!/bin/bash

PID=$(pidof mosquitto)

if [ -z "$PID" ]; then
  echo "0,0,0"
  exit 0
fi

# Sample CPU before
CPU_BEFORE=$(ps -p "$PID" -o %cpu= 2>/dev/null | tr -d ' ')

# Small delay
sleep 0.1

# Sample CPU after
CPU_AFTER=$(ps -p "$PID" -o %cpu= 2>/dev/null | tr -d ' ')
MEM=$(ps -p "$PID" -o rss= 2>/dev/null | tr -d ' ')

echo "$CPU_BEFORE,$CPU_AFTER,$MEM"
