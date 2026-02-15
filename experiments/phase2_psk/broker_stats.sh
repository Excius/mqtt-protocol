#!/bin/bash

PID=$(pidof mosquitto)

if [ -z "$PID" ]; then
  echo "Mosquitto not running"
  exit 1
fi

CPU=$(ps -p "$PID" -o %cpu=)
MEM=$(ps -p "$PID" -o rss=) # in KB

echo "$CPU,$MEM"