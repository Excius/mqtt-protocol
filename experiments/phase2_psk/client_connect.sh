#!/bin/bash

START=$(date +%s%N)

for i in {1..20}; do
  mosquitto_pub \
    -h localhost -p 8883 \
    --psk-identity client1 \
    --psk "$PSK_KEY" \
    -t test -m "hello" \
    >/dev/null 2>&1
done

END=$(date +%s%N)

echo $(( (END - START) / 1000000 ))