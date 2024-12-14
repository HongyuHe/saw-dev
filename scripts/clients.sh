#!/usr/bin/env bash
set -x

{
clients=(1 2 4 8)
# Check if the first argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <ofdm|ofdma>"
    exit 1
fi

# Determine the command based on the first argument
if [ "$1" == "ofdm" ]; then
    enableUlOfdma=0
elif [ "$1" == "ofdma" ]; then
    enableUlOfdma=1
else
    echo "Invalid argument: $1. Use 'ofdm' or 'ofdma'."
    exit 1
fi

# Loop through each client number
for clients in "${clients[@]}"; do
    ../../ns3 run src/saw.cc -- --clients="$clients" --enableUlOfdma="$enableUlOfdma" | tee logs/"$1"_"$clients"c.log
    mv ../../ap.pcap  ~/Desktop/"$1"_"$clients"c.pcap
done
}