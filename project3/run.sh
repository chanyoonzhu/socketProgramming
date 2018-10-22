#!/bin/bash

read -p "Type in the number of hosts: " n_hosts
echo "Opening $n_hosts hosts" 

for ((i = 1; i <= $n_hosts; i++))
do
    xterm -hold -e "./host$i inputs/$i.txt inputs/Project2Topo.pcap" &
done
