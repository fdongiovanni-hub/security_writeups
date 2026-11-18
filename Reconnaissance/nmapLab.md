# NMAP LAB EXERCISE

## PHASE 1
1. What is your IP address and network configuration?

`ip route`. my VM has the IP address 10.0.0.155 in the 10.0.0.0/8 network. The default gateway is 10.0.0.1

2. Which IP addresses are active within the authorised laboratory network?

`sudo nmap -sn -n 10.0.0.0/24`: 72 hosts up
- with -sn nmap only checks if the device is online (skips checking open services or ports). 
- with -n nmap doesn't resolve IP in a name (DNS)
- sudo: the scan with root privileges so Nmap uses Layer 2 ARP requests, which bypass OS firewalls

3. Can you identify an unknown server?


4. How do ARP, ICMP, and TCP host-discovery techniques differ?


5. Can you determine which IP address belongs to your target?

