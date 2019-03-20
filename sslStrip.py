from scapy.all import *
import os
import time

print "testbalbalbalblabllab"

file = open("vIP.txt")
contents = file.read()
file.close()
print (contents)


a = sniff(filter="tcp and port 80 and src " + contents, count=1)
#sniff(filter="tcp and src 192.168.56.101", count=1)

a.nsummary()
print "done"
