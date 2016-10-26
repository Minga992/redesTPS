#! / u s r / bin / env python
from scapy.all import *
import math

for x in xrange(1,30):
	print "x es " + str(x) + "\n"
	pkt = IP(dst='www.google.com', ttl=x) / ICMP()
	res = srloop(pkt , count = 5, timeout = 4)
	res[0][ICMP].display()
#	res[0][ICMP].display()
# 0000 IP / ICMP 192.168.0.105 > 173.194.42.211
# echo-request 0 ==> IP / ICMP 173.194.42.211 > 192.168.0.105
# echo-reply 0
