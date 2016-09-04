#! / u s r / bin / env python
from scapy.all import *
def monitor_callback(pkt):
	print pkt.show()

if __name__ == '__main__' :
	# sniff(prn = monitor_callback, store = 0)
	a = rdpcap("/home/fede/Captura2")
	for b in a:
		print b.dst
	# print a.sprintf("%TCP.sport% \t %TCP.flags%")