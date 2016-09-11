#! / u s r / bin / env python
from scapy.all import *
#def monitor_callback(pkt):
#	print pkt.show()

pktdump = PcapWriter("temp.cap", append=True, sync=True)

def monitor_callback_temp(pkt):
    global pktdump
    pktdump.write(pkt)	
    print pkt.show()
	
if __name__ == '__main__' :
    sniff(prn = monitor_callback_temp , store = 0)
    
#   #a = rdpcap("/home/minga/Escritorio/temp.cap")
#   #for b in a:
#   #   print b.show()
#    #print a.sprintf("%TCP.sport% \t %TCP.flags%")

