#! / u s r / bin / env python
from scapy.all import *
#def monitor_callback(pkt):
#	print pkt.show()

total_pkts = 0
pkts_broad = 0
ruta_archivo = sys.argv[1]

def clasificar_pkt(pkt):
		#dado un paquete printeo si es broadcast o unicast, pongo su dst , e incremento el contador correspondiente

  if (pkt.dst == "ff:ff:ff:ff:ff:ff") :
    global pkts_broad
    print "Broadcast: " + pkt.dst
    pkts_broad += 1
    
  else :
    print "Unicast: " + pkt.dst

      
def procesar_pkt(pkt):
		#dado un paquete, lo clasifica en Broad o Uni con lo que esto conlleve y printea la frecuencia relativa hasta el
  	#momento de ambas clasificaciones
		
  global total_pkts
    
  clasificar_pkt(pkt)

  total_pkts += 1
  print "Frecuencia relativa de paquetes broadcast: " + str(pkts_broad) + "/" + str(total_pkts) + " - " + str(pkts_broad / total_pkts)
  print "Frecuencia relativa de paquetes unicast: " + str(total_pkts - pkts_broad) + "/" + str(total_pkts) + " - " + str((total_pkts - pkts_broad) / total_pkts)


def monitor_callback(pkt):
    #dado un pkt, lo escribo en un .cap, y lo proceso.
    #El comportamiento total de esta funcion (o sea, en conjunto con las subfunciones que la componen),dejar un registro de el
    #en un .cap,luego printear si es Broad o Uni, y la frecuencia relativa de ambas clasificaciones, teniendo en cuenta los 
    #anteriores paquetes introducidos en el .cap .
    
  global pktdump
  pktdump.write(pkt)
  procesar_pkt(pkt)

    
def leer_y_procesar_pcap(ruta_archivo):
	#dado un archivo .cap, lee los paquetes que en el se encuentran, y los procesa 1 a 1, con un comportamiento similar a monitar_callback
  lista_pkts = rdpcap(ruta_archivo)
  for pkt in lista_pkts:
    procesar_pkt(pkt)	

if __name__ == '__main__' :
	#aca leo y hago cosas
  if sys.argv[2] == "r" :
    leer_y_procesar_pcap(ruta_archivo)

  #aca sniffeo con scapy, y hago cosas
  elif sys.argv[2] == "w" :
    pktdump = PcapWriter(ruta_archivo, append=True, sync=True)
    sniff(prn = monitor_callback , store = 0)

  #aca alguien metio la pata
  else :
    raise ValueError('El segundo argumento debe ser r para leer un archivo, o w para crear uno')
    




