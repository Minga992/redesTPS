#! / u s r / bin / env python
from scapy.all import *
#def monitor_callback(pkt):
#	print pkt.show()

total_pkts = 0
pkts_broad = 0
archi = open('bradcast_fuente.txt' ,'a')

def clasificar_pkt(pkt):
		#dado un paquete printeo si es broadcast o unicast, pongo su dst , e incremento el contador correspondiente

  global archi
  if (pkt.dst == "ff:ff:ff:ff:ff:ff") :
    global pkts_broad    
    archi.write('Broadcast: ' + str(pkt.dst) + '\n')
    pkts_broad += 1
    
  else :
    archi.write('Unicast: ' + str(pkt.dst) + '\n')

      
def procesar_pkt(pkt):
		#dado un paquete, lo clasifica en Broad o Uni con lo que esto conlleve y printea la frecuencia relativa hasta el
  	#momento de ambas clasificaciones
		
  global total_pkts    
  clasificar_pkt(pkt)
  total_pkts += 1

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

  global total_pkts
  global pkts_broad
  global archi
  archi.write('Frecuencia relativa de paquetes broadcast: '+ str(pkts_broad) + '/' + str(total_pkts) + ' - ' + str(pkts_broad / float(total_pkts)) + '\n')
  archi.write('Frecuencia relativa de paquetes unicast: ' + str(total_pkts - pkts_broad) + "/" + str(total_pkts) + " - " + str((total_pkts - pkts_broad) / float(total_pkts)) + '\n')

if __name__ == '__main__' :
	#aca leo y hago cosas

  ruta_archivo = sys.argv[1]
  if sys.argv[2] == "r" :
    leer_y_procesar_pcap(ruta_archivo)
    archi.close()
  #aca sniffeo con scapy, y hago cosas
  elif sys.argv[2] == "w" :
    segundosTimeOut = int(sys.argv[3])
    pktdump = PcapWriter(ruta_archivo, append=True, sync=True)
    sniff(prn = monitor_callback , store = 0, timeout = segundosTimeOut)

    
    archi.write('Frecuencia relativa de paquetes broadcast: '+ str(pkts_broad) + '/' + str(total_pkts) + ' - ' + str(pkts_broad / float(total_pkts)) + '\n')
    archi.write('Frecuencia relativa de paquetes unicast: ' + str(total_pkts - pkts_broad) + '/' + str(total_pkts) + ' - ' + str((total_pkts - pkts_broad) / float(total_pkts)) + '\n')

    archi.close()
  #aca alguien metio la pata
  else :
    raise ValueError('El segundo argumento debe ser r para leer un archivo, o w para crear uno')