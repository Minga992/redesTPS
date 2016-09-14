#! / u s r / bin / env python
from scapy.all import *
#def monitor_callback(pkt):
#	print pkt.show()

def clasificar_pkt(pkt,diccionarioIPorigen , diccionarioIPdestino, diccionarioIPorigenDestino):
	#dado un paquete, si es arp, mira su emisor y su receptor, y lo coloca en los diccionarios

  if (pkt.type == 2054) :
    
    paqueteArpSrc = pkt.psrc
    diccionarioIPorigen[paqueteArpSrc] = diccionarioIPorigen.get(paqueteArpSrc, 0) + 1
   
    paqueteArpDst = pkt.pdst
    diccionarioIPdestino[paqueteArpDst] = diccionarioIPdestino.get(paqueteArpDst, 0) + 1
   
    paqueteArpSrcDst = paqueteArpSrc+paqueteArpDst
    diccionarioIPorigenDestino[paqueteArpSrcDst] = diccionarioIPorigenDestino.get(paqueteArpSrcDst, 0) + 1

    return (diccionarioIPorigen , diccionarioIPdestino, diccionarioIPorigenDestino)
      
def procesar_fuente (diccionario , cantidadDePktsArP):
    
  FuenteInformacionSimb= {}
  DiferenciaEntropiaInfoSimb = {}
  entropia = 0

  for simb in diccionario.keys() :

    frecAbsDelSimb = diccionario.get(simb)
    frecRelDelSimb = frecAbsDelSimb / cantidadDePktsArP

    FuenteInformacionSimb[simb] = log(frecRelDelSimb,2) * (-1)

    entropia = entropia + (frecRelDelSimb * log(frecRelDelSimb,2))
  
  entropia = - entropia

  for simb in FuenteInformacionSimb.keys() :

    DiferenciaEntropiaInfoSimb[simb] = entropia - FuenteInformacionSimb.get(simb)
    #probablemente quiera el valor absoluto de esto


  return (entropia, DiferenciaEntropiaInfoSimb, FuenteInformacionSimb)

def procesar_pkts(cantidadDePktsArP,diccionarioIPorigen , diccionarioIPdestino, diccionarioIPorigenDestino):
		#dado un paquete, lo clasifica en Broad o Uni con lo que esto conlleve y printea la frecuencia relativa hasta el
  	#momento de ambas clasificaciones
		#datos es tripleta (entropia, DiferenciaEntropiaInfoSimb, FuenteInformacionSimb)
  
  datosOrigen = procesar_fuente(diccionarioIPorigen. cantidadDePktsArP)
  datosDestino = procesar_fuente(diccionarioIPdestino, cantidadDePktsArP)
  datosOrigenDestino = procesar_fuente(diccionarioIPorigenDestino, cantidadDePktsArP)    

  return (datosOrigen , datosDestino , datosOrigenDestino)

def monitor_callback(pkt):
    #dado un pkt, lo escribo en un .cap, y lo proceso.
    #El comportamiento total de esta funcion (o sea, en conjunto con las subfunciones que la componen),dejar un registro de el
    #en un .cap,luego printear si es Broad o Uni, y la frecuencia relativa de ambas clasificaciones, teniendo en cuenta los 
    #anteriores paquetes introducidos en el .cap .
    
  global pktdump
  pktdump.write(pkt)

    
def leer_y_procesar_pcap(ruta_archivo , cantidadDePktsArP):
	#dado un archivo .cap, lee los paquetes que en el se encuentran, y los procesa 1 a 1, con un comportamiento similar a monitar_callback
  lista_pkts = rdpcap(ruta_archivo)
  diccionarioIPorigen={}
  diccionarioIPdestino={}
  diccionarioIPorigenDestino={}

  for pkt in lista_pkts:
    (diccionarioIPorigen , diccionarioIPdestino, diccionarioIPorigenDestino) = clasificar_pkt(pkt,diccionarioIPorigen , diccionarioIPdestino, diccionarioIPorigenDestino)	
    cantidadDePktsArP += 1

  datosFuentes = procesar_pkts(cantidadDePktsArP,diccionarioIPorigen , diccionarioIPdestino, diccionarioIPorigenDestino)
  #mandar cada elemento de datos fuentes a un txt distinto acaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

if __name__ == '__main__' :
	#aca leo y hago cosas
  cantidadDePktsArP = 0
  ruta_archivo = sys.argv[1]

  if sys.argv[2] == "r" :
    leer_y_procesar_pcap(ruta_archivo, cantidadDePktsArP)

  #aca sniffeo con scapy, y hago cosas
  elif sys.argv[2] == "w" :

    segundosTimeOut = int(sys.argv[3])
    pktdump = PcapWriter(ruta_archivo, append=True, sync=True)
    sniff(prn = monitor_callback , store = 0, timeout = segundosTimeOut)
    #manda por parametro tiempo al sniff

    leer_y_procesar_pcap(ruta_archivo, cantidadDePktsArP)
    #fijate si esto funciona, el archivo esta abierto, podria crashear


  #aca alguien metio la pata
  else :
    raise ValueError('El segundo argumento debe ser r para leer un archivo, o w para crear uno')
    




