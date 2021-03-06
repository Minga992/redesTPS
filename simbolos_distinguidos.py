#! / u s r / bin / env python
from scapy.all import *
import math
#def monitor_callback(pkt):
#	print pkt.show()

superfrec = 0
namer = 1
traduccion_simbolos_a_numeros = {}
relaciones_por_numeros = {}

def clasificar_pkt(pkt,diccionarioIPorigen , diccionarioIPdestino, diccionarioIPorigenDestino,cantidadDePktsArP):
	#dado un paquete, si es arp, mira su emisor y su receptor, y lo coloca en los diccionarios

  try:

    if (pkt.type == 2054) :
      
      paqueteArpSrc = pkt.psrc
      diccionarioIPorigen[paqueteArpSrc] = diccionarioIPorigen.get(paqueteArpSrc, 0) + 1
     
      paqueteArpDst = pkt.pdst
      diccionarioIPdestino[paqueteArpDst] = diccionarioIPdestino.get(paqueteArpDst, 0) + 1
     
      paqueteArpSrcDst = paqueteArpSrc+paqueteArpDst
      diccionarioIPorigenDestino[paqueteArpSrcDst] = diccionarioIPorigenDestino.get(paqueteArpSrcDst, 0) + 1
      cantidadDePktsArP += 1

      global traduccion_simbolos_a_numeros
      global namer
      global relaciones_por_numeros

      paqueteArpSrc = str(paqueteArpSrc)
      paqueteArpDst = str(paqueteArpDst)

      if traduccion_simbolos_a_numeros.get(paqueteArpSrc, 0) == 0 :
        traduccion_simbolos_a_numeros[paqueteArpSrc] = namer
        namer += 1
      
      if traduccion_simbolos_a_numeros.get(paqueteArpDst, 0) == 0 :
        traduccion_simbolos_a_numeros[paqueteArpDst] = namer
        namer += 1
      
      nodoa = traduccion_simbolos_a_numeros.get(paqueteArpSrc, 0)
      nodob = traduccion_simbolos_a_numeros.get(paqueteArpDst, 0)

      if relaciones_por_numeros.get(nodoa , 0 ) == 0 :
        relaciones_por_numeros[nodoa] = []
      relaciones_por_numeros[nodoa].extend([nodob])




  except:
    
    pass

  return diccionarioIPorigen , diccionarioIPdestino, diccionarioIPorigenDestino, cantidadDePktsArP
      
def procesar_fuente (diccionario , cantidadDePktsArP):
  #dado un diccionario que tiene informacion sobre una fuente en particular(origen, destino u origendestino), y la cantidad de
  #pkts arp totales, devuelvo la entropia, en un diccionario(simbolo -> numerito) la cantidad de informacion de cada simbolo,
  # y en otro la dif entre la cantidad de info de cada simbolo y la entropia

  diccFrecRelSimb= {}
  FuenteInformacionSimb= {}
  DiferenciaEntropiaInfoSimb = {}
  entropia = 0
  global superfrec
  for simb in diccionario.keys() :

    frecAbsDelSimb = diccionario.get(simb)
    frecRelDelSimb = frecAbsDelSimb / float(cantidadDePktsArP)
    FuenteInformacionSimb[simb] = (math.log(frecRelDelSimb, 2) )* (-1)
    entropia = entropia + (frecRelDelSimb * math.log(frecRelDelSimb,2))
    diccFrecRelSimb[simb] = frecRelDelSimb
    superfrec += frecRelDelSimb
  entropia =  entropia * (-1)

  for simb in FuenteInformacionSimb.keys() :

    DiferenciaEntropiaInfoSimb[simb] = entropia - FuenteInformacionSimb.get(simb)
    #probablemente quiera el valor absoluto de esto


  return (entropia, DiferenciaEntropiaInfoSimb, FuenteInformacionSimb, diccFrecRelSimb)

def procesar_pkts(cantidadDePktsArP,diccionarioIPorigen , diccionarioIPdestino, diccionarioIPorigenDestino):
  #Dada la entrada que lees, donde cada diccionario representa una fuente distinta, consigo datos utiles por cada fuente
  #segun la funcion procesar_fuente

  datosOrigen = procesar_fuente(diccionarioIPorigen, cantidadDePktsArP)
  datosDestino = procesar_fuente(diccionarioIPdestino, cantidadDePktsArP)
  datosOrigenDestino = procesar_fuente(diccionarioIPorigenDestino, cantidadDePktsArP)    

  return datosOrigen , datosDestino , datosOrigenDestino

def monitor_callback(pkt):
  #Funcion que va creando el .cap
    
  global pktdump
  pktdump.write(pkt)

    
def leer_y_procesar_pcap(ruta_archivo , cantidadDePktsArP):
	#dado un archivo .cap, lee los paquetes que en el se encuentran, clasifica los paquetes segun las tres fuentes que representan 
  # los diccionarios, procesa estas fuentes, e imprime en distintos txt la informacion util

  lista_pkts = rdpcap(ruta_archivo)
  diccionarioIPorigen= {}
  diccionarioIPdestino= {}
  diccionarioIPorigenDestino= {}


  for pkt in lista_pkts:
    diccionarioIPorigen , diccionarioIPdestino, diccionarioIPorigenDestino, cantidadDePktsArP = clasificar_pkt(pkt, diccionarioIPorigen , diccionarioIPdestino, diccionarioIPorigenDestino, cantidadDePktsArP)	


  datosOrigen , datosDestino , datosOrigenDestino = procesar_pkts(cantidadDePktsArP,diccionarioIPorigen , diccionarioIPdestino, diccionarioIPorigenDestino)
  
  imprimir_datos_fuente_txt('Origen',datosOrigen)
  imprimir_datos_fuente_txt('Destino',datosDestino)
  #imprimir_datos_fuente_txt('OrigenDestino',datosOrigenDestino)

  
def imprimir_datos_fuente_txt(tipoFuente, datosFuente) :
  #dado un nombre de fuente, y los datos que se buscan imprimir, imprimo los datos
  #datosFuente[0] => entropia
  #datosFuente[1] => no importa
  #datosFuente[2] => cantidad de info simbolos
  #datosFuente[3] => probabilidades simbolos

  archiProb = open('Probabilidades' + tipoFuente + '.csv' ,'a')
  archiProb.write('Simbolos ;' + 'Probabilidad' + '\n' + '\n')
  for simb in datosFuente[1].keys():
    archiProb.write( str(simb) + ' ;' + str(datosFuente[3].get(simb,0) ) + '\n')
  archiProb.close()

  archiEntroCantIf = open('datos' + tipoFuente + '.csv' ,'a')
  archiEntroCantIf.write ('entropia ;' + str(datosFuente[0]) + '\n')
  archiEntroCantIf.write('Simbolos ;' + 'CantidadInformacion' + '\n')
  for simb in datosFuente[1].keys():
    archiEntroCantIf.write(str(simb) + ' ;' + str(datosFuente[2].get(simb,0)) + '\n')

  archiEntroCantIf.close()


if __name__ == '__main__' :
	
  cantidadDePktsArP = 0
  ruta_archivo = sys.argv[1]


  #aca leo y hago cosas
  if sys.argv[2] == "r" :
    leer_y_procesar_pcap(ruta_archivo, cantidadDePktsArP)
    
    archigraf = open('paraHacerGrafos.txt' ,'a')
    archigraf.write( str(namer - 1) + ':' )
    for simb in relaciones_por_numeros.keys():
      for nodo in relaciones_por_numeros.get(simb, 0):
        archigraf.write( str(simb) + '-' + str(nodo) + ',')
    
    archigraf.close()

    architable = open('TablaIpsNumeros.txt' ,'a')
    for simb in traduccion_simbolos_a_numeros.keys():
      architable.write( str(simb) + ': ' + str(traduccion_simbolos_a_numeros.get(simb , 0) ) + '\n')
    
    architable.close()

  #aca sniffeo con scapy, y hago cosas
  elif sys.argv[2] == "w" :

    segundosTimeOut = int(sys.argv[3])
    pktdump = PcapWriter(ruta_archivo, append=True, sync=True)
    sniff(prn = monitor_callback , store = 0, timeout = segundosTimeOut)
    #manda por parametro tiempo al sniff
    pktdump.close()
    leer_y_procesar_pcap(ruta_archivo, cantidadDePktsArP)
    #fijate si esto funciona, el archivo esta abierto, podria crashear


  #aca alguien metio la pata
  else :
    raise ValueError('El segundo argumento debe ser r para leer un archivo, o w para crear uno')
    




