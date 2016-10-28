#! /usr/bin/env python

import sys
from scapy.all import *

def process(hostname):

	# Constantes de tipos de paquetes
	TYPE_ECHO_REPLY = 0
	TYPE_ECHO = 8

	# Valor maximo de ttl (si el paquete nunca alcanza el destino puede quedar flotando de por vida sino)
	MAX_TTLS = 40
	
	# Por cada ttl enviamos esta cantidad de paquetes ya que las rutas pueden ir variando.
	# Luego, por cada ttl, nos quedaremos con la ip que mas veces respondio en estas repeticiones
	TTL_REPETITIONS = 5

	# Booleano para determinar si ya alcanzamos el destino, en tal caso dejamos de procesar
	host_reached = False

	# Valor inicial de ttl, arrancamos en 1 y vamos incrementandolo
	ttl = 1

	# Listado con los saltos que se fueron realizando
	hops = []

	
	while(not host_reached and ttl < MAX_TTLS):

		# Diccionario en donde guardamos por cada ip que responde, un listado de los rtt
		ips_rtts = {}

		for repetition in range(TTL_REPETITIONS):

			# Se genera y envia el paquete con el valor actual del ttl
			packet = IP(dst=hostname, ttl=ttl)/ ICMP(type=TYPE_ECHO)
			answered, unanswered = sr(packet, timeout=1, verbose=0)

			# Si no respondio nadie no hacemos nada, procesamos el siguiente
			if(unanswered):
				continue

			# paquete que se envio
			request = answered[0][0]

			# paquete que respondio
			response = answered[0][1]
			
			# tiempo de envio y de respuesta
			request_time = request.sent_time
			response_time = response.time

			# se calcula el rtt, puede llegar a ser negativo, en tal caso nos quedamos con 0
			# para que luego al calcular el rtt promedio, no nos reste
			rtt = max(0, response_time - request_time)

			# guardamos el rtt actual para la ip que respondio
			ips_rtts.setdefault(response.src, [])
			ips_rtts[response.src].append(rtt)

			# Si se alcanzo el destino, seteamos la variable host_reached en True para que deje de iterar
			if(response.type == TYPE_ECHO_REPLY):
				host_reached = True


		# Como la idea consiste en quedarse, para cada valor del ttl, con la ip que mas veces respondio, 
		# recorremos el diccionario y nos quedamos con esa ip
		max_responses = 0
		selected_ip = None

		for ip, rtts in ips_rtts.iteritems():
			if(len(rtts) >= max_responses):
				selected_ip = ip


		# Luego, para la ip que mas veces respondio, calculamos el rtt promedio y lo metemos en el listado de hops
		# Aclaracion: (ver que onda aca, si para el ttl actual no respondio nadie que deberiamos hacer, 
		# quizas incrementar el TTL_REPETITIONS ayude, por eso el if, sino selected_ip quedaba en None)
		if(selected_ip is not None): 
			rtt_avg = sum(ips_rtts[selected_ip]) / len(ips_rtts[selected_ip])
			hops.append({"ip": selected_ip, "rtt": rtt_avg}) 

			print "TTL: " + str(ttl)
			print "ip: " + str(selected_ip) 
			print "rtts: " + str(ips_rtts[selected_ip])
			print "avg: " + str(rtt_avg)

		ttl += 1

	print "\n\nHOPS: "
	print hops



if __name__ == '__main__':
	if(len(sys.argv) != 2):
		print "debe pasar el hostname como parametro"
	else:
		process(sys.argv[1])



# Si bien queda en el repo, dejo por las dudas comentado el codigo que ya estaba
#from scapy.all import *
#import math
#
#for x in xrange(1,30):
#	print "x es " + str(x) + "\n"
#	pkt = IP(dst='www.google.com', ttl=x) / ICMP()
#	res = srloop(pkt , count = 5, timeout = 4)
#	res[0][ICMP].display()
#	res[0][ICMP].display()
# 0000 IP / ICMP 192.168.0.105 > 173.194.42.211
# echo-request 0 ==> IP / ICMP 173.194.42.211 > 192.168.0.105
# echo-reply 0
