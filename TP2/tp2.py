#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from scapy.all import *

def process(hostname):

	# Constantes de tipos de paquetes
	TYPE_ECHO_REPLY = 0
	TYPE_ECHO = 8

	# Valor máximo de ttl (si el paquete nunca alcanza el destino puede quedar flotando de por vida si no)
	MAX_TTLS = int(sys.argv[2])
	
	# Por cada ttl enviamos esta cantidad de paquetes ya que las rutas pueden ir variando.
	# Luego, por cada ttl, nos quedaremos con la ip que más veces respondió en estas repeticiones
	TTL_REPETITIONS = int(sys.argv[3])

	# Booleano para determinar si ya alcanzamos el destino, en tal caso dejamos de procesar
	host_reached = False

	# Valor inicial de ttl, arrancamos en 1 y vamos incrementándolo
	ttl = 1

	# Último rtt promedio calculado, para calcular el rtt del nuevo hop
	last_rtt_avg = 0

	print "{0:3s} {1:15s} {2:8s}".format("ttl", "ip", "rtt (ms)")

	while(not host_reached and ttl < MAX_TTLS):

		# Diccionario en donde guardamos por cada ip que responde, un listado de los rtt
		ips_rtts = {}

		# Diccionario en donde guardamos por cada ip que responde, el response type (para luego saber si es el host destino)
		ips_responseType = {}

		for repetition in range(TTL_REPETITIONS):

			# Se genera y envía el paquete con el valor actual del ttl
			packet = IP(dst=hostname, ttl=ttl)/ ICMP(type=TYPE_ECHO)
			answered, unanswered = sr(packet, timeout=1, verbose=0)

			# Si no respondió nadie no hacemos nada, procesamos el siguiente
			if(unanswered):
				continue

			# paquete que se envió
			request = answered[0][0]

			# paquete que respondió
			response = answered[0][1]
			
			# tiempo de envío y de respuesta
			request_time = request.sent_time
			response_time = response.time

			# se calcula el rtt, puede llegar a ser negativo, en tal caso nos quedamos con 0
			# para que luego al calcular el rtt promedio, no nos reste
			rtt = max(0, response_time - request_time)

			# guardamos el rtt actual para la ip que respondió
			ips_rtts.setdefault(response.src, [])
			ips_rtts[response.src].append(rtt)

			ips_responseType[response.src] = response.type


		if ips_rtts:
			# Como la idea consiste en quedarse, para cada valor del ttl, con la ip que más veces respondió, 
			# recorremos el diccionario y nos quedamos con esa ip
			max_responses = 0
			selected_ip = None

			for ip, rtts in ips_rtts.iteritems():
				if(len(rtts) >= max_responses):
					selected_ip = ip
					max_responses = len(rtts)


			# Luego, para la ip que más veces respondió, calculamos el rtt promedio y le restamos el rtt promedio del
			# ttl (con respuesta) anterior para saber cuál fue el rtt este rtt_hop
			rtt_avg = sum(ips_rtts[selected_ip]) / len(ips_rtts[selected_ip])
			rtt_hop = max(0, rtt_avg - last_rtt_avg)
			last_rtt_avg = rtt_avg

			print "{0} {1} {2:f}".format(ttl, selected_ip, rtt_hop * 1000.0)

			# Si se alcanzó el destino, seteamos la variable host_reached en True para que deje de iterar
			if(ips_responseType[selected_ip] == TYPE_ECHO_REPLY):
				host_reached = True

		ttl += 1



if __name__ == '__main__':
	if(len(sys.argv) != 4):
		print "La cantidad de parámetros es incorrecta: \n\n python tp2.py -hostname -max_ttls -ttl_repetitions \n\n hostname: es la URL o la IP del host al cual se intenta hacer Traceroute.\n max_ttls: es la cantidad máxima de TTLs hasta la que se va a llegar a probar.\n ttl_repetitions: es la cantidad de paquetes que se enviarán en ráfaga para cada TTL que se pruebe."
	else:
		process(sys.argv[1])
