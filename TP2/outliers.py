#! /usr/bin/env python

import math
import sys
import csv

thompson = [0, 0, 0, 1.1511, 1.4250, 1.5712, 1.6563, 1.7110, 1.7491, 1.7770, 1.7984, 1.8153, 1.8290, 1.8403, 1.8498, 1.8579, 1.8649, 1.8710, 1.8764, 1.8811, 1.8853, 1.8891, 1.8926, 1.8957, 1.8985, 1.9011, 1.9035, 1.9057, 1.9078, 1.9096, 1.9114]

IP = "ip"
RTT = "rtt"

class Hop:
	ttl = 0
	ip = ""
	rtt = 0.0
	delta = 0.0
	standarized_rtt = 0.0


def metrics(hops):
	n = len(hops)
	average = sum(map(lambda hop: hop.rtt, hops)) / n
	variance = sum(map(lambda hop: pow(hop.rtt - average, 2), hops)) / n
	standard_deviation = math.sqrt(variance)
	return average, variance, standard_deviation


def standardize(hops):
	average, variance, standard_deviation = metrics(hops)
	for hop in hops:
		hop.standarized_rtt = abs(hop.rtt - average) / standard_deviation
	return hops


def find_outliers(hops):
	
	outliers = []
	find_more = True

	# Me quedo con los Hops cuyo RTT no sea 0
	# hops = filter(lambda hop: hop.rtt != 0, hops)

	while find_more:

		# Calculamos promedio y desvio standard para los hops que quedan
		average, variance, standard_deviation = metrics(hops)

		# Calculamos los delta_i
		for hop in hops:
			hop.delta = abs(hop.rtt - average)

		# Buscamos el mayor delta, es el primer potencial outlier
		max_delta = max(map(lambda hop: hop.delta, hops))

		tS = thompson[len(hops)] * standard_deviation

		if(max_delta <= tS):
			# No hay mas outliers
			find_more = False
		else:
			# agregamos el nuevo outlier a los outliers, borramos ese hop y seguimos iterando
			outliers += filter(lambda hop: hop.delta == max_delta, hops)
			hops = filter(lambda hop: hop.delta != max_delta, hops)

	return outliers




def parse_input_file(filename):
	hops = []
	with open(filename, 'rb') as csvfile:
		next(csvfile, None)
		reader = csv.reader(csvfile, delimiter='\t')
		for row in reader:
			hop = Hop()
			hop.ttl = int(row[0])
			hop.ip = row[1]
			hop.rtt = float(row[2])
			hops.append(hop)
	return hops


if __name__ == '__main__':
	if(len(sys.argv) != 2):
		print "debe pasar el nombre del archivo de entrada como parametro"
	else:
		hops = parse_input_file(sys.argv[1])
		hops = standardize(hops)
		outliers = find_outliers(hops)

		print "{0:15s}\t{1:18s}\t{2:18s}\t{3}".format("IP", "RTT", "STANDARIZED RTT", "OUTLIERS")
		rtts_outliers = map(lambda outlier: outlier.rtt, outliers)
		for hop in hops:
			print "{0}\t{1:4.14f}\t{2:4.14f}\t{3}".format(hop.ip, hop.rtt, hop.standarized_rtt, "[outlier]" if(hop.rtt in rtts_outliers) else "")
