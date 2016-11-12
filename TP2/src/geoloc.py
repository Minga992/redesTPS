import re
import json
from urllib2 import urlopen
import sys
import csv

# data = str(urlopen('http://checkip.dyndns.com/').read())
# IP = re.compile(r'(\d+.\d+.\d+.\d+)').search(data).group(1)
# IP = '155.232.6.130'
# url = 'http://ip-api.com/json/' + IP
# response = urlopen(url)
# data = json.load(response)

# org=data['org']
# city = data['city']
# country=data['country']
# region=data['regionName']
# lat=data['lat']
# lon=data['lon']

# print 'Your IP detail\n '
# print 'IP : {4} \nRegion : {1} \nCountry : {2} \nCity : {3} \nOrg : {0} \nLat : {5} \nLon : {6}'.format(org,region,country,city,IP,lat,lon)

def geoloc_ips(ips):

	coords = []

	for ip in ips:
		
		url = 'http://ip-api.com/json/' + ip
		response = urlopen(url)
		data = json.load(response)

		if (data['status'] == 'success'):

			lat=data['lat']
			lon=data['lon']

			latLon = {"lat": lat, "lng": lon}

			coords.append(latLon)

	return coords

def parse_input_file(filename):
	ips = []
	with open(filename, 'rb') as csvfile:
		next(csvfile, None)
		reader = csv.reader(csvfile, delimiter='\t')
		for row in reader:
			ip = row[1]
			ips.append(ip)
	return ips

if __name__ == '__main__':

	if(len(sys.argv) != 2):
		print "debe pasar el nombre del archivo de entrada como parametro"
	else:
		ips = parse_input_file(sys.argv[1])
		coords = geoloc_ips(ips)

		print json.dumps(coords)
