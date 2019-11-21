import nmap
import json
import sys

#print("Hostname veya IP giriniz: ")
#Hostname_or_IP = str(input())
nm = nmap.PortScanner()

nm.scan(str(sys.argv[1]),arguments='-O')
#print(str(sys.argv) )
keys = ["Hostname","State","Os","Ports"]
sub_keys = ["Service","State"]
#print(nm.all_hosts()[0].hostname())
#print(m['scan']['172.217.169.174']['hostnames'][0]['name'])
#print(m['scan']['172.217.169.174']['status']['state'])
#print(nm[nm.all_hosts()[0]].hostname())
#print(nm[nm.all_hosts()[0]].state())
#print(m['scan']['172.217.169.174']['osmatch'][0]['osclass'][0]['osfamily'])
p = []
for host in nm.all_hosts():

	values = [nm[host]['hostnames'][0]['name'], nm[host]['status']['state']]

	if nm[host]['osmatch']: 
		if nm[host]['osmatch'][0]['osclass']:
			if nm[host]['osmatch'][0]['osclass'][0]['osfamily']:
				values += [nm[host]['osmatch'][0]['osclass'][0]['osfamily']]
	else:
		values += ["Unknown"]		
	
	
	for protocol in nm[host].all_protocols():
		lport = nm[host][protocol].keys()

		for port in lport:
			sub_values = [nm[host][protocol][port]['name'], nm[host][protocol][port]['state']]
			b = dict(zip(sub_keys,sub_values))
			p += [{port: b}]

	values += [p]

	output = dict(zip(keys,values))

print(json.dumps(output))	



