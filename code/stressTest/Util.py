import random
import os.path

def checkFiles():
	d = os.path.isfile("/home/mininet/D-ITG-2.8.1-r1023/bin/ITGSend")
	a = os.path.isfile("/usr/bin/proxychains")
	b = os.path.isfile("/bin/nc")
	c = os.path.isfile("/usr/bin/cryptcat")

	if (not d):
		print "[!] D-ITG not found. Exiting."
		exit(-1)
	if (not a):
		print "[!] Proxychains not found. Exiting."
		exit(-1)
	if (not b):
		print "[!] NetCat not found. Exiting."
		exit(-1)
	if (not c):
		print "[!] CryptCat not found. Exiting."
		exit(-1)

def retRandomHost():
	hosts = ['h1','h2','h3','h4']
	return random.choice(hosts)

