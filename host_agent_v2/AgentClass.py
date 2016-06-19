import logging
import os
import os.path
import sys
import time

from ListenClass import ListenThread
from ProcClass import ProcThread
from NetClass import NetThread

from colorama import Fore, Back, Style, init
from utils import GREEN, RED, BLUE, YELLOW

LOG_LEVEL = logging.DEBUG
FNAME ='/tmp/host.db'
LPORT = 8888
DELAY = 1

###############################################################################
# AgentClass: Starts Up the SDN Listener, Proc Monitor, and Net Monitor
##############################################################################

class Agent:

	def __init__(self):
		try:
               		self.running = True
              		logging.basicConfig(level=LOG_LEVEL)
               		self.logger = logging.getLogger('HostAgent')
              		self.logger.debug(GREEN+'[+] Agent Class Initialized.')
			self.start_listener()
			self.start_proc_monitor()
			self.start_net_monitor()
			#time.sleep(DELAY)
			#self.start_orphan_checker()
			    			
			while True:
				pass 

		except KeyboardInterrupt:
  			print RED+"[*] Terminating Agent"
			self.end()
  			print RED+"[*] Flushing IPTables"
			os.system("iptables -F")
  			print RED+"[*] Killing Fatrace"
			os.system("ps | grep fatrace | awk {'print $1'} | xargs kill -9")
  			print RED+"[*] Killing Python"
			os.system("ps | grep python  | awk {'print $1'} | xargs kill -9")


	def start_listener(self):
		self.listenT = ListenThread('0.0.0.0',8888)
		self.listenT.daemon = True
		self.listenT.start()

	def start_proc_monitor(self):
		self.procT = ProcThread()
		self.procT.daemon = True
	    	self.procT.start()

	def start_net_monitor(self):
		self.netT = NetThread()
		self.netT.daemon = True
		self.netT.start()

	def end(self):
		self.listenT.end()
		self.procT.end()
		self.netT.end()

def root_check():
	if not os.geteuid()==0:
    		sys.exit(RED+"[!] Exiting. Script must be run under UID=0")
	else:
		return
def del_db():
	os.system('rm -rf '+FNAME)

def pkill_fatrace():
	try:
		import os
		os.system('pkill fatrace')
	except:
		pass

def install_netfilter_rules():
	try:
		os.system('iptables -F')
		os.system('iptables -I OUTPUT -j NFQUEUE --queue-num 1')
		os.system('iptables -I INPUT -j NFQUEUE --queue-num 1')
	except Exception as e:
		sys.exit(RED+"[!] Error could not install netfilter rules "+str(e))

def binary_check():
	try:
		if (os.path.isfile('/usr/sbin/fatrace')):
			return True
		else:
		   	print RED+"[*] Necessary Binarys cannot be loaded. Try installing the following binaries."
			print RED+"[!] apt-get install fatrace"
			sys.exit(RED+"[!] Exiting.")

	except Exception as e:
		print RED+"[*] Error: "+str(e)
		sys.exit(RED+"[!] Exiting.")

def modules_check():
	try:
		import datetime
		import glob
		import ipaddr
		import logging
		import netfilterqueue
		import psutil
		import re
		import scapy.all
		import SocketServer
		import sqlite3
		import subprocess
		import threading
		import colorama
		import pexpect
		import netifaces

	except Exception as e:
		print RED+"[*] Error: "+str(e)
		print RED+"[*] Necessary Libs cannot be loaded. Try installing the following libraries."
		print RED+"[!] apt-get install python-netfilter python-logging python-scapy python-sqlite"
		print RED+"[-] python-ipaddr python-psutil python-subprocess python-pthreading "
		print RED+"[-] python-pexpect python-netifaces"
		sys.exit(RED+"[!] Exiting.")

def setup():
	del_db()
	pkill_fatrace()
	install_netfilter_rules()
	root_check()
	binary_check()
	modules_check()

if __name__ == '__main__':
	init(autoreset=True)
	setup()
    	logging.basicConfig(level=LOG_LEVEL,format='%(message)s')
    	agent = Agent() 


	


