import threading
import os
import logging
import TaintClass
import utils

from threading import Thread
from netfilterqueue import NetfilterQueue
from scapy.all import *

from colorama import Fore, Back, Style, init
from utils import GREEN, RED, BLUE, YELLOW

FNAME ='/tmp/host.db'
PROC_TCP = "/proc/net/tcp"

#ProcHashTable = {}
#count = 0

###############################################################################
# ConnThread: Resolves Connections to PIDs
##############################################################################

class ConnThread(threading.Thread):
	def __init__(self):
		try:
	   		Thread.__init__(self)
	        	self.running = True
	                self.logger = logging.getLogger('ConnIdent')
	                self.logger.debug(GREEN+'[+] ConnIdent Initialized.')
			self.ConnTable = {}
		       	return
		except Exception as e:
			self.logger = logging.getLogger('ConnIdent')
			self.logger.error(RED+'[!] Failed to Initialize: '+str(e))
	
    	def run(self):
		try:
			while (self.running):
				self.poll()
		except Exception as e:
			self.logger.error(RED+'ConnIdent Failed: '+str(e))

	def newConn(self,lport,rport,rhost):
		if self.ConnTable.has_key((int(lport),int(rport),str(rhost))):
			return False
		else:
			return True

	def retPid(self,lport,rport,rhost):
		if self.ConnTable.has_key((int(lport),int(rport),str(rhost))):
			return self.ConnTable[(int(lport),int(rport),str(rhost))]
		else:
			return -1

	def poll(self):
		try:
			import utils
    			content=utils._load()
  			for line in content:
        			line_array = utils._remove_empty(line.split(' '))     
        			l_host,l_port = utils._convert_ip_port(line_array[1]) 
       				r_host,r_port = utils._convert_ip_port(line_array[2]) 
        			inode = line_array[9]                           
        			pid = utils._get_pid_of_inode(inode) 
 				if (pid > 1):
					#print GREEN+"{"+str(pid)+"} "+str(l_port)+"<->"+str(r_host)+":"+str(r_port)                 
					self.ConnTable[(int(l_port),int(r_port),str(r_host))]=int(pid)
		except Exception as e:
			self.logger.error(RED+'ConnIdent Poll Fail: '+str(e))

	def end(self):
     		self.running = False
