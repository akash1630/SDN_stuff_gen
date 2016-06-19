
import threading
import logging
import pexpect
import TaintClass
import os.path
import sys

from threading import Thread
from colorama import Fore, Back, Style, init
from utils import GREEN, RED, BLUE, YELLOW

FNAME ='/tmp/host.db'
WHITELIST = ["/var/","/sbin/","/bin","/usr/sbin","/usr/bin","/usr/lib","/lib",FNAME]

###############################################################################
# ProcThread: Execute 'fatrace', returning open files and owning pids.
# Inserts all results (pid, file, perms) into TaintDB
##############################################################################
class ProcThread(threading.Thread):
	def __init__(self):
		try:
	   		Thread.__init__(self)
	        	self.running = True
	                self.logger = logging.getLogger('ProcMon')
	                self.logger.debug(GREEN+'[+] ProcMonitor Initialized.')
		       	return
		except Exception as e:
			self.logger = logging.getLogger('ProcMon')
			self.logger.error(RED+'[!] Failed to Initialize: '+str(e))
	
    	def run(self):
		try:
			self.taintDb = TaintClass.TaintDb(FNAME)
	   		while (self.running):
				try:
					child = pexpect.spawn('fatrace',timeout=None)
					child.maxsize = 1
					for output in child:
						WLIST = False
		            			res = output.strip().split(' ')
						for dirname in WHITELIST:
							if (dirname in str(res[2])):
								WLIST = True
						if ((not WLIST) and (os.path.isfile(res[2]))):		
		            				pid=res[0][res[0].find("(")+1:res[0].find(")")]
							# if PID Tainted #
							msg = "[!] Opening "+str(res[2])+" "+str(res[1])+" by PID: "+str(pid)
							self.logger.debug(msg)
							# If PID is already tainted, taint the File						
							if (self.taintDb.is_tainted_p(pid)):
								msg = "[!] PID "+str(pid)+" tainted record for file: "+str(res[2])+" "+str(res[1])
								self.logger.info(YELLOW+msg)
								self.taintDb.insert_db(pid,res[2],res[1],True) 
							# If File is already tainted, taint the PID		
							elif (self.taintDb.is_tainted_f(str(res[2]))):
								msg = "[!] File: "+str(res[2])+" tainted record for pid: "+str(pid)
								self.taintDb.taint_pid(pid)
								self.taintDb.insert_db(pid,res[2],res[1],True) 
							# Otherwise insert as untainted		
							else:
								self.taintDb.insert_db(pid,res[2],res[1],False) 
				except Exception as e:
					self.logger.error(RED+'Pexpect Re-Spawning: '+str(e))
					
		except Exception as e:
			self.logger.error(RED+'ProcThread Failed: '+str(e))

	def end(self):
     		self.running = False
