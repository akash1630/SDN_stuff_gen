import threading
import psutil
import SocketServer
import logging
import ipaddr
import TaintClass
import time

from threading import Thread
from ConnIdent import ConnThread
from colorama import Fore, Back, Style, init

from colorama import Fore, Back, Style, init
from utils import GREEN, RED, BLUE, YELLOW


CHK_DELAY = 1
FNAME ='/tmp/host.db'

###############################################################################
# ListenThread: Listen for a Taint Message From the SDN Controller
##############################################################################
class ListenThread(threading.Thread):
	def __init__(self,host,port):
		try:
			Thread.__init__(self)
	        	self.host='0.0.0.0'
	        	self.port=port
	        	self.server = SocketServer.TCPServer((self.host,self.port), ListenHandler)
			self.logger = logging.getLogger('ListenMon')
			self.logger.debug(GREEN+'[+] Listener Initialized.')
			self.connT = ConnThread()
			self.connT.start()
		except Exception as e:
			self.logger = logging.getLogger('ListenMon')
			self.logger.error(RED+'[!] Failed to Initialize: '+str(e))

    	def run(self):
		try:
			self.server.allow_reuse_address = True 
			#self.server.server_bind()     
			#self.server.server_activate() 
	        	self.server.serve_forever()
		except Exception as e:
			self.logger.error(RED+'[!] Failed Run: '+str(e))

	def end(self):
		try:
			self.logger = logging.getLogger('ListenMon')
			self.logger.info(RED+'[!] Shutting Down SocketServer')
			self.server.shutdown()
		except Exception as e:
			self.logger.error(RED+'[!] Failed to Shutdown() Server: '+str(e))


###############################################################################
# HandleThread: Handles Message from SDN Controller
##############################################################################
class ListenHandler(SocketServer.StreamRequestHandler):    

    def later_check(self,lport,rport,rhost):
	try:
		self.logger = logging.getLogger('ListenMon')
		while True:
			pid=self.connT.retPid(lport,rport,rhost)
			if (pid > 1):
				self.logger.info(YELLOW+'[!] Found corresponding pid='+str(pid)+". Tainting.")
				self.taintDb.taint_pid(pid)
				return
			else:
				time.sleep(CHK_DELAY)
	except Exception as e:
		self.logger.info(RED+'[-] Failed Later_Check: '+str(e))

    
    def handle(self):
	try:
		self.logger = logging.getLogger('ListenMon')
		self.laterCheck = None
	    	self.taintDb = TaintClass.TaintDb(FNAME)
	        self.data = self.rfile.readline().strip()
		self.connT = ConnThread()
		self.connT.start()
	        ctl_msg = self.data.split(',')
	        if ('taint' in ctl_msg[0].lower()):
		        rhost = ipaddr.IPAddress(ctl_msg[1])
		        rport = ctl_msg[2]
			lport = ctl_msg[3]

		msg="[+] Rcvd Tainted Conn: "+str(self.data)
	       	self.logger.info(BLUE+msg)

		if ((rhost) and (int(rport) > 0) and (int(rport) < 65535)):
			rtn_msg = 'ack,'+str(rhost)+','+str(rport)+","+str(lport)+'\n'
		        self.wfile.write(rtn_msg)
		        self.wfile.close()
			pid=self.connT.retPid(lport,rport,rhost)
			if (pid > 1):
				self.logger.info(YELLOW+'[+] Found corresponding pid='+str(pid)+". Tainting.")
				self.taintDb.taint_pid(pid)
			else:
				self.logger.debug('[-] Could Not Find Corresponding Process. Checking Later.')
				self.later_check(lport,rport,rhost)
	except Exception as e:
			self.logger.error('[!] Failed Handler: '+str(e))


