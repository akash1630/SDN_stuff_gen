import threading
import os
import logging
import TaintClass
import utils
import socket

from ConnIdent import ConnThread
from threading import Thread
from netfilterqueue import NetfilterQueue
from scapy.all import *
from colorama import Fore, Back, Style, init
from utils import GREEN, RED, BLUE, YELLOW

from netifaces import interfaces, ifaddresses, AF_INET

MY_ADDRS = []
for ifaceName in interfaces():
    addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP addr'}] )]
    for addr in addresses:
	MY_ADDRS.append(addr)

FNAME ='/tmp/host.db'
PROC_TCP = "/proc/net/tcp"
SYN_DELAY = .01
SDN_IP = '192.168.158.1'
SDN_PORT = 8888

###############################################################################
# NetThread: Installs IN/OUT NetFilter Rules and Monitors for TCP SYNs
##############################################################################

class NetThread(threading.Thread):
	def __init__(self):
		try:
	   		Thread.__init__(self)
	        	self.running = True
	                self.logger = logging.getLogger('NetMon')
	                self.logger.debug(GREEN+'[+] NetMonitor Initialized.')
			self.connT = ConnThread()
			self.connT.start()
		except Exception as e:
			self.logger = logging.getLogger('NetMon')
			self.logger.error(RED+'[!] Failed to Initialize: '+str(e))
	
###############################################################################
# Handle_Pkt: Checks PKT against the naughty list of PIDs
##############################################################################
	def handle_pkt(self,p):
		try:
	    		pkt = IP(p.get_payload())

	   		if ((pkt.haslayer(TCP)) and (pkt['TCP'].flags==0x02) and (int(pkt['TCP'].dport)==int(9999))):
				self.logger.info(BLUE+"[+] Permitting SDN Message Through NetFilter.")			
	   		elif ((pkt.haslayer(TCP)) and (pkt['TCP'].flags==0x02) and (int(pkt['TCP'].dport)!=int(8888))):
				if (pkt.src in MY_ADDRS):
					lport = int(pkt['TCP'].sport)
					rport = int(pkt['TCP'].dport)
					rhost = str(pkt.dst)
					msg="[+] Detected OUTBOUND TCP-SYN: "+str(lport)+","+"->"+str(rhost)+":"+str(rport)
					self.logger.info(BLUE+msg)

				else:
					r_port = int(pkt['TCP'].sport)
					r_host = str(pkt.src)
					lport = int(pkt['TCP'].dport)
					rhost = str("0.0.0.0")
					rport = int(0)
					msg="[+] Detected INBOUND TCP-SYN: "+str(r_host)+":"+str(r_port)+"->"+str(lport)
					self.logger.info(BLUE+msg)
				
				time.sleep(SYN_DELAY)				
				pid=self.connT.retPid(lport,rport,rhost)
				self.taintDb = TaintClass.TaintDb(FNAME)
				
				if (pid < 2):
					count = 0					
					while ((count < 5) and (pid < 2)):
						count = count +1
						pid=self.connT.retPid(lport,rport,rhost)
						time.sleep(1)
				
				msg="[+] PID ={"+str(pid)+"} for SYN:"+str(lport)+","+"->"+str(rhost)+":"+str(rport)				
				self.logger.debug(BLUE+msg)

				if (self.taintDb.is_tainted_p(pid)):
					self.logger.info(YELLOW+'[!] Tainted Connection: '+str(lport)+"<->"+str(rhost)+":"+str(rport))
					self.logger.info(YELLOW+'[!] Connection Tainted By PID: '+str(pid))
					self.send_ctl_msg(rhost,rport,lport)
				

			p.accept()
		except Exception as e:
			self.logger.error(RED+'[!] Failed to Handle Pkt: '+str(e))

	def send_ctl_msg(self,rhost,rport,lport):
		# THIS IS HACK, NEED TO CLEANUP
		# CAN'T USE SOCKET HERE SINCE PKT_HANDLE() IS WAITING ON IT AND QUEUES ITSELF RECUSRIVELY
		# SO INSTEAD DOING A ECHO "CTL_MSG" | nc sdn_ip sdn_port &
		# WILL FIX LATER		
		try:
			msg = "taint,"+str(rhost)+","+str(rport)+","+str(lport)+"\n"
			cmd = "echo \""+msg+"\" | nc "+SDN_IP+" 9999 &"
			os.system(cmd)
		except Exception as e:
			self.logger.error(RED+'[!] Send_ctl_msg Failed: '+str(e))

						
    	def run(self):
		try:
			while (self.running):

				nfqueue = NetfilterQueue()
				nfqueue.bind(1, self.handle_pkt)
			        nfqueue.run()

		
		except Exception as e:
			self.logger.error(RED+'NetFilter Failed: '+str(e))

	def end(self):
     		self.running = False
