import socket
import threading
import SocketServer
from pox.core import core

log = core.getLogger()

class MessageHandler(SocketServer.StreamRequestHandler):
    def handle(self):
    	try:
    		log.debug("----- handling message ------")
		self.data = self.request.recv(1024).strip()
		log.debug("received message : " + self.data)
	        host_msg = self.data.split(',')
	        if ('taint' in host_msg[0].lower()):
		        #rhost = ipaddr.IPAddress(host_msg[1])
			tainted_host = host_msg[1]
		        tainted_port = host_msg[2]

			log.debug("[+] Rcvd Tainted Conn: "+str(self.data))

			if ((tainted_host) and (int(tainted_port) > 0) and (int(tainted_port) < 65535)):
				rtn_msg = 'ack,'+str(tainted_host)+','+str(tainted_port)+","'\n'
			        self.wfile.write(rtn_msg)
			        self.wfile.close()
	except Exception as e:
		log.error('[!] Failed Handler: '+str(e))

class ListenThread(threading.Thread):
	def __init__(self,host,port):
		try:
			threading.Thread.__init__(self)
	        	self.host='0.0.0.0'
	        	self.port=port
	        	self.server = SocketServer.TCPServer((self.host,self.port), MessageHandler)
			log.debug('------runing thread------')
			self.server.allow_reuse_address = True
			self.server.serve_forever()
			log.debug('[+] Listener Initialized.')
		except Exception as e:
			log.error('[!] Failed to Initialize: '+str(e))

    	def run(self):
		try:
			self.server.allow_reuse_address = True
			log.debug('----running thread-----') 
			#self.server.server_bind()     
			#self.server.server_activate() 
	        	self.server.serve_forever()
		except Exception as e:
			log.error('[!] Failed Run: '+str(e))

	def end(self):
		try:
			log.debug(RED+'[!] Shutting Down SocketServer')
			self.server.shutdown()
		except Exception as e:
			log.error('[!] Failed to Shutdown() Server: '+str(e))
