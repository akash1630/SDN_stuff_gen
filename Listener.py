import socket
import threading
import SocketServer
from pox.core import core

log = core.getLogger()

class MessageHandler(SocketServer.StreamRequestHandler):
    def handle(self):
    	try:
    		log.debug("----- handling message ------")
			self.data = self.rfile.readline().strip()
			log.debug("received message : " + self.data)
	        host_msg = self.data.split(',')
	        if ('taint' in host_msg[0].lower()):
		        rhost = ipaddr.IPAddress(host_msg[1])
		        rport = host_msg[2]

			log.debug("[+] Rcvd Tainted Conn: "+str(self.data))

			if ((rhost) and (int(rport) > 0) and (int(rport) < 65535)):
				rtn_msg = 'ack,'+str(rhost)+','+str(rport)+","+str(lport)+'\n'
			        self.wfile.write(rtn_msg)
			        self.wfile.close()
		cur_thread = threading.current_thread()
        response = "{}: {}".format(cur_thread.name, self.data)
        self.request.sendall(response)
	except Exception as e:
		log.error('[!] Failed Handler: '+str(e))

class ListenThread(threading.Thread):
	def __init__(self,host,port):
		try:
			Thread.__init__(self)
	        	self.host='0.0.0.0'
	        	self.port=port
	        	self.server = SocketServer.TCPServer((self.host,self.port), MessageHandler)
			log.debug('[+] Listener Initialized.')
		except Exception as e:
			log.error('[!] Failed to Initialize: '+str(e))

    	def run(self):
		try:
			self.server.allow_reuse_address = True 
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