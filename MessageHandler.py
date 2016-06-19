import socket
import threading
import SocketServer

log = core.getLogger()

class ThreadedMessageHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        try:
		    self.data = self.rfile.readline().strip()
	        host_msg = self.data.split(',')
	        if ('taint' in host_msg[0].lower()):
		        rhost = ipaddr.IPAddress(host_msg[1])
		        rport = host_msg[2]

			log.debug("[+] Rcvd Tainted Conn: "+str(self.data))

			if ((rhost) and (int(rport) > 0) and (int(rport) < 65535)):
				rtn_msg = 'ack,'+str(rhost)+','+str(rport)+","+str(lport)+'\n'
			        self.wfile.write(rtn_msg)
			        self.wfile.close()
		except Exception as e:
				self.logger.error('[!] Failed Handler: '+str(e))


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class ListenThread():
	def __init__(self,host,port):
		try:
	        self.host='0.0.0.0'
	        self.port=port
	        self.server = ThreadedTCPServer((self.host,self.port), ThreadedMessageHandler)

		    # Start a thread with the server -- that thread will then start one
		    # more thread for each request
		    server_thread = threading.Thread(target=server.serve_forever)
		    # Exit the server thread when the main thread terminates
		    server_thread.daemon = True
		    server_thread.start()
		    print "Server loop running in thread:", server_thread.name