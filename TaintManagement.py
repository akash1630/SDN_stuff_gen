import time
import random as random
import pprint
from pox.lib.recoco import Timer
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
import socket
import ipaddr
import threading
import SocketServer
from threading import Thread
import numpy as np
import scipy as sp

from pox.openflow.of_json import *

log = core.getLogger()
ip_port_dict_local = {}                  #mapping for destination mac addr and egres port
protected_resources = ["10.0.0.3"]       #list of protected resources
tainted_hosts = {}                       #dict: key - tainted hosts (ip addresses), val - timestamp
tainted_hosts_ports = {}                 #dict: key - tainted hosts (ip addresses), val - ports list
suspected_hosts = []                     #list of suspected hosts acting as pivots
spawned_threads_send = {}
spawned_threads_receive = {}
mac_ip_map = {}
ip_mac_map = {}
waiting_for_message = []
tracked_flows = {}
check_for_stats_ctr = 1
data_recvd_from_protected = {}
prune_counter = 0
samples = np.random.normal(250, 35, 1000)

#############################################################################
#define internal network here - ****IMPORTANT****
#############################################################################
internal_ips = "10.0.0.0/24"
developer_machines_ips = "10.0.0.0/28"
internal_network = ipaddr.IPNetwork(internal_ips)
developer_mcahines_network = ipaddr.IPNetwork(developer_machines_ips)


#############################################################################
#function to flood packets
#############################################################################
def flood_packet (event, dst_port = of.OFPP_ALL):
  msg = of.ofp_packet_out(in_port=event.ofp.in_port)
  #log.debug("flooding packet for buffer_id " + str(event.ofp.buffer_id))
  if event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None:
    msg.buffer_id = event.ofp.buffer_id
  else:
    if event.ofp.data:
      return
    msg.data = event.ofp.data

  msg.actions.append(of.ofp_action_output(port = dst_port))
  event.connection.send(msg)


##############################################################################
#function to drop packets for isolating pivots
##############################################################################
def drop_packet(event):
  msg = of.ofp_packet_out(in_port=event.ofp.in_port)
  #log.debug("dropping packet for buffer_id " + str(event.ofp.buffer_id))
  if event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None:
    msg.buffer_id = event.ofp.buffer_id
  else:
    if event.ofp.data:
      return
    msg.data = event.ofp.data

  #msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
  event.connection.send(msg)


#############################################################################
#function to add a host to the tainted list
#############################################################################
def add_to_tainted_hosts(host):
  global tainted_hosts
  if host in protected_resources:
    return
  if (tainted_hosts.has_key(host)):
    log.debug("host already present in tainted list. Refreshing time")
    #tainted_hosts[host] = time.time()
  else:
    tainted_hosts[host] = time.time()
    log.debug("added %s to tainted_hosts list ", host)
  pprint.pprint(tainted_hosts)


##############################################################################
#function to add/append tainted ports to the global dict
##############################################################################
def append_to_tainted_ports(host, port):
  global tainted_hosts_ports
  log.debug('Appending a new tainted port')
  if port > 0:
    if tainted_hosts_ports.has_key(host):
      if port not in tainted_hosts_ports[host]:
        tainted_hosts_ports[host].append(port)
    else:
      tainted_hosts_ports[host] = [port]
  pprint.pprint(tainted_hosts_ports)


##############################################################################
#function to delete flow entries for a tainted host from all switches
##############################################################################
def delete_flow_entries(host):
  log.debug("deleting flow table entries for " + str(host))
  msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
  #msg.priority = 65635
  msg.match.dl_type = 0x800
  msg.match.nw_src = host
  for conn in core.openflow.connections:
    conn.send(msg)

def isolate_host(host):
  log.debug('----------------isolating host : ' + host + ' -------------')
  

#################################################################################
#function to prune tainted list based on a distributed interval - NOT BEING USED
#################################################################################
def prune_tainted_list():
  global prune_counter
  global samples
  log.debug("****** pruning tainted hosts list **********")
  if(prune_counter%30 == 29):
    mu = random.uniform(250, 50)
    sigma = random.uniform(0, 35)
    mu_sigma_vals = [0,0]
    mu_sigma_vals[0] = mu
    mu_sigma_vals[1] = sigma
    samples = np.random.normal(mu, sigma, 1000)
    prune_counter = 0
  else:
    prune_counter =+ 1

  marked_for_deletion = []
  get_flow_stats()
  pprint.pprint(tracked_flows)
  pprint.pprint(data_recvd_from_protected)
  index = random.randint(0,999)
  log.debug("***** selected index : " + str(index) + "    and pruning interval : " + str(samples[index]) + " *****")
  for key in tracked_flows.keys():
    host = (key.split('-'))[0]
    log.debug('   ******* check for host : ' + host + "  and flow : " + key + "  traffic : " + str(tracked_flows[key][0]))
    if data_recvd_from_protected.has_key(host):
      if tracked_flows[key][0] >= data_recvd_from_protected[host] and tracked_flows[key][0] <= 1.15*data_recvd_from_protected[host]:
        log.debug('********** suspected pivot *********' + host)
        suspected_hosts.append(host)
        isolate_host(host)
      else:
        log.debug(' ******** deleting a flow from tracked flows as sizes do not correlate  - ' + key)
        del tracked_flows[key]
    else:
      log.debug('******* deleting a flow from tracked flows as no data info from protected_resources  - ' + key)
      del tracked_flows[key]
  for key in tainted_hosts.keys():
    if (key not in suspected_hosts) and (time.time() - tainted_hosts[key] >= samples[index]):
      #if time.time() - last_watermarked_flow_time[key] >= 121:
      #get_flow_stats(key)
      marked_for_deletion.append(key)

  for host in marked_for_deletion:
    del tainted_hosts[host]
    del data_recvd_from_protected[host]
  log.debug(" ****** deleted %i hosts from the tainted list *********", len(marked_for_deletion))


##############################################################################
#function to send taint message to hosts
##############################################################################
def send_message(ip, port):
  #log.debug('##### sending taint message : ' + 'taint, ' + str(ip) + ', '+ str(port))
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  #host = str(ip)
  host = '172.16.229.128'
  port = 8888
  sock.settimeout(100)
  #os.system('nc ')
  try:
    sock.connect((host,port))
    #r=input('taint, ' + host + ', '+ str(port)) 
    #r = input('taint,172.16.229.128,1339,8080')
    r = "taint,172.16.229.128,1339,8080"
    log.debug('##### sending taint message : ' + r)
    sock.sendall(r.encode())
    sock.shutdown(socket.SHUT_WR)
    data = ''
    waiting_for_ack = 1
    while waiting_for_ack:
      data = sock.recv(4096).decode()
      #log.debug('-----------reading data----------')
      #if (data.find('ack') >= 0 and data.find(str(ip)) >=0 and data.find(str(port)) >= 0): 
      if(data.find('ack') >= 0):
        log.debug('-------received ack!! -------' + data)
        waiting_for_ack = 0
    sock.close()
  except:
    log.debug(" Host port denied connection")
    sock.close()


##############################################################################
#function to start a listener thread
##############################################################################
def taint_msg_listener():
  log.debug('------- taint message listener thread setup start ------')
  listener = ListenThread('0.0.0.0',9999)
  listener.daemon = True
  listener.start()


##############################################################################
#function to request flow stats from switches
##############################################################################
def get_flow_stats():
  for conn in core.openflow.connections:
    log.debug("********* requesting flow stats from switch : %s :", dpidToStr(conn.dpid))
    conn.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

  
##############################################################################
#EVent handler for flow stats recieved event
##############################################################################
def _handle_flowstats_received(event):
  stats = flow_stats_to_list(event.stats)
  #log.debug("FlowStatsReceived from %s: %s", dpidToStr(event.connection.dpid), stats)
  log.debug("FlowStatsReceived from %s", dpidToStr(event.connection.dpid))
  
  for f in event.stats:

    if tainted_hosts.has_key(str(f.match.dl_src)) or str(f.match.dl_src) in protected_resources:
      print('***** storing statstics ******')
      bytes_count = 0
      flows_count = 0
      packets_count = 0
      dst = str(f.match.dl_dst)
      src = str(f.match.dl_src)
      bytes_count += f.byte_count
      packets_count += f.packet_count
      flows_count += 1

      if src in protected_resources:
        data_recvd_from_protected[dst] = bytes_count

      if not tracked_flows.has_key(src + '-' + dst):
        tracked_flows[src + '-' + dst] = [0,0,0]

      (tracked_flows.get(src + '-' + dst))[0] = bytes_count
      (tracked_flows.get(src + '-' + dst))[1] = packets_count
      (tracked_flows.get(src + '-' + dst))[2] = flows_count
      log.debug("traffic switch %s: %s bytes %s packets  %s flows", dpidToStr(event.connection.dpid), bytes_count, packets_count, flows_count)


#############################################################################
#Event handler for packet_in event
#############################################################################
def _handle_PacketIn (event):

  global forward_rule_set
  global backward_rule_set
  global ip_port_dict_local
  global protected_resources
  global tainted_hosts
  global mac_ip_map
  skip_add_to_dict_dest = 0
  skip_add_to_dict_src = 0
  mu_sigma_vals = [0,0]
  is_correlated = 0
  is_tcp_ack = 0
  srcport = 0
  dstport = 0


  packet =event.parsed
  #log.debug("packet in buffer_id check : " +str(event.ofp.buffer_id))

  dest_eth_addr = str(packet.dst)
  src_eth_addr = str(packet.src)
  key = src_eth_addr + '-' + dest_eth_addr
  srcip = ''
  dstip = ''

  if src_eth_addr in suspected_hosts:
    delete_flow_entries(packet.src)
    drop_packet(event)
    return

  ipv4_pack = packet.find("ipv4")
  if ipv4_pack:
    log.debug("IP packet in transit from  "+str(ipv4_pack.srcip)+"<->"+str(ipv4_pack.dstip))
    srcip = str(ipv4_pack.srcip)
    dstip = str(ipv4_pack.dstip)
    mac_ip_map[src_eth_addr] = srcip
    mac_ip_map[dest_eth_addr] = dstip
    ip_mac_map[srcip] = src_eth_addr
    ip_mac_map[dstip] = dest_eth_addr
    key = srcip + '-' + dstip

  tcp = packet.find("tcp")
  if tcp:
    #log.debug("TCP pakcet! - SYN : %d   FIN: %d  ACK: %d ", tcp.SYN, tcp.FIN, tcp.ACK)
    srcport = tcp.srcport
    dstport = tcp.dstport
    if tcp.ACK:
      log.debug("!!!!!!   TCP ack packet  %s   !!!!!!", key)
      #mac_port_dict[packet.src] = event.port
      is_tcp_ack = 1


  #log.debug("packet forwarding  " + src_eth_addr + "  " + dest_eth_addr)
  is_tcp_ack = 0
  if is_tcp_ack == 0:
    if (srcip in protected_resources):
      if(dstip in protected_resources):
        log.debug("protected to protected communication")
        skip_add_to_dict_dest = 0
      else:
        log.debug(" __________ Traffic from protected resource to normal host __________ ")
        taint_action(dstip, dstport)

    elif(tainted_hosts.has_key(srcip) and (dstip not in protected_resources)):
      log.debug("-------- Traffic coming from tainted host --------")
      if(tainted_hosts_ports.has_key(srcip)):
        if(srcport in tainted_hosts_ports[srcip]):
          log.debug("-------- traffic coming from a tainted port on a tainted host --------")
          taint_action(dstip, dstport)
        else:
          log.debug("------ CLean traffic from a tainted host---------- ")


  if (skip_add_to_dict_dest == 0) and (skip_add_to_dict_src == 0):
    log.debug("  adding to dictionary skip_add_to_dict_src is %i and skip_add_to_dict_dest is %i", skip_add_to_dict_src, skip_add_to_dict_dest)
    ip_port_dict_local[srcip] = event.port
    if dstip not in ip_port_dict_local:
      log.debug("flooding to all ports as no entry in dictionary")
      flood_packet(event, of.OFPP_ALL)
    else:
      port = ip_port_dict_local[dstip]
      log.debug("setting a flow table entry as matching entry found in dict - " + srcip + "    " + dstip)
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, event.port)
      msg.priority = 1009
      msg.actions.append(of.ofp_action_output(port = port))
      msg.data = event.ofp
      event.connection.send(msg)
  elif (skip_add_to_dict_dest == 1) and (skip_add_to_dict_src == 0):
    log.debug("  ready to flood. skip_add_to_dict_src is %i and skip_add_to_dict_dest is %i", skip_add_to_dict_src, skip_add_to_dict_dest)
    flood_packet(event, of.OFPP_ALL)


#############################################################################
#function to perform the taint operations
#############################################################################
def taint_action(ip, port):
  log.debug("<<<<<<<  Performing taint actions >>>>>>>>>>")
  add_to_tainted_hosts(ip)
  append_to_tainted_ports(ip, port)
  delete_flow_entries(ip)
  t = Thread(target = send_message, name = 'send_thread' + ip, args = (ip, port))
  #spawned_threads_send[] = t
  #waiting_for_message.append(dest_eth_addr)
  t.start()


#############################################################################
#function to check if the current tainted connection indicates pivoting
#############################################################################
def check_for_pivot(ip):
  log.debug("------ Checking if pivot (tainted connection to external network) ----------")
  ipaddr_to_check = ipaddr.IPAddress(ip)
  is_external = not (internal_network.Contains(ipaddr_to_check))
  return is_external


#############################################################################
#function to decde the action to be performed after pivot detection
#############################################################################
def decide_action_pivot(client_address):
  log.debug("*** Developer machine - Isolating " + client_address)
  #pass


#############################################################################
#Event handler for connectionUp event
#############################################################################
def _handle_ConnectionUp (event):
  log.debug("[!] HubACLs v0.0.1 Running %s", dpidToStr(event.dpid))


#############################################################################
#Launch method for the controller app
#############################################################################
def launch ():
  #Timer(50, prune_tainted_list, recurring = True)
  Timer(.5, taint_msg_listener, recurring = False)
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn",_handle_PacketIn)
  core.openflow.addListenerByName("FlowStatsReceived", _handle_flowstats_received) 
  #thr = Thread(target = taint_msg_listener, name = 'listen_for_messages')
  #thr.start()

class MessageHandler(SocketServer.StreamRequestHandler):
    def handle(self):
      try:
        log.debug("----- Receiving message from : " + str(self.client_address[0]) +" ------")
    	self.data = self.request.recv(1024).strip()
    	log.debug("received message : " + self.data)
	client_addr = str(self.client_address[0])
        host_msg = self.data.split(',')
        if ('taint' in host_msg[0].lower()):
            #rhost = ipaddr.IPAddress(host_msg[1])
      	    host_to_taint = host_msg[1]
            tainted_dest_port = host_msg[2]
            tainted_src_port = host_msg[3]

      	log.debug("[+] Rcvd Tainted Conn: "+str(self.data))

      	if ((host_to_taint) and (int(tainted_dest_port) > 0) and (int(tainted_dest_port) < 65535)):
        	if((int(tainted_src_port) > 0) and (int(tainted_src_port) < 65535)):
          		rtn_msg = 'ack,'+str(host_to_taint)+','+str(tainted_dest_port)+","+str(tainted_src_port)+'\n'
                	self.wfile.write(rtn_msg)
                	self.wfile.close()
                  	pivot = False
                  	pivot = check_for_pivot(host_to_taint)
                  	if(pivot):
                    		log.debug('######---- Pivot Detected : '+ client_addr + ' - check action---------------######')
                        	decide_action_pivot(client_addr)
                  	else:
                    		log.debug('------ tainted host sending tainted data to internal hosts ----------')
                	  	taint_action(host_to_taint, tainted_dest_port)

      except Exception as e:
	log.error('[!] Failed Handler: '+str(e))

class ListenThread(threading.Thread):
  def __init__(self,host,port):
    try:
      threading.Thread.__init__(self)
      self.host='0.0.0.0'
      self.port=port
      self.server = SocketServer.TCPServer((self.host,self.port), MessageHandler)
      log.debug(' -----    Listener Initialized.     ------')
    except Exception as e:
      log.error('----- Failed to Initialize: '+str(e))

  def run(self):
    try:
      self.server.allow_reuse_address = True
      log.debug('----running listener thread-----') 
      self.server.serve_forever()
    except Exception as e:
      log.error('Error during Run: '+str(e))

  def end(self):
    try:
      log.debug(' ------  SocketServer shutting down now -------')
      self.server.shutdown()
    except Exception as e:
      log.error('Failed to Shutdown SocketServer: '+str(e))