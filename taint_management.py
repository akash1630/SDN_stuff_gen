import time
import random as random
import pprint
from pox.lib.recoco import Timer
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
import socket
import threading
from threading import Thread

from pox.openflow.of_json import *
#import taint_db_impl

log = core.getLogger()
mac_port_dict = {}                                          #mapping for destination mac addr and egres port
protected_resources = ["00:00:00:00:00:03"]                 #list of protected resources
tainted_hosts = {}
tainted_hosts_ports = {}
suspected_hosts = []                                        #list of suspected hosts acting as pivots
spawned_threads_send = {}
mac_ip_map = {}
ip_mac_map = {}
waiting_for_message = []
tracked_flows = {}
check_for_stats_ctr = 1
data_recvd_from_protected = {}

#function to flood packets
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

def drop_packet(event):
  msg = of.ofp_packet_out(in_port=event.ofp.in_port)
  log.debug("dropping packet for buffer_id " + str(event.ofp.buffer_id))
  if event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None:
    msg.buffer_id = event.ofp.buffer_id
  else:
    if event.ofp.data:
      return
    msg.data = event.ofp.data

  msg.actions.append(of.ofp_action_output(port = of.OFPP_TABLE))
  event.connection.send(msg)

#function to add a host to the tainted list
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

#function to delete flow entries for a tainted host from all switches
def delete_flow_entries(event, packet, host):
  #if (host_address not in protected_resources)
  log.debug("deleting flow table entries for " + str(host))
  msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
  #msg.priority = 65635
  msg.match.dl_src = host
  event.connection.send(msg)
  for conn in core.openflow.connections:
    #log.debug("********* sending a flow removal message to switch : %s ", dpidToStr(conn.dpid))
    conn.send(msg)
  #log.debug("successfully sent delete flow messages!!!!!!")

def isolate_host(host):
  log.debug('----------------isolating host : ' + host + ' -------------')
  

#function to prune the tainted hosts list
def prune_tainted_list():
  log.debug("****** pruning tainted hosts list **********")
  marked_for_deletion = []
  get_flow_stats()
  pprint.pprint(tracked_flows)
  pprint.pprint(data_recvd_from_protected)
  for key in tracked_flows.keys():
    host = (key.split('-'))[0]
    log.debug('   ******* check for host : ' + host)
    if data_recvd_from_protected.has_key(host):
      if data_recvd_from_protected[host] >= .95*tracked_flows[key][0] and data_recvd_from_protected[host] <= 1.1*tracked_flows[key][0]:
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
    if (key not in suspected_hosts) and (time.time() - tainted_hosts[key] >= 201):
      #if time.time() - last_watermarked_flow_time[key] >= 121:
      #get_flow_stats(key)
      marked_for_deletion.append(key)

  for host in marked_for_deletion:
    del tainted_hosts[host]
  log.debug(" ****** deleted %i hosts from the tainted list *********", len(marked_for_deletion))


def send_message(ip, port):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  host = str(ip)
  port = 8080
  sock.settimeout(100)
  sock.connect((host,port))
  r=input('taint, ' + host + ', '+ str(port)) 
  log.debug('##### sending taint message : ' + 'taint, ' + host + ', '+ str(port))
  sock.send(r.encode())
  data = ''
  waiting_for_ack = 1
  while waiting_for_ack: 
    data = sock.recv(1024).decode()
    if (data.find('ack') >= 0 and data.find(str(ip)) >=0 and data.find(str(port)) >= 0): 
      print (data + '    received ack!!')
      waiting_for_ack = 0
  sock.close ()

def listen_for_messages():
  serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  serversock.bind(('localhost', 8080))
  serversock.listen(30)
  while 1:
    (clientsock, addr) = serversock.accept()
    print '...connected from:', addr
    t = Thread(target = receive_data, args = (clientsock, addr))
    spawned_threads_receive[ip_mac_map[addr]] = t
    t.start()

def receive_data(clientsock,addr):
  send_pending = 1
  while send_pending:
    data = clientsock.recv(1024)
    print 'data:' + repr(data)
    if not data: break
    data_split = data.split(',')
    if data.find('pivot') >= 0:
      for el in data_split:
        el.strip()
      host = data_split[1]
      port = int(data_split[2])
      add_to_tainted_hosts(host)
      append_to_tainted_ports(host, port)
      suspected_hosts.append(host)
      isolate_host(host)
      log.debug(' ######## suspected pivot ######### ' + host)
      clientsock.send(response('ack, ' + host + ', '+ str(port)))
      print 'sent:' + repr(response(''))
      send_pending = 0
      break
    else:
      clientsock.send(response('ack, ' + host + ', '+ str(port)))
      print 'sent:' + repr(response(''))
      send_pending = 0
      break
  clientsock.close()

def get_flow_stats():
  for conn in core.openflow.connections:
    log.debug("********* requesting flow stats from switch : %s :", dpidToStr(conn.dpid))
    conn.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
  

def _handle_flowstats_received(event):
  stats = flow_stats_to_list(event.stats)
  log.debug("FlowStatsReceived from %s: %s", 
    dpidToStr(event.connection.dpid), stats)

  
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

def _handle_PacketIn (event):

  global forward_rule_set
  global backward_rule_set
  global mac_port_dict
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

  log.debug("packet in buffer_id check : " +str(event.ofp.buffer_id))

  dest_eth_addr = str(packet.dst)
  src_eth_addr = str(packet.src)
  key = src_eth_addr + dest_eth_addr
  srcip = ''
  dstip = ''

  if src_eth_addr in suspected_hosts:
    delete_flow_entries(event, packet, packet.src)
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

  tcp = packet.find("tcp")
  if tcp:
    #log.debug("TCP pakcet! - SYN : %d   FIN: %d  ACK: %d ", tcp.SYN, tcp.FIN, tcp.ACK)
    srcport = tcp.srcport
    dstport = tcp.dstport
    if tcp.ACK:
      log.debug("!!!!!!   TCP ack packet  %s   !!!!!!", key)
      #flood_packet(event, of.OFPP_ALL)
      #mac_port_dict[packet.src] = event.port
      is_tcp_ack = 1


  #log.debug("packet forwarding  " + src_eth_addr + "  " + dest_eth_addr)
  is_tcp_ack = 0
  if is_tcp_ack == 0:
    if (dest_eth_addr in protected_resources):
      log.debug("***traffic going to protected resource***")

    elif (tainted_hosts.has_key(dest_eth_addr)):
      log.debug("***traffic going to Tainted host ***")

    if (src_eth_addr in protected_resources):
      if(dest_eth_addr in protected_resources):
        log.debug("protected to protected communication")
        skip_add_to_dict_dest = 0
      else:
        add_to_tainted_hosts(dest_eth_addr)
        append_to_tainted_ports(dest_eth_addr, dstport)
        delete_flow_entries(event, packet, packet.dst)
        t = Thread(target = send_message, name = 'send_thread' + dest_eth_addr, args = (dstip, dstport))
        spawned_threads_send[dest_eth_addr] = t
        #waiting_for_message.append(dest_eth_addr)
        t.start()


    elif(tainted_hosts.has_key(src_eth_addr) and (dest_eth_addr not in protected_resources)):
      if not tainted_hosts.has_key(dest_eth_addr):
        delete_flow_entries(event, packet, packet.dst)
      add_to_tainted_hosts(dest_eth_addr)
      append_to_tainted_ports(dest_eth_addr, dstport)
      t = Thread(target = send_message, name = 'send_thread' + dest_eth_addr, args = (dstip, dstport))
      spawned_threads_send[dest_eth_addr] = t
      #waiting_for_message.append(dest_eth_addr)
      t.start()
      #delete_flow_entries(event, packet, packet.dst)

  if (skip_add_to_dict_dest == 0) and (skip_add_to_dict_src == 0):
    log.debug("  adding to dictionary skip_add_to_dict_src is %i and skip_add_to_dict_dest is %i", skip_add_to_dict_src, skip_add_to_dict_dest)
    mac_port_dict[packet.src] = event.port
    if packet.dst not in mac_port_dict:
      log.debug("flooding to all ports as no entry in dictionary")
      flood_packet(event, of.OFPP_ALL)
    else:
      port = mac_port_dict[packet.dst]
      log.debug("setting a flow table entry as matching entry found in dict - " + src_eth_addr + "    " + dest_eth_addr)
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, event.port)
      msg.priority = 1009
      msg.actions.append(of.ofp_action_output(port = port))
      msg.data = event.ofp
      event.connection.send(msg)
  elif (skip_add_to_dict_dest == 1) and (skip_add_to_dict_src == 0):
    log.debug("  ready to flood. skip_add_to_dict_src is %i and skip_add_to_dict_dest is %i", skip_add_to_dict_src, skip_add_to_dict_dest)
    flood_packet(event, of.OFPP_ALL)


def _handle_ConnectionUp (event):
  log.debug("[!] HubACLs v0.0.1 Running %s", dpidToStr(event.dpid))

def launch ():
  Timer(50, prune_tainted_list, recurring = True)
  #Timer(300, delete_flows_for_watermark_detection, recurring = True)
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn",_handle_PacketIn)
  core.openflow.addListenerByName("FlowStatsReceived", _handle_flowstats_received) 
  thr = Thread(target = listen_for_messages, name = 'listen_for_messages')
  thr.start()

