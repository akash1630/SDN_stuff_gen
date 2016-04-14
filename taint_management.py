import numpy as np
import scipy as sp
import scipy.stats as stats
import time
import random as random
import pprint
from pox.lib.recoco import Timer
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
#import taint_db_impl

log = core.getLogger()
mac_port_dict = {}                                          #mapping for destination mac addr and egres port
protected_resources = ["00:00:00:00:00:03"]                 #list of protected resources
tainted_hosts = {}                                          #dictionary: key - tainted hosts , value - time of taint 
suspected_hosts = []                                        #list of suspected hosts acting as pivots
flow_last_packet_received_time = {}                                  #dictionary: key - suspected flows being monitored , value - time since last packet 
flow_ipds = {}                                              #dictionary: key - suspected flows being monitored , value - ipd arrays
flow_last_packet_sent_time = {}
flow_packets_queues = {}


#function to flood packets
def flood_packet (event, dst_port = of.OFPP_ALL):
  msg = of.ofp_packet_out(in_port=event.ofp.in_port)
  log.debug("flooding packet for buffer_id " + str(event.ofp.buffer_id))
  if event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None:
    msg.buffer_id = event.ofp.buffer_id
  else:
    if event.ofp.data:
      return
    msg.data = event.ofp.data

  msg.actions.append(of.ofp_action_output(port = dst_port))
  event.connection.send(msg)


#function to add a host to the tainted list
def add_to_tainted_hosts(host):
  global tainted_hosts
  if (tainted_hosts.has_key(host)) or (host in protected_resources):
    log.debug("host already present in tainted list. Refreshing time")
    tainted_hosts[host] = time.time()
  else:
    tainted_hosts[host] = time.time()
    log.debug("added %s to tainted_hosts list ", host)
  pprint.pprint(tainted_hosts)

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

def delete_flows_for_watermark_detection():
  for host in tainted_hosts:
    log.debug("****** deleting flows for tainted hosts to check for correlation ***" + str(host))
    msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
    msg.match.dl_src = host
    for conn in core.openflow.connections:
      conn.send(msg)

#function called after a delay to flood packets
def delay_and_flood(event):
  log.debug("++++++++++ flooding after wait ++++++++++++")
  flood_packet(event, of.OFPP_ALL)

#function tp prune the tailted hosts list
def prune_tainted_list():
  log.debug("****** pruning tainted hosts list **********")
  marked_for_deletion = []
  for key in tainted_hosts.keys():
    if (key not in suspected_hosts) and (time.time() - tainted_hosts[key] >= 121):
      #if time.time() - last_watermarked_flow_time[key] >= 121:
        marked_for_deletion.append(key)

  for host in marked_for_deletion:
    del tainted_hosts[host]
  log.debug(" ****** deleted %i hosts from the tainted list *********", len(marked_for_deletion))

#function to update the interpacket-delay arrical times array for a given flow
def update_ipd_arrays(src_eth_addr, dest_eth_addr):
  key = src_eth_addr + dest_eth_addr
  log.debug(" updating ipd array for : " + key)
  curr_time = time.time()
  packet_delay = 0
  if flow_last_packet_received_time.has_key(key):
    packet_delay = curr_time - flow_last_packet_received_time[key]
  flow_last_packet_received_time[key] = curr_time
  if flow_ipds.has_key(key):
    flow_ipds.get(key).append(packet_delay)
  else:
    flow_ipds[key] = []


def release_packets(key):
  log.debug("releasing packet")
  if flow_packets_queues.has_key(key):
    event = (flow_packets_queues.get(key)).pop()
    flood_packet(event, of.OFPP_ALL)

def _handle_PacketIn (event):

  global forward_rule_set
  global backward_rule_set
  global mac_port_dict
  global protected_resources
  global tainted_hosts
  skip_add_to_dict_dest = 0
  skip_add_to_dict_src = 0
  mu_sigma_vals = [0,0]
  is_correlated = 0
  is_tcp_ack = 0

  packet =event.parsed

  log.debug("packet in buffer_id check : " +str(event.ofp.buffer_id))

  dest_eth_addr = str(packet.dst)
  src_eth_addr = str(packet.src)
  key = src_eth_addr + dest_eth_addr

  ipv4_pack = packet.find("ipv4")
  if ipv4_pack:
    log.debug("IP packet in transit from  "+str(ipv4_pack.srcip)+"<->"+str(ipv4_pack.dstip))

  tcp = packet.find("tcp")
  if tcp:
    #log.debug("TCP pakcet! - SYN : %d   FIN: %d  ACK: %d ", tcp.SYN, tcp.FIN, tcp.ACK)
    if tcp.ACK:
      log.debug("!!!!!!   TCP ack packet  %s   !!!!!!", key)
      flood_packet(event, of.OFPP_ALL)
      is_tcp_ack = 1


  #log.debug("packet forwarding  " + src_eth_addr + "  " + dest_eth_addr)
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
        #log.debug("*** traffic from protected resource***")
        #log.debug("***FLow rule not added to switches. Send to controller***")
        add_to_tainted_hosts(dest_eth_addr)
        #skip_add_to_dict_src = 1
        #flood_packet(event, of.OFPP_ALL)
        delete_flow_entries(event, packet, packet.dst)
         #send_packet(event, of.OFPP_ALL)

    elif(tainted_hosts.has_key(src_eth_addr) and (dest_eth_addr not in protected_resources)):
      add_to_tainted_hosts(dest_eth_addr)
      #skip_add_to_dict_src = 1
      #flood_packet(event, of.OFPP_ALL)
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
  Timer(120, prune_tainted_list, recurring = True)
  #Timer(300, delete_flows_for_watermark_detection, recurring = True)
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn",_handle_PacketIn)
