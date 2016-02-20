import numpy as np
import time
import random as random
import pprint
from pox.lib.recoco import Timer
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr

log = core.getLogger()
syn_counter = 0
watermark_samples = []
watermark_samples.append(np.random.normal(1, 0.5, 1000))
mac_port_dict = {}
protected_resources = ["00:00:00:00:00:03"]
tainted_hosts = []
watermarks_received_on_hosts = {}
watermark_index = 0
watermarks_created_for_hosts = {}
for host in protected_resources:
  watermarks_created_for_hosts[host] = 0

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

def create_watermark(host):
  global watermark_samples
  global watermark_index
  global watermarks_created_for_hosts
  if watermarks_created_for_hosts.has_key(host):
    log.debug("host has watermark created already!")
    return watermarks_created_for_hosts.get(host)
  else:
    mu = random.uniform(0.5, 2.0)
    sigma = random.uniform(0.2, 0.9)
    log.debug("creating watermark array with params : "+ str(mu) + "    "+ str(sigma))
    samples = np.random.normal(mu, sigma, 1000)
    #watermark_samples = np.vstack((watermark_samples, samples))
    watermark_samples.append(samples)
    watermark_index = watermark_index + 1
    watermarks_created_for_hosts[host] = watermark_index
    pprint.pprint(watermarks_created_for_hosts)
    return watermark_index

def add_to_tainted_hosts(host):
  global tainted_hosts
  global watermarks_received_on_hosts
  if (host in tainted_hosts) or (host in protected_resources):
    log.debug("host already present in tainted list")
  else:
    tainted_hosts.append(host)
    #watermarks_received_on_hosts = np.vstack((watermarks_received_on_hosts, [host]))
    #watermarks_received_on_hosts.append(h)
    log.debug("added %s to tainted_hosts list ", host)

def add_to_watermarks_received_on_hosts(host, watermark):
  if watermarks_received_on_hosts.has_key(host):
    if watermark not in watermarks_received_on_hosts.get(host):
      log.debug("appended watermark to list")
      watermarks_received_on_hosts.get(host).append(watermark)
      pprint.pprint(watermarks_received_on_hosts)
  else:
    log.debug("host not found in the watermarks_received_on_hosts list")
    watermarks_received_on_hosts[host] = [watermark]
    pprint.pprint(watermarks_received_on_hosts)

def delete_flow_entries(event, packet, host_address):
  #if (host_address not in protected_resources)
  log.debug("deleting flow table entries for " + host_address)
  msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
  #msg.priority = 65635
  msg.match.dl_src = host_address
  event.connection.send(msg)


def _handle_PacketIn (event):

  global syn_counter
  global forward_rule_set
  global backward_rule_set
  global mac_port_dict
  global watermark_samples
  global protected_resources
  global tainted_hosts
  global watermark_count
  skip_add_to_dict = 0

  packet =event.parsed

  dest_eth_addr = str(packet.dst)
  src_eth_addr = str(packet.src)

  ipv4_pack = packet.find("ipv4")
  if ipv4_pack:
    log.debug("IP packet in transit from  "+str(ipv4_pack.srcip)+"<->"+str(ipv4_pack.dstip))

  log.debug("packet forwarding  " + src_eth_addr + "  " + dest_eth_addr)
  if (dest_eth_addr in protected_resources):
    log.debug("***traffic going to protected resource***")
    #log.debug("***FLow rule not added to switches. Send to controller***")
    #send_packet(event, packet)
    #skip_add_to_dict = 1
  elif (dest_eth_addr in tainted_hosts):
    log.debug("***traffic going to Tainted host ***")
    #log.debug("***FLow rule not added to switches. Send to controller***")
    #send_packet(event, packet)
    #skip_add_to_dict = 1

  if (src_eth_addr in protected_resources):
    if (dest_eth_addr in protected_resources):
      log.debug("*** traffic from protected resource to protected_resources***")
      skip_add_to_dict = 0
    else:
      log.debug("*** traffic from protected resource***")
      log.debug("***FLow rule not added to switches. Send to controller***")
      add_to_tainted_hosts(dest_eth_addr)
      add_to_watermarks_received_on_hosts(dest_eth_addr, 0)
      index = random.randint(0,1000)
      log.debug("index %i", index)
      log.debug("****inserting  "+str(watermark_samples[0][index])+" seconds delay here - src Protected***")
      time.sleep(watermark_samples[0][index])
      skip_add_to_dict = 1
      flood_packet(event, of.OFPP_ALL)
      delete_flow_entries(event, packet, dest_eth_addr)
      #send_packet(event, of.OFPP_ALL)
    
  elif(src_eth_addr in tainted_hosts) and (dest_eth_addr not in protected_resources):
    log.debug("***** traffic from  a tainted host *********")
    log.debug("***FLow rule not added to switches. Send to controller***")
    add_to_tainted_hosts(dest_eth_addr)
    watermark = create_watermark(src_eth_addr, mu, sigma)
    add_to_watermarks_received_on_hosts(dest_eth_addr, watermark)
    index = random.randint(0,1000)
    log.debug("index %i", index)
    log.debug("****inserting  "+str(watermark_samples[watermark][index])+" seconds delay here - src Tainted***")
    time.sleep(watermark_samples[watermark][index])
    skip_add_to_dict = 1
    flood_packet(event, of.OFPP_ALL)
    delete_flow_entries(event, packet, dest_eth_addr)

  if skip_add_to_dict != 1:
  	mac_port_dict[packet.src] = event.port

  if (packet.dst not in mac_port_dict and skip_add_to_dict == 0):
    log.debug("flooding to all ports as no entry in dictionary and skip_add_to_dict is %i", skip_add_to_dict)
    flood_packet(event, of.OFPP_ALL)
  elif (packet.dst not in mac_port_dict and skip_add_to_dict == 1):
    log.debug(" ----- Entry not found in dictpacket has already been flooded -----")
  elif (packet.dst in mac_port_dict and skip_add_to_dict == 1):
    log.debug("**** Entry fround in dict but packet has already been flooded ******")
  else:
	 port = mac_port_dict[packet.dst]
	 log.debug("setting a flow table entry as matching entry found in dict - " + src_eth_addr + "    " + dest_eth_addr)
	 msg = of.ofp_flow_mod()
	 msg.match = of.ofp_match.from_packet(packet, event.port)
	 msg.priority = 1009
	 msg.actions.append(of.ofp_action_output(port = port))
	 msg.data = event.ofp
	 event.connection.send(msg)

def _handle_ConnectionUp (event):
  log.debug("[!] HubACLs v0.0.1 Running %s", dpidToStr(event.dpid))

def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn",_handle_PacketIn)

