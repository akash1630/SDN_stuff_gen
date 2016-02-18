import numpy as np
import time
from pox.lib.recoco import Timer
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr

log = core.getLogger()
syn_counter = 0
counter_s1 = 1
counter_s2 = 1
watermark_samples = []
watermark_samples.append(np.random.normal(1, 0.5, 500))
mac_port_dict = {}
protected_resources = ["00:00:00:00:00:03"]
tainted_hosts = []
watermarks_received_on_hosts = []

def flood_packet (event, dst_port = of.OFPP_ALL):
  msg = of.ofp_packet_out(in_port=event.ofp.in_port)
  if event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None:
    msg.buffer_id = event.ofp.buffer_id
  else:
    if event.ofp.data:
      return
    msg.data = event.ofp.data
  msg.actions.append(of.ofp_action_output(port = dst_port))
  event.connection.send(msg)

def create_watermark(mu, sigma):
  global watermark_samples
  log.debug("creating watermark array with params : "+ str(mu) + "    "+ str(sigma))
  samples = np.random.normal(mu, sigma, 500)
  #watermark_samples = np.vstack((watermark_samples, samples))
  watermark_samples.append(samples)

def add_to_tainted_hosts(host):
  global tainted_hosts
  global watermarks_received_on_hosts
  if (host in tainted_hosts):
    log.debug("host already present in tainted list")
  else:
    tainted_hosts.append(host)
    #watermarks_received_on_hosts = np.vstack((watermarks_received_on_hosts, [host]))
    #watermarks_received_on_hosts.append(h)
    log.debug("added %s to tainted_hosts list and watermarks received list", host)

def add_to_watermarks_received_on_hosts(host, watermark):
  hosts = [i[0] for i in watermarks_received_on_hosts]
  if host in hosts:
    watermarks_received_on_hosts[hosts.index(host)].append(watermark)
    log.debug("appended watermark to list")
  else:
    log.debug("host not found in the watermarks_received_on_hosts list")
    watermarks_received_on_hosts.append([host, watermark])

def delete_flow_entries(event, packet, host_address):
  log.debug("deleting flow table entries for " + str(host_address))
  msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
  #msg.priority = 65635
  msg.match.dl_src = str(host_address)
  event.connection.send(msg)


def _handle_PacketIn (event):

  global syn_counter
  global forward_rule_set
  global backward_rule_set
  global counter_s1
  global counter_s2
  global mac_port_dict
  global watermark_samples
  global protected_resources
  global tainted_hosts
  skip_add_to_dict = 0

  packet =event.parsed
  ipv4_pack = packet.find("ipv4")
  if ipv4_pack:
    log.debug("IP packet in transit from  "+str(ipv4_pack.srcip)+"<->"+str(ipv4_pack.dstip))

  log.debug("packet forwarding  " + str(packet.src) + "  " + str(packet.dst))
  if (str(packet.dst) in protected_resources):
    log.debug("***traffic going to protected resource***")
    log.debug("***FLow rule not added to switches. Send to controller***")
    #send_packet(event, packet)
    skip_add_to_dict = 1

  if (str(packet.src) in protected_resources):
    log.debug("*** traffic from protected resource***")
    log.debug("***FLow rule not added to switches. Send to controller***")
    log.debug("****inserting"+str(watermark_samples[0][counter_s1%500])+" seconds delay here - src Protected***")
    add_to_tainted_hosts(packet.dst)
    delete_flow_entries(event, packet, packet.dst)
    log.debug("counter index %i", counter_s1)
    time.sleep(watermark_samples[0][counter_s1%500])
    counter_s1 = counter_s1 + 1
    skip_add_to_dict = 1
     #send_packet(event, of.OFPP_ALL)
  if skip_add_to_dict != 1:
  	mac_port_dict[packet.src] = event.port
  if (packet.dst not in mac_port_dict and skip_add_to_dict == 1):
	 flood_packet(event, of.OFPP_ALL)
	 log.debug("flooding to all ports as no entry in dictionary and skip_add_to_dict is 1")
  elif packet.dst not in mac_port_dict:
   flood_packet(event, of.OFPP_ALL)
   log.debug("flooding to all ports as no entry in dictionary ")
  else:
	 port = mac_port_dict[packet.dst]
	 log.debug("setting a flow table entry as matching entry found in dict - " + str(packet.src) + "    " + str(packet.dst))
	 msg = of.ofp_flow_mod()
	 #msg.priority = 1009
	 msg.match = of.ofp_match.from_packet(packet, event.port)
	 msg.priority = 1009
	 msg.actions.append(of.ofp_action_output(port = port))
	 msg.data = event.ofp
	 event.connection.send(msg)

def _handle_ConnectionUp (event):
  log.debug("[!] HubACLs v0.0.1 Running %s", dpidToStr(event.dpid))
  create_watermark(1,0.3)
  create_watermark(2.5,1.2)

def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn",_handle_PacketIn)

