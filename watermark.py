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
samples1 = []
samples2 = []
mac_port_dict = {}

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

def initialize_watermark_array(mu, sigma):
  log.debug("creating watermaek array with params : "+ str(mu) + "    "+ str(sigma))
  samples = np.random.normal(mu, sigma, 1000)
  return samples

def _handle_PacketIn (event):

  global syn_counter
  global forward_rule_set
  global backward_rule_set
  global counter_s1
  global counter_s2
  global samples1
  global samples2
  global mac_port_dict
  skip_add_to_dict = 0

  packet =event.parsed
  ipv4_pack = packet.find("ipv4")
  if ipv4_pack:
    log.debug("IP packet in transit from  "+str(ipv4_pack.srcip)+"<->"+str(ipv4_pack.dstip))

  log.debug("packet forwarding  " + str(packet.src) + "  " + str(packet.dst))
  if (str(packet.dst) == "00:00:00:00:00:03"):
    log.debug("***traffic going to protected resource***")
    log.debug("***FLow rule not added to switches. Send to controller***")
    #send_packet(event, packet)
    skip_add_to_dict = 1

  if (str(packet.src) == "00:00:00:00:00:03"):
    log.debug("*** traffic from protected resource***")
    log.debug("***FLow rule not added to switches. Send to controller***")
    log.debug("****inserting"+str(samples1[counter_s1%1000])+" seconds delay here - src Protected***")
    time.sleep(samples1[counter_s1 % 1000])
    counter_s1 = counter_s1 + 1
    skip_add_to_dict = 1
     #send_packet(event, of.OFPP_ALL)
  if skip_add_to_dict != 1:
  	mac_port_dict[packet.src] = event.port
  if packet.dst not in mac_port_dict:
	flood_packet(event, of.OFPP_ALL)
	log.debug("flooding to all ports as no entry in dictionary")
  else:
	port = mac_port_dict[packet.dst]
	log.debug("setting a flow table entry - matching entry found in dict")
	msg = of.ofp_flow_mod()
	#msg.priority = 1009
	msg.match = of.ofp_match.from_packet(packet, event.port)
	msg.priority = 1009
	msg.actions.append(of.ofp_action_output(port = port))
	msg.data = event.ofp
	event.connection.send(msg)

def _handle_ConnectionUp (event):
  log.debug("[!] HubACLs v0.0.1 Running %s", dpidToStr(event.dpid))
  global samples1
  global samples2
  samples1 = initialize_watermark_array(1,0.3)
  samples2 = initialize_watermark_array(2.5,1.2)

def launch ():
  Timer(5,check_flows,recurring = True)
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn",_handle_PacketIn)

