import numpy as np
import scipy as sp
import stats as scipy.stats
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
tainted_hosts = {}
last_watermarked_flow_time = {}
watermarks_received_on_hosts = {}
watermark_index = 0
watermarks_created_for_hosts = {}
correlated_flows = {}
suspected_hosts = []
flow_last_packet_time = {}
flow_ipds = {}
watermark_index_to_params_map = {}

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
    mu_sigma_vals = [0,0]
    mu_sigma_vals[0] = mu
    mu_sigma_vals[1] = sigma
    watermark_index_to_params_map[watermark_index] = mu_sigma_vals
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
  if (tainted_hosts.has_key(host)) or (host in protected_resources):
    log.debug("host already present in tainted list")
  else:
    tainted_hosts[host] = time.time()
    #watermarks_received_on_hosts = np.vstack((watermarks_received_on_hosts, [host]))
    #watermarks_received_on_hosts.append(h)
    log.debug("added %s to tainted_hosts list ", host)
  last_watermarked_flow_time[host] = time.time()

def add_to_watermarks_received_on_hosts(host, watermark):
  global watermarks_received_on_hosts
  if watermarks_received_on_hosts.has_key(host):
    if watermark not in watermarks_received_on_hosts.get(host):
      log.debug("appended watermark to list")
      watermarks_received_on_hosts.get(host).append(watermark)
      pprint.pprint(watermarks_received_on_hosts)
  else:
    log.debug("host not found in the watermarks_received_on_hosts list")
    watermarks_received_on_hosts[host] = [watermark]
    pprint.pprint(watermarks_received_on_hosts)

def delete_flow_entries(event, packet, host):
  #if (host_address not in protected_resources)
  log.debug("deleting flow table entries for " + str(host))
  msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
  #msg.priority = 65635
  msg.match.dl_src = host
  event.connection.send(msg)
  log.debug("successfully sent delete flow message!!!!!!")

def delay_and_flood(event):
  log.debug("++++++++++ flooding after wait ++++++++++++")
  flood_packet(event, of.OFPP_ALL)

def prune_tainted_list():
  log.debug("****** pruning tainted hosts list **********")
  marked_for_deletion = []
  for key in tainted_hosts.keys():
    if (key not in suspected_hosts) and (time.time() - tainted_hosts[key] >= 121):
      if time.time() - last_watermarked_flow_time[key] >= 121:
        marked_for_deletion.append(key)

  for host in marked_for_deletion:
    del tainted_hosts[host]
  log.debug(" ****** deleted %i hosts from the tainted list *********", len(marked_for_deletion))

def update_ipd_arrays(src_eth_addr, dest_eth_addr):
  key = src_eth_addr + dest_eth_addr
  log.debug(" updating ipd array for : " + key)
  curr_time = time.time()
  packet_delay = 0
  if flow_last_packet_time.has_key(key):
    packet_delay = curr_time - flow_last_packet_time[key]
  flow_last_packet_time[key] = curr_time
  if flow_ipds.has_key(key):
    flow_ipds.get(key).append(packet_delay)
  else:
    flow_ipds[key] = [packet_delay]

def check_distribution(ipd_array):
  log.debug(" Checking for a normal distribution")
  chi_stats = stats.normaltest(ipd_array)
  p_val = chi_stats[1]
  if p_val > 0.1:
    log.debug("******** Sample follows a normal distribution *********")
    return 1
  log.debug(" ------- sample Does Not follow a normal distribution ----------")
  return 0

def find_mu_sigma(ipd_array):
  log.debug(" calculating mu and sigma for a normal distribution")
  mu_sigma_vals = [0,0]
  mu_sigma_vals[0] = ipd_array.mean()
  mu_sigma_vals[1] = numpy.std(ipd_array, axis = None)
  log.debug(" calcluated mean = %f  and std-dev = %f ", mu_sigma_vals[0], mu_sigma_vals[1])
  return mu_sigma_vals

def find_correlation(src_eth_addr, dest_eth_addr, mu_sigma_vals):
  log.debug("**** performing correlation tests for src: "+ src_eth_addr + " dest: " + dest_eth_addr)
  watermarks_to_check = []
  key = src_eth_addr + dest_eth_addr
  if (watermarks_received_on_hosts.has_key(src_eth_addr)):
    watermarks_to_check = watermarks_received_on_hosts[src_eth_addr]
  else:
    log.debug(" No watermarks received reorded for src : " + src_eth_addr)
    return
  for watermark_index in watermarks_to_check:
    recorded_mu_sigma = watermark_index_to_params_map[watermark_index]
    if (mu_sigma_vals[0] == recorded_mu_sigma[0]) and (mu_sigma_vals[1] == recorded_mu_sigma[1]):
      log.debug(" ########### correlation found : %s -> %s  ###########", src_eth_addr, dest_eth_addr)
      del flow_ipds[key]
      del flow_last_packet_time[key]
      return 1
  log.debug(" --------- No correlation found ------------")
  del flow_ipds[key]
  del flow_last_packet_time[key]
  return 0

def _handle_PacketIn (event):

  global syn_counter
  global forward_rule_set
  global backward_rule_set
  global mac_port_dict
  global watermark_samples
  global protected_resources
  global tainted_hosts
  global watermark_count
  skip_add_to_dict_dest = 0
  skip_add_to_dict_src = 0
  mu_sigma_vals = [0,0]

  packet =event.parsed

  log.debug("packet in buffer_id check : " +str(event.ofp.buffer_id))

  dest_eth_addr = str(packet.dst)
  src_eth_addr = str(packet.src)

  ipv4_pack = packet.find("ipv4")
  if ipv4_pack:
    log.debug("IP packet in transit from  "+str(ipv4_pack.srcip)+"<->"+str(ipv4_pack.dstip))

  log.debug("packet forwarding  " + src_eth_addr + "  " + dest_eth_addr)
  if (dest_eth_addr in protected_resources):
    log.debug("***traffic going to protected resource***")
    log.debug("***FLow rule not added to switches. Send to controller***")
    #send_packet(event, packet)
    skip_add_to_dict_dest = 1

  elif (tainted_hosts.has_key(dest_eth_addr)):
    log.debug("***traffic going to Tainted host ***")
    log.debug("***FLow rule not added to switches. Send to controller***")
    #send_packet(event, packet)
    skip_add_to_dict_dest = 1

  if (src_eth_addr in protected_resources):
    if(dest_eth_addr in protected_resources):
      log.debug("protected to protected communication")
      skip_add_to_dict_dest = 0
    else:
      log.debug("*** traffic from protected resource***")
      log.debug("***FLow rule not added to switches. Send to controller***")
      add_to_tainted_hosts(dest_eth_addr)
      add_to_watermarks_received_on_hosts(dest_eth_addr, 0)
      index = random.randint(0,1000)
      log.debug("index %i", index)
      log.debug("****inserting  "+str(watermark_samples[0][index])+" seconds delay here - src Protected***")
      #time.sleep(watermark_samples[0][index])
      #Timer(watermark_samples[0][index], delay_and_flood, event)
      core.callDelayed(watermark_samples[0][index], delay_and_flood, event)
      skip_add_to_dict_src = 1
      #flood_packet(event, of.OFPP_ALL)
      delete_flow_entries(event, packet, packet.dst)
       #send_packet(event, of.OFPP_ALL)

  elif(tainted_hosts.has_key(src_eth_addr)):
    update_ipd_arrays(src_eth_addr, dest_eth_addr)
    flow_ipd_array = flow_ipds.get(src_eth_addr+dest_eth_addr)

    if (len(flow_ipd_array) >= 40):
      if (check_distribution(flow_ipd_array) == 1):
        mu_sigma_vals = find_mu_sigma(flow_ipd_array)

    if (dest_eth_addr in protected_resources):
      log.debug("tainted to protected communication")
      skip_add_to_dict_dest = 0
    else:
      log.debug("***** traffic from  a tainted host *********")
      log.debug("***FLow rule not added to switches. Send to controller***")

      add_to_tainted_hosts(dest_eth_addr)
      watermark = create_watermark(src_eth_addr)
      add_to_watermarks_received_on_hosts(dest_eth_addr, watermark)
      index = random.randint(0,1000)
      log.debug("index %i", index)
      log.debug("****inserting  "+str(watermark_samples[watermark][index])+" seconds delay here - src Tainted***")
      #time.sleep(watermark_samples[watermark][index])
      #Timer(watermark_samples[watermark][index], delay_and_flood , event)
      core.callDelayed(watermark_samples[watermark][index], delay_and_flood , event)
      skip_add_to_dict_src = 1
      #flood_packet(event, of.OFPP_ALL)
      delete_flow_entries(event, packet, packet.dst)

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
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn",_handle_PacketIn)

