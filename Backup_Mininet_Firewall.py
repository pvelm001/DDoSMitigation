#This code is used to block the packets

from pox.core import core
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
import os

class Switch:
  def __init__ (self, connection):
    self.connection = connection
    self.macToPort = {}

    connection.addListeners(self)

  def _handle_PacketIn (self, event):

    Rules(event)
    
    in_port=event.port
    dpid=event.dpid
    packet = event.parsed
    eth = packet.find("ethernet")
    self.macToPort[eth.src]=in_port
    if eth.dst in self.macToPort:
	out_port=self.macToPort[eth.dst]
    else:
	out_port=of.OFPP_FLOOD
    
    if out_port!=of.OFPP_FLOOD:
    	    msg = of.ofp_flow_mod()
	    msg.match = of.ofp_match()
	    msg.match.dl_dst=eth.dst
	    msg.match.in_port=event.port
	    msg.idle_timeout = 10
	    msg.hard_timeout = 30
	    msg.actions.append(of.ofp_action_output(port = out_port))
	    msg.data = event.ofp 
 	    self.connection.send(msg)
    else:
  	msg = of.ofp_packet_out()
  	msg.actions.append(of.ofp_action_output(port = out_port))
    	msg.data = event.ofp 
    	self.connection.send(msg)

def _handle_ConnectionUp (event):

  Rules(event)
  Switch(event.connection)

def launch ():

  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)


def Rules(event) :

  policyFile = "../Desktop/SDN/SDN_KMeans_Clustering/Firewall_Rules.csv"
  rules_file = open(policyFile,"r")
  rules=[rule.strip()for rule in rules_file]
  for i in range(len(rules)):
      rule_list=rules[i].split(' ')
      fw_add_rule=of.ofp_flow_mod()
      fw_add_rule.match=of.ofp_match()
      fw_add_rule.match.dl_src=EthAddr(rule_list[0])
      fw_add_rule.match.dl_dst=EthAddr(rule_list[1])
      event.connection.send(fw_add_rule)

  
