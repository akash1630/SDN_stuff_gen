import random, time, shlex
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import Host, Controller, RemoteController, OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.util import pmonitor
from mininet.node import CPULimitedHost

# class star (good)
class StarType(Topo):
    def __init__(self, **opts):
	print "Starting Star Network"
        super(StarType, self).__init__(**opts)

 	s1 = self.addSwitch('s1', cls=OVSKernelSwitch)

    	h4 = self.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)
    	h3 = self.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)
    	h2 = self.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    	h1 = self.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    	h5 = self.addHost('h5', cls=Host, ip='10.0.0.5', defaultRoute=None)

	self.addLink(h1, s1)
    	self.addLink(s1, h2)
    	self.addLink(s1, h3)
    	self.addLink(s1, h4)
    	self.addLink(s1, h5)

# class tree (good)
class TreeType(Topo):
    def __init__(self, **opts):
        super(TreeType, self).__init__(**opts)

	s2 = self.addSwitch('s2', cls=OVSKernelSwitch)
    	s3 = self.addSwitch('s3', cls=OVSKernelSwitch)
    	s4 = self.addSwitch('s4', cls=OVSKernelSwitch)
    	s1 = self.addSwitch('s1', cls=OVSKernelSwitch)
    	s5 = self.addSwitch('s5', cls=OVSKernelSwitch)

	h1 = self.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    	h2 = self.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    	h3 = self.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)
    	h4 = self.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)

    	self.addLink(s1, s5)
    	self.addLink(s2, s5)
    	self.addLink(s3, s5)
    	self.addLink(s4, s5)
    	self.addLink(h1, s1)
    	self.addLink(h2, s2)
    	self.addLink(h3, s3)
    	self.addLink(h4, s4)


# class ring (good) 
class RingType(Topo):
    def __init__(self, **opts):
        super(RingType, self).__init__(**opts)

	s2 = self.addSwitch('s2', cls=OVSKernelSwitch)
    	s3 = self.addSwitch('s3', cls=OVSKernelSwitch)
    	s4 = self.addSwitch('s4', cls=OVSKernelSwitch)
    	s1 = self.addSwitch('s1', cls=OVSKernelSwitch)
    	s5 = self.addSwitch('s5', cls=OVSKernelSwitch)

	h1 = self.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    	h2 = self.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    	h3 = self.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)
    	h4 = self.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)

    	self.addLink(s1, s5)
    	self.addLink(s2, s5)
    	self.addLink(s3, s5)
    	self.addLink(s4, s5)
    	self.addLink(h1, s1)
    	self.addLink(h2, s2)
    	self.addLink(h3, s3)
    	self.addLink(h4, s4)


# class bus (good)
class BusType(Topo):
    def __init__(self, **opts):
        super(BusType, self).__init__(**opts)

  	s3 = self.addSwitch('s3', cls=OVSKernelSwitch)
    	s2 = self.addSwitch('s2', cls=OVSKernelSwitch)
    	s4 = self.addSwitch('s4', cls=OVSKernelSwitch)
    	s1 = self.addSwitch('s1', cls=OVSKernelSwitch)

    	h1 = self.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    	h4 = self.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)
    	h2 = self.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    	h3 = self.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)

    	self.addLink(s2, s3)
    	self.addLink(s3, h3)
    	self.addLink(s3, s4)
    	self.addLink(s4, h4)
    	self.addLink(s1, h1)
    	self.addLink(s1, s2)
    	self.addLink(s2, h2)

