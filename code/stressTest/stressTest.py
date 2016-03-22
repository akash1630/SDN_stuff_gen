#!/usr/bin/python

# standard imports
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections, pmonitor
from mininet.log import setLogLevel
from mininet.node import Controller, RemoteController, CPULimitedHost
from mininet.cli import CLI
from optparse import OptionParser
import threading,sys,os

# user-provided imports
from Util import *
from TopoTypes import *
from TrafficGen import *
from PivotTests import *
from PerfTests import *
from ThreadLib import *

# setup MiniNet & Connect to Remote Controller
def setupNet(topoType):
    os.system("mn -c 2> /dev/null")
    os.system("fallocate -l 1G /tmp/secret.txt")

    c = RemoteController('c', '0.0.0.0', 6633)
    net = Mininet(topo=topoType, host=CPULimitedHost, controller=None)
    net.addController(c)
    net.start()
    return net

# tearDown MiniNet
def tearDownNet(net):
    print "[!] Tearing Down Network"
    os.system("rm -f /tmp/secret.txt")
    net.stop()
    sys.exit()


if __name__ == '__main__':
    checkFiles()
    # parse options
    usage = "usage: %prog [options] arg"
    parser = OptionParser(usage)
    # topo
    parser.add_option("-t", "--topo", dest="topo", help="Network Topology {star,bus,ring,tree}")
    parser.add_option("-p", "--pivot", dest="pivot", help="Pivot Type {netcat,cryptcat,sshport,proxychains}")
    # performance monitoring
    parser.add_option("-m", "--perf",
                  action="store_true", dest="perf", default=False,
                  help="Enable Performance Monitoring")
    # traffic generation
    parser.add_option("-g", "--gen",
                  action="store_true", dest="traffic", default=False,
                  help="Enable Traffic Generation")

    (options,args) = parser.parse_args()

    # right now traffic generation and performance monitoring not enable to work at same time (due to assertion error)
    if (options.traffic and options.perf):
        print "[!] May not enable traffic generation and performance monitoring at same time."
        sys.exit(-1)

    # parse topo
    topoTypes = ["star","bus","ring","tree"]
    if ((not options.topo) or (options.topo not in topoTypes)):
	print "[!] A topology (-t) is required (star,bus,ring,tree)"
        exit (-1)
    else:
	topo = options.topo
    topos = {'bus':BusType(),
             'star':StarType(),
             'ring':RingType(),
             'tree':TreeType()
	     }
    topoType = topos[topo]
    net = setupNet(topoType=topoType)
    setLogLevel('info')
    
    # perf monitoring thread
    if (options.perf):
	    "[+] Performance Monitoring Enabled, Starting."
	    perfT = PerfThread(kwargs={'net':net})
	    perfT.start()

    # traffic generation thread
    if (options.traffic):
	    "[+] Traffic Generation Enabled, Starting."
	    trafficT = TrafficThread(kwargs={'net':net})
	    trafficT.start()

    if (options.pivot):
	    pivots = ["sshport","proxychains","netcat","cryptcat"]
	    if (options.pivot not in pivots):
		print "[!] Error supported pivots are {sshport,proxychains,netcat,cryptcat}"
	    pivotT = PivotThread(kwargs={'net':net,'ptype':options.pivot})
	    pivotT.start()

    # present the command prompt
    CLI(net)

    # after 'quit' is entered, teardown the network and all threads
    if (options.perf):
	    perfT.end()
    if (options.traffic):
	    trafficT.end()
    if (options.pivot):
	    pivotT.end()
    tearDownNet(net)

