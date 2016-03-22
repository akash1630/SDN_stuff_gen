from mininet.util import dumpNodeConnections

def pingTest(net):
    print "[+] Ping: Testing network connectivity"
    net.pingAll()

def perfTest(net,src,dst):
    net.iperf((src, dst))

