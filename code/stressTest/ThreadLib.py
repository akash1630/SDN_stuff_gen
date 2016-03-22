import threading, time
from PivotTests import *
from Util import *
from TrafficGen import *
from PerfTests import *

class PivotThread(threading.Thread):
        def __init__(self, group=None, target=None, name=None, kwargs=None, verbose=None):
                threading.Thread.__init__(self, group=group, target=target, name=name,verbose=verbose)
                self.kwargs = kwargs
                self.running = True
                return

        def run(self):
                net = self.kwargs['net']
                pType = self.kwargs['ptype']

                h1 = net.get('h1')
                h2 = net.get('h2')
                h3 = net.get('h3')

                print "[+] Generating Pivot From "+h1.IP()+"<->"+h2.IP()+"<->"+h3.IP()
                if (pType == "netcat"):
                        netCatTest(net,h1,h2,h3)
                elif (pType == "cryptcat"):
                        cryptCatTest(net,h1,h2,h3)
                elif (pType == "sshport"):
                        sshPortTest(net,h1,h2,h3)
                elif (pType == "proxychains"):
                        proxyChainTest(net,h1,h2,h3)

        def end(self):
                self.running = False


# trafficGenThread
class TrafficThread(threading.Thread):
        def __init__(self, group=None, target=None, name=None, kwargs=None, verbose=None):
                threading.Thread.__init__(self, group=group, target=target, name=name,verbose=verbose)
                self.kwargs = kwargs
                self.running = True
                return

        def run(self):
                while (self.running):
                        net = self.kwargs['net']
                        src = net.get(retRandomHost())
                        dst = net.get(retRandomHost())
                        while (src == dst):
                                dst = net.get(retRandomHost())
                        print "[+] Generating Traffic Between "+src.IP()+"<->"+dst.IP()
                        trafficTest(net,src,dst)
                        time.sleep(1)

        def end(self):
                self.running = False


# perfThread: Thread for doing iPerf Tests
class PerfThread(threading.Thread):
        def __init__(self, group=None, target=None, name=None, kwargs=None, verbose=None):
                threading.Thread.__init__(self, group=group, target=target, name=name,verbose=verbose)
                self.kwargs = kwargs
                self.running = True
                return

        def run(self):
                while (self.running):
                        net = self.kwargs['net']
                        src = net.get(retRandomHost())
                        dst = net.get(retRandomHost())
                        while (src == dst):
                                dst = net.get(retRandomHost())
                        perfTest(net,src,dst)
                        time.sleep(1)

        def end(self):
                self.running = False


# pingThread: Thread for doing PingAll Tests
class PingThread(threading.Thread):
        def __init__(self, group=None, target=None, name=None, kwargs=None, verbose=None):
                threading.Thread.__init__(self, group=group, target=target, name=name,verbose=verbose)
                self.kwargs = kwargs
                return
        def run(self):
                net = self.kwargs['net']
                pingTest(net)
