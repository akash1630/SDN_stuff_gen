import time, datetime

def trafficTest(net,src,dst):

    now = datetime.datetime.now()
    t=now.strftime("%Y%d%m%H%M%S")
    s = "logs/sender-"+t+".log"
    r = "logs/receiver-"+t+".log"
    print "[+] Starting Receiver on "+dst.IP()
    dst.cmd("sudo ~/D-ITG-2.8.1-r1023/bin/ITGRecv &")
    time.sleep(3)
    print "[+] Generating Traffic from "+src.IP()
    src.cmd("sudo ~/D-ITG-2.8.1-r1023/bin/ITGSend -T TCP -a "+dst.IP()+" -c 100 -C 10 -t 1500 -l "+s+" -x "+r)
    time.sleep(3)
    print "[+] Cleaning Up, Killing ITGRecv"
    dst.cmd("sudo pkill ITGRecv")
    
