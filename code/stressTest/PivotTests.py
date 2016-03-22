import time

def proxyChainTest(net,h1,h2,h3):
    print "[+] ProxyChain Test"
    h1,h2,h3 = net.get('h1','h2','h3')
    h2.cmd('/usr/sbin/sshd &')
    h3.cmd('nc -lvp 8000 < /tmp/secret.txt &')
    print "[+] ... SSH Port Forwarding Setting Up"
    time.sleep(5)
    h1.cmd('ssh -i ~/.ssh/id_rsa -f -N -D 127.0.0.1:9050 mininet@'+h2.IP())
    print "[+] ... SSH Port Tunnel Created, Testing ProxyChains"
    time.sleep(5)
    h1.cmd('proxychains nc '+h3.IP()+' 8000 > /dev/null')
    print "[+] SSH Port Forwarding Complete"

def sshPortTest(net,h1,h2,h3):
    print "[+] SSH Port Forwarding Test"
    h1,h2,h3 = net.get('h1','h2','h3')
    h2.cmd('/usr/sbin/sshd &')
    h3.cmd('nc -lvp 8000 < /tmp/secret.txt &')
    print "[+] ... SSH Port Forwarding Setting Up"
    time.sleep(5)
    h1.cmd('ssh -i ~/.ssh/id_rsa -f -N -L 127.0.0.1:8000:'+h3.IP()+':8000 mininet@'+h2.IP())
    print "[+] ... SSH Port Tunnel Created, Standby"
    time.sleep(5)
    h1.cmd('nc 127.0.0.1 8000 > /dev/null')
    print "[+] SSH Port Forwarding Complete"

def cryptCatTest(net,h1,h2,h3):
    print "[+] CryptCat Relay Test"
    h2.cmd('cryptcat -lvp 8000 0<backpipe | cryptcat '+h3.IP()+' 8000 > backpipe &')
    h3.cmd('cryptcat -lvp 8000 < /tmp/secret.txt &')
    print "[+] CryptCat Relay Setting Up"
    time.sleep(5)
    h1.cmd('cryptcat '+h2.IP()+' 8000 > /dev/null')
    print "[+] CryptCat Relay Complete"

def netCatTest(net,h1,h2,h3):
    print "[+] NetCat Relay Test"
    h2.cmd('nc -lvp 8000 0<backpipe | nc '+h3.IP()+' 8000 > backpipe &')
    h3.cmd('nc -lvp 8000 < /tmp/secret.txt &')
    print "[+] NetCat Relay Setting Up"
    time.sleep(5)
    h1.cmd('nc '+h2.IP()+' 8000 > /dev/null')
    print "[+] NetCat Relay Complete"

