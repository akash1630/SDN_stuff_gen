import glob
import re
import os

from colorama import Fore, Back, Style, init

PROC_TCP = "/proc/net/tcp"

GREEN  = Fore.GREEN+Style.BRIGHT
RED    = Fore.RED+Style.BRIGHT
BLUE   = Fore.BLUE+Style.BRIGHT
YELLOW = Fore.YELLOW+Style.BRIGHT

###############################################################################
# Utils: Helper Module
##############################################################################

def _load():
	    with open(PROC_TCP,'r') as f:
	        content = f.readlines()
	        content.pop(0)
	    return content

def _hex2dec(s):
	    return str(int(s,16))

def _ip(s):
	    ip = [(_hex2dec(s[6:8])),(_hex2dec(s[4:6])),(_hex2dec(s[2:4])),(_hex2dec(s[0:2]))]
	    return '.'.join(ip)

def _remove_empty(array):
	    return [x for x in array if x !='']

def _convert_ip_port(array):
	    host,port = array.split(':')
	    return _ip(host),_hex2dec(port)

def _get_pid_of_inode(inode):
    for item in glob.glob('/proc/[0-9]*/fd/[0-9]*'):
        try:
            if re.search(inode,os.readlink(item)):
                return item.split('/')[2]
        except:
            pass
    return None

