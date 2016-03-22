#!/usr/bin/python

import os
import sqlite3
import datetime
import threading

modules = ["psxview","privs","dlllist","cmdline","pstree","modules"]
	
def FormatSQL(s):
	s = s.replace("[","(").replace("]",")").replace("'","").replace("(P)",'').replace("(V)",'')
	return s
	
def FormatArray(s):
	s = s.replace('u"','"').replace("u'","'").replace("[","(").replace("]",")")
	return s
	
def RetPids(t,host,ipaddr):

	print "[+] Running SOCKSCAN Module; Returning List of PIDs"	
	# Run SockScan to determine all open sockets and their PIDs
	fname = "logs/"+"netscan-"+ipaddr+"-"+t+".db"
	cmd = "vol.py -l vmi://"+host+" --profile=Win7SP1x86 netscan --output=sqlite --output-file="+fname
	os.system(cmd)
	conn = sqlite3.connect(fname)
	c = conn.cursor()
	c.execute("select DISTINCT Pid from netscan")
	res = c.fetchall()
	conn.close()

	# Return String of all open PIDs with open sockets
	PIDList = "( "
	for PID in res:
		PIDList = PIDList +str(PID[0])+","
	PIDList = PIDList+")"
	PIDList = PIDList.replace(",)"," )")

	print "[+] Found {0} PIDs with Open Connections".format(len(res))
	return PIDList

def RunModule(t,host,module,ipaddr,PIDList):
	
	print "[+] Running {0} Module".format(module)
	# Run Module and store output in Sqlite DB
	fname = "logs/"+module+"-"+ipaddr+"-"+t+".db"
	cmd = "vol.py -l vmi://"+host+" --profile=Win7SP1x86 "+module+" --output=sqlite --output-file="+fname+" 2>/dev/null"
	os.system(cmd)
	
	# Retrieve Results from Module Where PID in list of PIDs with open sockets
	conn = sqlite3.connect(fname)
	c = conn.cursor()
	if (module=="modules"):
		c.execute("select * from modules")
	else:
		c.execute("select * from "+module+" where Pid in "+PIDList)
	rows = c.fetchall()
	conn.close()

	cols = []
	for col in c.description:
		cols.append((str(col[0])))	
	cols.insert(0,"IPAddr")
	cols.insert(1,"TimeStamp")
	
	conn = sqlite3.connect("Master.db")
	c = conn.cursor()

	# Store Results in Master DB, Append IPaddr + TimeStamp, Remove ID
	for row in rows:
		insert_stmt = "INSERT INTO "+module+" "+str(cols)+" VALUES "
		insert_stmt = FormatSQL(insert_stmt)
		row = list(row)
		row.insert(0,ipaddr)
		row.insert(1,t)
		pretty_row = FormatArray(str(row))
		insert_stmt = insert_stmt+pretty_row
		c.execute(insert_stmt)
		conn.commit()
	conn.close()
	print "[+] Results of {0} Stored in Master.db".format(module)

def UpdateTable(ipaddr,t):
	conn = sqlite3.connect("Master.db")
        c = conn.cursor()
	insert_stmt = "INSERT INTO Tests (IPAddr,TimeStamp) VALUES ('"+str(ipaddr)+"','"+str(t)+"')"
	c.execute(insert_stmt)
	conn.commit()
	conn.close()

class MyThread(threading.Thread):
	def __init__(self, group=None, target=None, name=None, kwargs=None, verbose=None):
        	threading.Thread.__init__(self, group=group, target=target, name=name,verbose=verbose)
        	#self.args = args
		self.kwargs = kwargs
        	return


    	def run(self):
		t = self.kwargs['t']
		host = self.kwargs['host']
		module = self.kwargs['module']
		ipaddr = self.kwargs['ipaddr']
		PIDList = self.kwargs['PIDList']
		RunModule(t,host,module,ipaddr,PIDList)
		return

def main():

	from optparse import OptionParser
	usage = "usage: %prog [options] arg"
	parser = OptionParser(usage)
	parser.add_option("-n", "--host", dest="host", help="XEN Guest Name")
	parser.add_option("-i", "--ip", dest="ip", help="XEN Guest IP Address")
	(options, args) = parser.parse_args()
	if ((not options.host) or (not options.ip)):
        	print "[!] Error. Requires both host (-n) and ip address (-i)"
        	exit(-1)
	host=options.host
	ipaddr=options.ip


	# Parse IPAddr as Option
	#ipaddr = "192.168.122.70"
	
	# Determine Current Time
	now = datetime.datetime.now()
	t=now.strftime("%Y%d%m%H%M%S")

	print "[+] Running Test Against {0} at {1}".format(ipaddr,t)	
	UpdateTable(ipaddr,t)

	# Return String of Processes With Open Sockets
	PIDList = RetPids(t,host,ipaddr)
	
	# Run All Modules at current time against ipaddr and PIDList
	for module in modules:
		th = MyThread(kwargs={'t':t,'host':host,'module':module,'ipaddr':ipaddr,'PIDList':PIDList})
		th.start()
		#RunModule(t,host,module,ipaddr,PIDList)			
	
if __name__ == "__main__":
    main()

