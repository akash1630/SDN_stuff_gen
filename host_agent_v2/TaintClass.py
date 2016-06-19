import sqlite3
from datetime import datetime
import os.path
import logging
import time

LOG_LEVEL = logging.DEBUG
ORPHAN_DELAY = 1

from colorama import Fore, Back, Style, init
from utils import GREEN, RED, BLUE, YELLOW

### TODO PRUNE DB ###
### TaintPID --> Send Notice To Current Connections ####

class TaintDb:

	def __init__(self,dbname):
		try:
			self.dbname = dbname
			logging.basicConfig(level=LOG_LEVEL)
			self.logger = logging.getLogger('TaintClass')
			if (os.path.isfile(self.dbname)): 
				self.conn = sqlite3.connect(self.dbname)
			else:
				self.logger.debug(YELLOW+'[+] Creating New TaintDB')
				self.conn = sqlite3.connect(self.dbname)
				self.create_db()
			#self.check_orphans()

		except Exception as e:
			self.logger.error('[!] TaintDB Init Failed: '+str(e))
		
	def create_db(self):
		try:
			self.conn.execute('''CREATE TABLE TAINT
			       (PID            INT      NOT NULL,
			       FNAME          TEXT     NOT NULL,
			       PERMS          TEXT     NOT NULL,
			       TDATE          INT      NOT NULL,
			       PRIMARY KEY (PID,FNAME));''')
			self.conn.commit()
		except Exception as e:
			self.logger.error(RED+'[!] Failed CreateDB: '+str(e))

	def fp_exists(self,fname,pid):
		try:
			c = self.conn.cursor()
			c.execute("select PID from TAINT where PID=(?) and FNAME = (?)",(pid,fname))
			res = c.fetchone()
			if (res):
				return True
			else:
				return False
		except Exception as e:
			self.logger.error(RED+'[!] Failed F_Exists: '+str(e))
	

	def insert_db(self,pid,fname,perms,taint):
		try:
			if (self.is_tainted_fp(fname,pid)):
				return
			elif ((self.fp_exists(fname,pid)) and (taint == False)):
				return
			elif (taint):
				now = datetime.now()  
			else:
				now = 0
			c = self.conn.cursor()
			params = (pid,fname,perms,now)
			c.execute("insert into TAINT(PID,FNAME,PERMS,TDATE) values (?, ?, ?, ?)",params,)
			self.conn.commit()
			
			if (taint):
				orphans = self.ret_orphans(pid) 
				for orphan in orphans:
					msg = '[+] PID {'+str(pid)+'}'+' has tainted '+str(orphan)
					self.logger.debug(YELLOW+msg)
					perms = self.ret_perms(pid,fname)
					self.insert_db(pid,orphan,perms,True)

		except Exception as e:
			self.logger.error(RED+'[!] Failed InsertDB: '+str(e))

	def taint_pid(self,pid):
		try:
			### Add Logic ###
			### Look Up Any Current Connections for PID and Send Notice ####

			msg = "[-] Tainting PID: "+str(pid)
			self.logger.debug(YELLOW+msg)
			now = datetime.now()  
			c = self.conn.cursor()
			c.execute("select PID from TAINT where PID=(?);",[str(pid)])
			res = c.fetchone()
			if (res):
				c.execute('update TAINT set TDATE=(?) where PID=(?) and TDATE=0',(now,pid))
				self.conn.commit()
			else:
				#self.logger.debug('[+] insert null record.')
				self.insert_db(pid,'NULL','NULL',True)		
		except Exception as e:
			self.logger.error('[!] Failed Taint_PID: '+str(e))


	def taint_file(self,filename):
		try:
			msg = "[-] Tainting File: "+str(filename)
			self.logger.debug(YELLOW+msg)
			now = datetime.now()  
			c = self.conn.cursor()
			c.execute('update TAINT set TDATE=(?) where FNAME=(?) and TDATE=0',(now,filename))
			self.conn.commit()
		except Exception as e:
			self.logger.error(RED+'[!] Failed Taint_File: '+str(e))
	
	def is_tainted_fp(self,fname,pid):
		try:
			c = self.conn.cursor()
			c.execute('select TDATE from TAINT where fname=(?) and pid=(?);',(fname,pid))
			tlist = c.fetchall()
			for tdate in tlist:
				if (tdate[0] != 0): 
					self.taint_file(fname)
					return True
			return False 
		except Exception as e:
			self.logger.error(RED+'[!] Failed Is_Tainted_FP: '+str(e))
			return False


	def is_tainted_f(self,fname):
		try:
			c = self.conn.cursor()
			c.execute('select TDATE from TAINT where fname=(?);',[fname])
			tlist = c.fetchall()
			for tdate in tlist:
				if (tdate[0] != 0): 
					self.taint_file(fname)
					return True
			return False 
		except Exception as e:
			self.logger.error(RED+'[!] Failed Is_Tainted_F: '+str(e))
			return False

	def is_tainted_p(self,pid):
		try:
			c = self.conn.cursor()
			c.execute('select TDATE from TAINT where PID=(?);',[str(pid)])
			tlist = c.fetchall()
			for tdate in tlist:
				if (tdate[0] != 0): 
					self.taint_pid(pid)
					return True
			return False 
		except Exception as e:
			self.logger.error(RED+'[!] Failed Is_Tainted_P: '+str(e))
	
	def ret_orphans(self,pid):
		try:
			c = self.conn.cursor()
			c.execute('select FNAME from TAINT where PID=(?) and TDATE=0;',[str(pid)])
			orphans = c.fetchall()
			return orphans
		except Exception as e:
			self.logger.error(RED+'[!] Failed Ret_Orphans: '+str(e))
	
	def ret_perms(self,pid,fname):
		try:
			c = self.conn.cursor()
			c.execute('select PERMS from TAINT where fname=(?) and pid=(?);',(fname,pid))
			perms = c.fetchone()
			if (perms):
				return perms
			else:
				return 'NULL'
		except Exception as e:
			self.logger.error(RED+'[!] Failed Distinct PIDS: '+str(e))

	def ret_distinct_pids(self):
		try:
			c = self.conn.cursor()
			c.execute("select distinct PID from TAINT;")
			pidlist = c.fetchall()
			return pidlist

		except Exception as e:
			self.logger.error(RED+'[!] Failed Distinct PIDS: '+str(e))

	def prune_db(self,curr_pids):
		pass
		# Must Implement Later #

