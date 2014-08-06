import sys

try:
	sys.path.append("\\".join(__file__.split("\\")[0:-1]) + "\\..\\base\\Lib")
except:
	print "Failed to add '.\\..\\base\\Lib' to path."

import os
try:
	sys.path.append(os.path.join(os.path.dirname(__file__), "..", "base"))
except:
	print "Failed to add '.\\..\\base' to path."


import subprocess
import operator
import time
from processes import *
from breakpoint_handler import *
import random
import capture
import logging
logging.basicConfig(level=logging.DEBUG)

THREAD_GET_CONTEXT = 0x0008
THREAD_QUERY_INFORMATION = 0x0040
THREAD_SET_CONTEXT = 0x0010
THREAD_SET_INFORMATION = 0x0020
THREAD_SUSPEND_RESUME = 0x0002

# Create one instance of notepad attacking driver messages
class Controller:
	last_fault = None
	
	def system_new_process(self, name, pid, ph):
		pass

	def __init__(self, CEngine):
		self.CEngine = CEngine
		pass
	
	def main(self, args):
		# Set working directory to controller directory
		os.chdir(os.path.join(os.path.dirname(__file__), ".."))

		try:
			self.printOnly = False
			self.instrumentFile = ""

			for arg in args:
				if str(arg) == "-printonly":
					self.printOnly = True
				else:
					self.instrumentFile = arg

			# Select a random seed
			seed = int(random.random()*1000000)
			self.generator = random.Random()
			self.generator.seed(seed)
			
			# Create the sandbox sample
			self.logger = capture.sandbox_logfile(".","events")
			mBreakpoint = BreakpointEmpty()
			mProcess = ProcessSandbox(self, "C:\\Crash\\", mBreakpoint, -1, 0, self.printOnly, self.logger, self.instrumentFile, self.instrumentFile, None, False, None )
			self.CEngine.AttachProcess(mProcess)
			
			sleep(10000)
			mProcess.stop()

		except Exception,e:
			logging.exception("Controller main loop unhandled exception.")
    		raise	

	def process_fork(self, new_pid, new_tid, new_ph, suspend_switched):
		# Fork the sandbox sample
		mBreakpoint = BreakpointEmpty()
		new_th = windll.kernel32.OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                             0,
                             new_tid,)
		if new_th == 0:
			# failed
			print "Failed to OpenThread to resume thread on process fork. Last error = %i." % windll.kernel32.GetLastError()
		else:
			mProcess = ProcessSandbox(self, "C:\\Crash\\", mBreakpoint, new_pid, 0, self.printOnly, self.logger, self.instrumentFile, self.instrumentFile, new_th, suspend_switched, new_ph )
			self.CEngine.AttachProcess(mProcess)
	