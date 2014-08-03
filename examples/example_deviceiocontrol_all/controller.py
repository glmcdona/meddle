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

# Create one instance of notepad attacking driver messages
class Controller:
	last_fault = None
	
	def system_new_process(self, name, pid, ph):
		mBreakpoint = BreakpointEmpty()
		mProcess = ProcessDeviceIo(self, "C:\\Crash\\", mBreakpoint, pid, ph, 0, False, self.logger, False, -1 )
		self.CEngine.AttachProcess(mProcess)


	def attach_new_process(self, name, pid, ph):
		return
		# Attach to this process
		print "attaching to %s" % name
		mBreakpoint = BreakpointMeasurement()
		mProcess = ProcessFork(self, mBreakpoint, "", "", pid, ph, -1, False )

		try:
			self.CEngine.AttachProcess(mProcess)
		except:
			print "Failed to attach to %s" % name

	def __init__(self, CEngine):
		self.CEngine = CEngine
		pass
	
	def main(self, args):
		# Set working directory to controller directory
		os.chdir(os.path.join(os.path.dirname(__file__), ".."))
		
		try:
			self.logger = capture.capture("capture.log",["timestamp","type","process_name","pid","device_name", "device_h", "data_base64"])

			# Attach to all processes
			processes = self.CEngine.GetAllProcesses()
			for process in processes:
				# Attach
				self.attach_new_process(process.ProcessName, process.Id, process.Handle)

			return
		except Exception,e:
			logging.exception("Controller main loop unhandled exception.")
    		raise	
	
	def process_fork(self, new_pid, new_tid, new_ph, suspend_switched):
		mBreakpoint = BreakpointEmpty()
		new_th = windll.kernel32.OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                             0,
                             new_tid,)
		if new_th == 0:
			# failed
			print "Failed to OpenThread to resume thread on process fork. Last error = %i." % windll.kernel32.GetLastError()
		else:
			mProcess = ProcessDeviceIo(self, "C:\\Crash\\", mBreakpoint, new_pid, new_ph, 0, False, self.logger, suspend_switched, new_th )
			self.CEngine.AttachProcess(mProcess)