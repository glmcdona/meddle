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
		pass

	def __init__(self, CEngine):
		self.CEngine = CEngine
		pass
	
	def main(self, args):
		# Set working directory to controller directory
		os.chdir(os.path.join(os.path.dirname(__file__), ".."))
		
		try:
			printOnly = False
			instrumentFile = ""
			for arg in args:
				instrumentFile = arg

			mBreakpoint = BreakpointMeasurement()
			mProcess = ProcessTrace(instrumentFile, instrumentFile, self, "C:\\Crash\\", mBreakpoint, -1, -1, 0, printOnly )
			self.CEngine.AttachProcess(mProcess)
			return

		except Exception,e:
			logging.exception("Controller main loop unhandled exception.")
    		raise
	

#def on_crash(Engine, process, instance_argument, seed):
#    # Restart the instance but with a new seed so it doesn't just do the same thing again
#    seed = int(random()*100000)
#    print "Controller: Restarting crashed instance attacking '%s' with arguments '%s'." % (process, instance_arguments)
#    return [[process, instance_arguments]]