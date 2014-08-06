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
		f = open("log.txt","a")
		f.write("process loaded %s\r\n" % name)
		f.flush()
		f.close()

	def __init__(self, CEngine):
		self.CEngine = CEngine
		pass
	
	def main(self, args):
		# Set working directory to controller directory
		os.chdir(os.path.join(os.path.dirname(__file__), ".."))
		
		try:
			printOnly = False
			for arg in args:
				if str(arg) == "-printonly":
					printOnly = True

			# Select a random seed
			seed = int(random.random()*1000000)
			self.generator = random.Random()
			self.generator.seed(seed)
			print "Controller is using seed value of %i. Set this value manually to reproduce this attack." % seed
			
			# Perform an initial measurement to gather data for an organized attack
			logger = capture.capture("capture.log",["timestamp","type","process_name","pid","device_name", "device_h", "data_base64"])
			mBreakpoint = BreakpointMeasurement()
			mProcess = ProcessDeviceIo(self, "C:\\Crash\\", mBreakpoint, -1, -1, 0, printOnly, logger )
			self.CEngine.AttachProcess(mProcess)
			
			if printOnly:
				sleep(10000)
			else:
				sleep(10)
				
			mProcess.stop()
			measurements = mBreakpoint.measurement
			
			# Generate the measurement report
			report_sum_fuzz_blocks = 0
			report_events_by_target = {}
			report_blocks_by_target = {}
			for measurement in measurements: # [[target_name, event_name, len(fuzz_blocks)]]
				report_sum_fuzz_blocks += measurement[2]
				if measurement[1] not in report_events_by_target:
					report_events_by_target[measurement[1]] = 1
				else:
					report_events_by_target[measurement[1]] += 1
				if measurement[1] not in report_blocks_by_target:
					report_blocks_by_target[measurement[1]] = measurement[2]
				else:
					report_blocks_by_target[measurement[1]] += measurement[2]
			
			# Print report and wait for input to attack
			print "CONTROLLER MEASUREMENT: Attack will consist of %i attacked events corresponding to %i fuzzed blocks.\n" % (len(measurements), report_sum_fuzz_blocks)
			print "Number of events being attacked by name:"
			for name, count in sorted(report_events_by_target.iteritems(), key=operator.itemgetter(1), reverse=True):
				print "%i\t%s" % (count, name)
			print "\nNumber of attacked blocks being attacked by name:"
			for name, count in sorted(report_blocks_by_target.iteritems(), key=operator.itemgetter(1), reverse=True):
				print "%i\t%s" % (count, name)
			print "\n\n"

			print "ALERT: Fuzzing device communication may result in corrupting files or other damage depending on usage."
			raw_input("Press any key to begin attack. I understand this has the potential to cause damage.\n")
			
			# Run the auto-it script that will press "Cancel" on the watson crash dump. Unfortunately this has to be clicked
			# before the process is terminated in order for a proper crashdump to be created it seems.
			subprocess.Popen(['autoit3.exe', os.path.join(os.path.dirname(__file__), "..", "autoit", "watson_cancel.au3"), ">nul"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

			f = open("log.txt","wb")
			f.write(str(datetime.datetime.now()) + "\r\n")
			f.write("controller using seed %i\r\n" % seed)
			f.write("Number of events being attacked by name:\r\n")
			for name, count in sorted(report_events_by_target.iteritems(), key=operator.itemgetter(1), reverse=True):
				f.write("%i\t%s\r\n" % (count, name))
			print "\nNumber of attacked blocks being attacked by name:"
			for name, count in sorted(report_blocks_by_target.iteritems(), key=operator.itemgetter(1), reverse=True):
				f.write("%i\t%s\r\n" % (count, name))
			f.flush()
			f.close()
			
			# Attack each fuzz block sequentially - each with it's own attack instance
			print "CONTROLLER: Beginning attacks"
			times = []
			processes = []
			terminate_counts = []
			fault_pause = 180
			self.last_fault = time.time()-120000
			max_runtime = 10
			num_processes = 20
			unique_identifier = 1

			event_positions = {}

			logger = capture.capture_empty()
			
			while True:
				for j in range(len(report_events_by_target)):
					# Attack this occurrence of this event
					while len(processes) >= num_processes:
						#sleep(0.5)
						sleep(0.1)
						# Cleanup old processes
						for k in range(len(processes)):
							#if processes[k].attack_count > terminate_counts[k] or processes[k].terminated or int(time() - times[k]) > max_runtime:
							if int(time.time() - self.last_fault) > fault_pause and ( processes[k].terminated or int(time.time() - times[k]) > max_runtime ):
								processes[k].stop()
								del processes[k]
								del times[k]
								del terminate_counts[k]
								break
					
					event_name = report_events_by_target.keys()[j]
					attack_index_max = report_events_by_target[event_name]
					attack_index_current = 0
					if event_name in event_positions:
						attack_index_current = event_positions[event_name]
						event_positions[event_name] = (event_positions[event_name] + 1) % attack_index_max
					else:
						event_positions[event_name] = 0
					
					# Create a new process
					breakpointSeed = self.generator.randint(1,10000000)
					newBreakpoint = BreakpointAttackSequentially(5, event_positions[event_name], event_name, breakpointSeed ) # 5% of data will be attacked
					newProcess = ProcessDeviceIo(self, "C:\\Crash\\", newBreakpoint, -1, -1, unique_identifier, False, logger )
					self.CEngine.AttachProcess(newProcess)
					unique_identifier+=1
					
					terminate_counts.append( event_positions[event_name] )
					times.append( time.time() )
					processes.append(newProcess)

		except Exception,e:
			logging.exception("Controller main loop unhandled exception.")
    		raise	
	

#def on_crash(Engine, process, instance_argument, seed):
#    # Restart the instance but with a new seed so it doesn't just do the same thing again
#    seed = int(random()*100000)
#    print "Controller: Restarting crashed instance attacking '%s' with arguments '%s'." % (process, instance_arguments)
#    return [[process, instance_arguments]]