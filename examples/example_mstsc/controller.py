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
from time import *
from processes import *
from breakpoint_handler import *
import random
import capture

# Create one instance of notepad attacking driver messages
class Controller:
	last_fault = None
	
	def system_new_process(self, name, pid, ph):
		# Kill it if it is windows error reporting. In other cases windows error reporting might indicate success.
		f = open("log.txt","a")
		f.write("process loaded %s\r\n" % name)
		f.flush()
		f.close()

		print "process loaded %s" % name
		if name == "WerFault":
			# Stop fuzzing for awhile
			self.last_fault = time()
			for i in range(10):
				print '\a'
			#while True:
				#print '################################################################################################################################################################################################################################### SUCCESS!!! #######################'
				#print '\a'
				#sleep(0.3)
			#windll.kernel32.TerminateProcess(ph,0)

	def __init__(self, CEngine):
		self.CEngine = CEngine
		pass
	
	def main(self):
		seed = int(random.random()*1000000)
		seed = 9
		self.generator = random.Random()
		self.generator.seed(seed)
		print "Controller is using seed value of %i. Set this value manually to reproduce this attack." % seed
		
		# Perform an initial measurement to gather data for an organized attack
		logger = capture.capture("capture.log",["timestamp","type","process_name","pid","device_name", "device_h", "data_base64"])
		mBreakpoint = BreakpointMeasurement()
		#mProcess = ProcessNotepad(self, "C:\\Crash\\", mBreakpoint, -1, 0, True )
		mProcess = ProcessDeviceIo(self, "C:\\Crash\\", mBreakpoint, -1, 0, True, logger )
		self.CEngine.AttachProcess(mProcess)
		sleep(500)
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
		raw_input("Press any key to begin attack...\n")
		
		# Run the auto-it script that will press "Cancel" on the watson crash dump. Unfortunately this has to be clicked
		# before the process is terminated in order for a proper crashdump to be created.
		subprocess.Popen(['C:\\Program Files (x86)\\AutoIt3\\autoit3.exe', '.\\autoit\\watson_cancel.au3', ">nul"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		
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
		self.last_fault = time()-120000
		max_runtime = 5
		num_processes = 10
		unique_identifier = 1

		event_positions = {}
		
		while True:
			for j in range(len(report_events_by_target)):
				# Attack this occurrence of this event
				while len(processes) >= num_processes:
					#sleep(0.5)
					sleep(0.1)
					# Cleanup old processes
					for k in range(len(processes)):
						#if processes[k].attack_count > terminate_counts[k] or processes[k].terminated or int(time() - times[k]) > max_runtime:
						if int(time() - self.last_fault) > fault_pause and ( processes[k].terminated or int(time() - times[k]) > max_runtime ):
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
				newProcess = ProcessNotepad(self, "C:\\Crash\\", newBreakpoint, -1, unique_identifier, False )
				self.CEngine.AttachProcess(newProcess)
				unique_identifier+=1
				
				terminate_counts.append( event_positions[event_name] )
				times.append( time() )
				processes.append(newProcess)
	

#def on_crash(Engine, process, instance_argument, seed):
#    # Restart the instance but with a new seed so it doesn't just do the same thing again
#    seed = int(random()*100000)
#    print "Controller: Restarting crashed instance attacking '%s' with arguments '%s'." % (process, instance_arguments)
#    return [[process, instance_arguments]]