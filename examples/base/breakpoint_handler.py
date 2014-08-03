import random, clr, sys, os
from meddle_types import *


class BreakpointMeasurement:
	def __init__(self):
		self.measurement = []
		
	def breakpoint_hit(self, parent, target, event_name, address, context, th):
		[fuzz_blocks, fuzz_name] = target.breakpoint_hit(event_name, address, context, th)
		
		if fuzz_blocks != None:
			# Record the possible attack
			self.measurement += [[target.__class__.__name__, fuzz_name, len(fuzz_blocks)]]
	
	def to_string(self):
		return "Breakpoint Handler: %s\r\n" % self.__class__.__name__

class BreakpointEmpty:
	def __init__(self):
		pass
		
	def breakpoint_hit(self, parent, target, event_name, address, context, th):
		target.breakpoint_hit(event_name, address, context, th)
	
	def to_string(self):
		return "Breakpoint Handler: %s\r\n" % self.__class__.__name__

class BreakpointAttackSequentially:
	def __init__(self, percent_to_attack, events_num_skip, fuzz_name_filter, seed):
		self.percent_to_attack = percent_to_attack
		self.events_num_skip = events_num_skip
		self.attack_count = 0
		self.fuzz_name_filter = fuzz_name_filter
		self.seed = seed
		self.generator = random.Random()
		self.generator.seed(seed)
		
	def to_string(self):
		return "Breakpoint Handler: %s\r\nseed: %i\r\nevents_num_skip: %i\r\nfuzz_name_filter: %s\r\npercent_to_attack: %i\r\n" % (self.__class__.__name__, self.seed, self.events_num_skip, self.fuzz_name_filter, self.percent_to_attack)
		
	def breakpoint_hit(self, parent, target, event_name, address, context, th):
		[fuzz_blocks, fuzz_name] = target.breakpoint_hit(event_name, address, context, th)
		
		if fuzz_blocks != None and (fuzz_name == self.fuzz_name_filter or len(self.fuzz_name_filter) == 0 ):
			self.attack_sequentually(parent, target, event_name, address, context, th, fuzz_blocks, fuzz_name)
			self.attack_count += 1
		
	def attack_sequentually(self, parent, target, event_name, address, context, th, fuzz_blocks, fuzz_name):
		if self.attack_count >= self.events_num_skip and len(fuzz_blocks) > 0:
			# Attack this event
			
			# Set the flag that we attacked this process
			parent.set_attacked()
			
			# Init
			fuzzed_indices = []
			log = ""
			
			# Select the number of blocks to attack
			num_blocks = int(float(len(fuzz_blocks)) * (self.percent_to_attack/100) + 0.5);
			if num_blocks == 0:
				num_blocks = 1
			print "attacking event %i %s: fuzzing %i of %i blocks." % ( self.attack_count, fuzz_name, num_blocks, len(fuzz_blocks) )
			
			# Attack each block
			for i in range(num_blocks):
				# Select a block to fuzz
				if len(fuzz_blocks) > 1:
					rnd = self.generator.randint(0,len(fuzz_blocks)-1)
					while rnd in fuzzed_indices:
						rnd = self.generator.randint(0,len(fuzz_blocks)-1)
				else:
					rnd = 0
				
				# Fuzz this block
				orig_value = fuzz_blocks[rnd].GetValue(context)[0]
				parent.types.fuzz_qword(self.generator, fuzz_blocks[rnd], context)
				fuzzed_indices.append(rnd)
				log += "fuzzing block %i at %s named %s from value 0x%x to 0x%x\r\n" % (rnd, fuzz_blocks[rnd].GetLocation(), fuzz_blocks[rnd].GetName(), orig_value, fuzz_blocks[rnd].GetValue(context)[0])
			
			parent.log("attacking event %i %s: fuzzing %i of %i blocks.\r\n" % ( self.attack_count, fuzz_name, num_blocks, len(fuzz_blocks) ))
			parent.log(log + "\r\n")
		
	