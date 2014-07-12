import System

FUZZ = True
NOFUZZ = False

class meddle_types():
	Engine = None;
	
	# Target specific variables. These may change depending
	# on if the target is running in x86 or x64 mode.
	options_buffer_size = 0x500;
	
	def __init__(self, Engine):
		self.Engine = Engine
	
	def size_ptr(self):
		if self.Engine.IsWin64:
			return 8
		return 4
	
	def size_long(self):
		if self.Engine.IsWin64:
			return 8
		return 4

	def size_short(self):
		return 2
		
	def size_int(self):
		return 4
	
	def fuzz_qword(self, generator, fuzz_block, context):
		if fuzz_block.GetSize() == 8:
			# Decide how it will be fuzzed
			type = generator.randint(1,120)
			result = False
			if type < 20:
				# Flip one to three random bits in the fuzz block
				num_bits = generator.randint(1,3)
				bit = 0
				for i in range(num_bits):
					bit = bit + (1 << generator.randint(0,63))
				new_value = (fuzz_block.GetValue(context)[0]) ^ bit
				result = fuzz_block.SetValue( new_value, context)
			elif type < 60:
				# Random byte at random position
				position = generator.randint(0,7)
				new_value = (generator.randint(0,0xff) << (position * 8)) ^ fuzz_block.GetValue(context)[0]
				result = fuzz_block.SetValue( new_value , context)
			elif type < 80:
				# Random word at random position
				position = generator.randint(0,3)
				new_value = (generator.randint(0,0xffff) << (position * 16)) ^ fuzz_block.GetValue(context)[0]
				result = fuzz_block.SetValue( new_value , context)
			elif type < 90:
				# Random dword at random position
				position = generator.randint(0,1)
				new_value = (generator.randint(0,0xffffffff) << (position * 16)) ^ fuzz_block.GetValue(context)[0]
				result = fuzz_block.SetValue( new_value , context)
			elif type < 100:
				result = fuzz_block.SetValue( generator.randint(0,1) , context)
			elif type <= 120:
				# Fuzz the whole qword block
				result = fuzz_block.SetValue( generator.randint(0,0xffffffffffffffff) , context)
			if not result:
				print "Failed to fuzz block: %s" % fuzz_block.ToString()
		else:
			print "Failed to fuzz block. It is not a qword: %s" % fuzz_block.ToString()
		
	
	def pascal(self, arg_specs):
		# Convert the arg_specs into both a register and stack spec
		# according to the PASCAL calling convention.
		# Input like:
		# [types.size_ptr , None, NOFUZZ, "returnAddress"],
		# [types.size_ptr , None, NOFUZZ, "hDevice"],
		
		if self.size_ptr() == 8:
			# Win64 PASCAL is WINAPI it seems.
			return self.winapi(arg_specs);
		else:
			# http://en.wikipedia.org/wiki/X86_calling_conventions#pascal
			# Stack left to right (other conventions is right-to-left)
			# No register arguments.
			# No difference between x86 and x64 specs.
			regspec = []
			
			# Return address
			stackspec = [[self.size_ptr() , None, NOFUZZ, "returnAddress", None]]
				
			# Stack arguments
			for i in range(len(arg_specs)):
				arg = arg_specs[i]
				#stackspec.insert(1,arg);
				stackspec += [arg];
			
			return [regspec, stackspec]
	
	def winapi(self, arg_specs):
		# Convert the arg_specs into both a register and stack spec
		# according to the WINAPI calling convention.
		# Input like:
		# [ {"name": "socket",
		#	 "size": self.ProcessBase.types.size_ptr(),
		#	 "type": None,
		#    "fuzz": NOFUZZ }, ]
		
		# Output like:
		# regspec, stackspec
		#
		# regspec: [{"name": "socket",
		#			 "register": "rcx",
		#			 "type": None,
		#			 "fuzz": NOFUZZ},]
		#
		# stackspec: [{"name": "socket",
		#			   "size": 4,
		#			   "type": None,
		#			   "fuzz": NOFUZZ},]
		
		if self.Engine.IsWin64:
			# http://msdn.microsoft.com/en-us/magazine/cc300794.aspx
			#RCX: 1st integer argument
			#RDX: 2nd integer argument
			#R8: 3rd integer argument
			#R9: 4th integer argument
			# arguments on stack afterwards with reserved stack space
			regspec = []
			
			# Return address
			stackspec = [{"name":"returnAddress", "size":self.size_ptr(), "type":None, "fuzz":NOFUZZ}]
			
			# Reserved stack space. One for each register argument.
			for i in range(min([4, len(arg_specs)])):
				stackspec.append({"name":"_reserved%i"%i, "size":self.size_ptr(), "type":None, "fuzz":NOFUZZ})
				
			# Stack and register arguments
			for i in range(len(arg_specs)):
				arg = arg_specs[i]
				
				if i <= 3:
					# Register argument
					del arg["size"]
					
					if i == 0:
						arg["register"] = "rcx"
					elif i == 1:
						arg["register"] = "rdx"
					elif i == 2:
						arg["register"] = "r8"
					elif i == 3:
						arg["register"] = "r9"
					
					regspec.append(arg)
				else:
					# Stack argument
					stackspec.append(arg);
			
		else:
			# All stack arguments by 32bit convention
			regspec = []
			stackspec += arg_specs
			
		return [regspec, stackspec]

	# Return an array that specifies the structure and which
	# members should be fuzzed. An array of variable descriptions
	# is returned. Simply put, an array of arrays is returned, with each
	# array describing a single argument. The single argument can be
	# defined as a point to another type by embedding a reference to
	# the type parser of the pointed-to type. The address is provided as
	# an input structure incase the structure depends on the data values.
	# The target is provided as input to be able to access target specific
	# information, such as maybe looking up the device name corresponding to
	# a parsed device handle.
	# 
	# A few basic variable examples:
	#  struct MyStruct{
	#   SomeStruct* myVar; 
	#  }                      ==> [[size_ptr, parse_SomeStruct, NOFUZZ, "myVar"]]
	#  struct MyStruct{
	#   int test;
	#   SomeStruct* myVar; 
	#  }                      ==> [[size_int, None, FUZZ, "test"],
	#							   [size_ptr, parse_SomeStruct, NOFUZZ, "myVar"]]
	#  struct MyStruct{
	#   SomeStruct  myVar; 
	#  }                      ==> this.parse_SomeStruct(target, address)
	#  struct MyStruct{
	#   int test;
	#   SomeStruct  myVar; 
	#  }                      ==> [[size_int, None, FUZZ, "test"]] +
	# 							   this.parse_SomeStruct(target, address + size_int)
	# 
	# A full description for sample struct like:
	#  struct Handshake {
	#	  Hand* otherHand;
	#     Hand myHand;
	#	  long strength;
	#	} ;
	#
	#  struct Hand {
	#	  long warmth;
	#	  long owner_id;
	#	} ;
	#
	# Should be described like:
	#
	# def parse_Handshake(self, target, address, extra_name):
	#  return [[size_ptr, parse_Hand, NOFUZZ, extra_name + "otherHand"]] +
	#		   parse_Hand(target, address+size_ptr, extra_name + "myHand_") +
	#		  [[size_long, None, FUZZ, extra_name + "strength"]]
	#
	# def parse_Hand(self, target, address, extra_name):
	#  return [[size_long, None, FUZZ, extra_name + "warmth"],
	#		   [size_long, None, FUZZ, extra_name + "owner_id"]]
	#
	# From python, these arguments are then accessible easily by:
	#  arguments.otherHand.warmth.ToLong()
	#  arguments.otherHand.owner_id.ToLong()
	#  arguments.myHand_warmth.ToLong()
	#  arguments.myHand_owner_id.ToLong()
	#  arguments.strength.ToLong()
	
	
	
	def parse_HANDLE(self, address, extra_name, size_override):
		# Handles are usually not fuzzed.
		return [ {"name": extra_name + "HANDLE",
				  "size": self.size_long(),
				  "type": None,
				  "fuzz": NOFUZZ } ]

	  
	def parse_BUFFER(self, address, extra_name, size_override):
		return [ {"name": extra_name + "BUFFER",
				  "size": size_override,
				  "type": None,
				  "fuzz": FUZZ } ]

	def parse_OBJECT_ATTRIBUTES(self, address, extra_name, size_override):
		#typedef struct _OBJECT_ATTRIBUTES {
		#  ULONG           Length;
		#  HANDLE          RootDirectory;
		#  PUNICODE_STRING ObjectName;
		#  ULONG           Attributes;
		#  PVOID           SecurityDescriptor;
		#  PVOID           SecurityQualityOfService;
		#}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
		return [ {"name": extra_name + "Length",
				  "size": self.size_ptr(),
				  "type": None,
				  "fuzz": FUZZ },
				  {"name": extra_name + "RootDirectory",
				  "size": self.size_ptr(),
				  "type": None,
				  "fuzz": FUZZ },
				  {"name": extra_name + "ObjectName",
				  "size": self.size_ptr(),
				  "type": self.parse_UNICODE_STRING,
				  "fuzz": FUZZ },
				  {"name": extra_name + "Attributes",
				  "size": self.size_ptr(),
				  "type": None,
				  "fuzz": FUZZ },
				  {"name": extra_name + "SecurityDescriptor",
				  "size": self.size_ptr(),
				  "type": None,
				  "fuzz": FUZZ },
				  {"name": extra_name + "SecurityQualityOfService",
				  "size": self.size_ptr(),
				  "type": None,
				  "fuzz": FUZZ } ]

	def parse_UNICODE_STRING(self, address, extra_name, size_override):
		#typedef struct _UNICODE_STRING {
		#  USHORT Length;
		#  USHORT MaximumLength;
		#  PWSTR  Buffer;
		#} UNICODE_STRING, *PUNICODE_STRING;
		return [ {"name": extra_name + "Length",
				  "size": self.size_short(),
				  "type": None,
				  "fuzz": FUZZ },
				  {"name": extra_name + "MaximumLength",
				  "size": self.size_short(),
				  "type": None,
				  "fuzz": FUZZ },
				  {"name": extra_name + "_padding",
				  "size": 4,
				  "type": None,
				  "fuzz": FUZZ },
				  {"name": extra_name + "Buffer",
				  "size": self.size_ptr(),
				  "type": None,
				  "fuzz": FUZZ } ]

	def parse_BUFFER_PTR(self, address, extra_name, size_override):
		return [ {"name": extra_name + "BUFFER_PTR",
				  "size": self.size_ptr(),
				  "type": self.parse_BUFFER,
				  "size_override": size_override,
				  "fuzz": FUZZ } ]

	def parse_BUFFER_PTR_TABLE(self, address, extra_name, size_override):
		return [ {"name": extra_name + "BUFFER_PTR1",
				  "size": self.size_ptr(),
				  "type": self.parse_BUFFER,
				  "size_override": size_override,
				  "fuzz": FUZZ },
				  {"name": extra_name + "BUFFER_PTR2",
				  "size": self.size_ptr(),
				  "type": self.parse_BUFFER,
				  "size_override": size_override,
				  "fuzz": FUZZ },
				  {"name": extra_name + "BUFFER_PTR3",
				  "size": self.size_ptr(),
				  "type": self.parse_BUFFER,
				  "size_override": size_override,
				  "fuzz": FUZZ },
				  {"name": extra_name + "BUFFER_PTR4",
				  "size": self.size_ptr(),
				  "type": self.parse_BUFFER,
				  "size_override": size_override,
				  "fuzz": FUZZ },
				  {"name": extra_name + "BUFFER_PTR5",
				  "size": self.size_ptr(),
				  "type": self.parse_BUFFER,
				  "size_override": size_override,
				  "fuzz": FUZZ },
				  {"name": extra_name + "BUFFER_PTR6",
				  "size": self.size_ptr(),
				  "type": self.parse_BUFFER,
				  "size_override": size_override,
				  "fuzz": FUZZ } ]
	
