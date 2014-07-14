from target_base import *
		

class Target_PrintSymbols(TargetBase):	
	
	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = ["mstscax.dll"]
		
		# Regex library name match pattern to add hooks on
		#self.libraries_regex = re.compile("^((?!kernel|user|ntdll).)*$",re.IGNORECASE) # match nothing
		self.libraries_regex = re.compile("a^",re.IGNORECASE) # match nothing
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = []
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile(".*(encrypt|rc4|decrypt|receive).*",re.IGNORECASE)
		self.functions_regex = re.compile(".*",re.IGNORECASE)

		self.hook_exports = False   # Don't hook matching exports
		self.hook_symbols = True  # Hook matching symbols from pdb
	

	def breakpoint_hit(self, event_name, address, context, th):
		print event_name
		return [[],[]]


class Target_RDP_RC4(TargetBase):	
	
	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = ["mstscax.dll"]
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("a^",re.IGNORECASE) # match nothing
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = ["rc4"]
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("a^",re.IGNORECASE) # match nothing

		self.hook_exports = False   # Don't hook matching exports
		self.hook_symbols = True  # Hook matching symbols from pdb
	

	def breakpoint_hit(self, event_name, address, context, th):
		if event_name.strip() == "mstscax.dll::rc4":
			parameters = [ {"name": "key", "size": self.ProcessBase.types.size_ptr(),
							"type": None,
							"fuzz": NOFUZZ },

							{"name": "size", "size": self.ProcessBase.types.size_ptr(),
							"type": None,
							"fuzz": NOFUZZ },

							{"name": "buffer", "size": self.ProcessBase.types.size_ptr(),
							"type": self.ProcessBase.types.parse_BUFFER, "size_override": "size",
							"fuzz": NOFUZZ }, ]

			
			[reg_spec, stack_spec] = self.ProcessBase.types.pascal( parameters )
			
			arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)		
			
			if self.ProcessBase.verbose:
				print arguments.buffer.BUFFER.ToString("RC4 buffer")

			return [arguments.GetFuzzBlockDescriptions(), "RC4 buffer"]

		return [[],[]]

		
class Target_Winsock_Send(TargetBase):	
	
	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = ["ws2_32.dll"]
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("a^",re.IGNORECASE) # match nothing
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = ["send", "wsasend"]
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("a^",re.IGNORECASE) # match nothing

		self.hook_exports = True   # Hook matching exports
		self.hook_symbols = False  # Don't hook matching symbols from pdb
		
	def breakpoint_hit(self, event_name, address, context, th):
		if event_name == "ws2_32.dll::send":
			parameters = [ {"name": "socket", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "buffer", "size": self.ProcessBase.types.size_ptr(),
							"type": self.ProcessBase.types.parse_BUFFER, "type_args": "size",
							"fuzz": NOFUZZ },
						   
						   {"name": "size",	"size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "flags", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ } ]

			[reg_spec, stack_spec] = self.ProcessBase.types.pascal( parameters )
			arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)
			
			
			if self.ProcessBase.verbose:
				print "Sent size = %i" % arguments.size.ToInt()
				print arguments.buffer.BUFFER.ToString()

			return [arguments.GetFuzzBlockDescriptions(), "Winsock Send Event"]
		elif event_name == "ws2_32.dll::WSASend":
			parameters = [ {"name": "socket", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "lpBuffers", "size": self.ProcessBase.types.size_ptr(),
							"type": self.ProcessBase.types.parse_WSABUF_ARRAY, "type_args": "dwBufferCount",
							"fuzz": NOFUZZ },
						   
						   {"name": "dwBufferCount",	"size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "lpNumberOfBytesSent", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "dwFlags", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "lpOverlapped", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "lpCompletionRoutine", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ } ]
			[reg_spec, stack_spec] = self.ProcessBase.types.pascal( parameters )
			arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)
			if self.ProcessBase.verbose:
				print arguments.lpBuffers.ToString()

			return [arguments.GetFuzzBlockDescriptions(), "Winsock WSASend Event"]

		return [None, None]

		



		
class Target_Winsock_Receive(TargetBase):	
	
	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		self.buffers = {}
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = ["ws2_32.dll"]
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("'a^'",re.IGNORECASE) # match nothing
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = ["recv"]
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("'a^'",re.IGNORECASE) # match nothing

		self.hook_exports = True   # Hook matching exports
		self.hook_symbols = False  # Don't hook matching symbols from pdb
		
		
	def breakpoint_hit(self, event_name, address, context, th):
		if event_name == "ws2_32.dll::recv":
			# Start of the function, record the input arguments.
			parameters = [ {"name": "socket", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "buffer", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "size",	"size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "flags", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ } ]
		
			
			[reg_spec, stack_spec] = self.ProcessBase.types.pascal( parameters )
			
			arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)
			
			# Add breakpoint at ret address
			self.Engine.AddBreakpoints(self, arguments.returnAddress.ToPtr(), "ws2_32.dll::recv_ret")
			self.buffers[str(th)] = arguments;
		else:
			# Return address of the function, extract buffer now that it has received data.
			parameters = [ {"name": "read_size", "register": "rax",
							"type": None, "fuzz": NOFUZZ } ]
			arguments = self.Engine.ParseArguments([], parameters, context)
			
			if str(th) in self.buffers:
				old_args = self.buffers[str(th)]
				del self.buffers[str(th)]
				self.Engine.RemoveBreakpoints(self, [address])
				
				if arguments.read_size.ToInt() > 0:
					parameters = [ {"name": "Received", "size": arguments.read_size.ToInt(),
								    "type": None, "fuzz": FUZZ } ]
					data = self.Engine.ParseStructure(parameters, old_args.buffer.ToLong())
					
					if self.ProcessBase.verbose:
						print data.ToString()
				
					# Return the received buffer fuzz blocks
					if arguments.read_size.ToInt() <= old_args.size.ToInt():
						return [data.GetFuzzBlockDescriptions(), "Winsock Receive Event"]
		
		return [None, None]
