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


class Target_Handles(TargetBase):

	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		self.buffers = {}
		self.ProcessBase.handles = {}
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = ["ntdll.dll"]
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("a^",re.IGNORECASE) # match nothing
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = ["ntopenfile","ntcreateevent","ntcreatefile","zwopenfile","zwcreateevent","zwcreatefile"]
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("a^",re.IGNORECASE)

		self.hook_exports = True   # Hook matching exports
		self.hook_symbols = False  # Don't hook matching symbols from pdb
		
	def breakpoint_hit(self, event_name, address, context, th):
		if event_name == "return handle":
			if str(th) in self.buffers:
				# Extract the handle name
				name = self.buffers[str(th)].PObjectAttributes.ObjectName.Buffer.ReadString()
				handle = self.Engine.ReadDword(self.buffers[str(th)].hFile.ToPtr())
				del self.buffers[str(th)]
				
				# Add it to the process description
				#if self.ProcessBase.verbose:
				#	print "%s, 0x%x" % (name, handle)
				self.ProcessBase.handles[handle] = name

			# Remove this breakpoint
			self.Engine.RemoveBreakpoint(self, address)
		else:
			# All have the first three parameters the same.
			parameters = [ {"name": "hFile", "size": self.ProcessBase.types.size_ptr(),
						    "type": None, "fuzz": NOFUZZ },
					   
						   {"name": "DesiredAccess", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "PObjectAttributes", "size": self.ProcessBase.types.size_ptr(),
							"type": self.ProcessBase.types.parse_OBJECT_ATTRIBUTES, "fuzz": NOFUZZ } ]
			[reg_spec, stack_spec] = self.ProcessBase.types.pascal( parameters )
			arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)

			# Record this filename. We don't know which handle yet.
			self.buffers[str(th)] = arguments;

			# Add a breakpoint on the return address to gather the resulting handle
			self.Engine.AddBreakpoint(self, arguments.returnAddress.ToPtr(), "return handle")

		return [None, None]

class Target_DeviceIoControl(TargetBase):

	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		self.buffers = {}
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = ["ntdll.dll"]
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("a^",re.IGNORECASE) # match nothing
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = [("NtDeviceIoControlFile").lower()]
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("a^",re.IGNORECASE) # match nothing

		self.hook_exports = True   # Hook matching exports
		self.hook_symbols = False  # Don't hook matching symbols from pdb
	
	def breakpoint_hit(self, event_name, address, context, th):
		if event_name == "ntdll.dll::NtDeviceIoControlFile":
			parameters = [ {"name": "FileHandle", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "Event", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "ApcRoutine",	"size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "ApcContext", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "IoStatusBlock", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ},

						   {"name": "IoControlCode", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "InputBuffer", "size": self.ProcessBase.types.size_ptr(),
							"type": self.ProcessBase.types.parse_BUFFER, "size_override": "InputBufferLength", "fuzz": NOFUZZ },

						   {"name": "InputBufferLength", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "OutputBuffer", "size": self.ProcessBase.types.size_ptr(),
							"type": self.ProcessBase.types.parse_BUFFER, "size_override": "OutputBufferLength", "fuzz": NOFUZZ },

						   {"name": "OutputBufferLength", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ } ]
			
			
			[reg_spec, stack_spec] = self.ProcessBase.types.pascal( parameters )
			arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)	
			
			name = "Driver unknown"
			if arguments.FileHandle.ToInt() in self.ProcessBase.handles:
				name = self.ProcessBase.handles[arguments.FileHandle.ToInt()]
			
			print name
			print arguments.InputBuffer.BUFFER.ToString()

			if arguments.OutputBufferLength.ToInt() > 0:
				self.Engine.AddBreakpoint(self, arguments.returnAddress.ToPtr(), "return buffer")

			self.buffers[str(th)] = arguments;

			# Log the event
			fields = {}
			fields["timestamp"] = str(time.time())
			fields["process_name"] = self.ProcessBase.process_name
			fields["type"] = "InputBuffer"
			fields["pid"] = str(self.ProcessBase.pid)
			fields["device_name"] = name
			fields["device_h"] = str(arguments.FileHandle.ToInt())
			fields["data_base64"] = arguments.InputBuffer.BUFFER.ToBase64()
			self.ProcessBase.log_csv(fields)
			
			
			
			
		elif event_name == "return buffer":
			# Find the create file arguments corresponding to this return
			if str(th) in self.buffers:
				arguments = self.buffers[str(th)]
				del self.buffers[str(th)]

				name = "Driver unknown"
				if arguments.FileHandle.ToInt() in self.ProcessBase.handles:
					name = self.ProcessBase.handles[arguments.FileHandle.ToInt()]

				arguments.OutputBuffer.ParseChildren()

				print name
				print arguments.OutputBuffer.BUFFER.ToString()

				# Log the event
				fields = {}
				fields["timestamp"] = str(time.time())
				fields["process_name"] = self.ProcessBase.process_name
				fields["type"] = "OutputBuffer"
				fields["pid"] = str(self.ProcessBase.pid)
				fields["device_name"] = name
				fields["device_h"] = str(arguments.FileHandle.ToInt())
				fields["data_base64"] = arguments.OutputBuffer.BUFFER.ToBase64()
				self.ProcessBase.log_csv(fields)

			self.Engine.RemoveBreakpoint(self, address)

		return [None, None]
