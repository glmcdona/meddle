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
							"type": self.ProcessBase.types.parse_BUFFER, "type_args": "InputBufferLength", "fuzz": NOFUZZ },

						   {"name": "InputBufferLength", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "OutputBuffer", "size": self.ProcessBase.types.size_ptr(),
							"type": self.ProcessBase.types.parse_BUFFER, "type_args": "OutputBufferLength", "fuzz": NOFUZZ },

						   {"name": "OutputBufferLength", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ } ]
			
			
			[reg_spec, stack_spec] = self.ProcessBase.types.pascal( parameters )
			arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)	
			
			name = "Driver unknown"
			if arguments.FileHandle.ToInt() in self.ProcessBase.handles:
				name = self.ProcessBase.handles[arguments.FileHandle.ToInt()]
			
			if self.ProcessBase.verbose:
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
			
			return [arguments.InputBuffer.GetFuzzBlockDescriptions(), "Send %s" % name]
			
			
		elif event_name == "return buffer":
			# Find the create file arguments corresponding to this return
			if str(th) in self.buffers:
				arguments = self.buffers[str(th)]
				del self.buffers[str(th)]

				name = "Driver unknown"
				if arguments.FileHandle.ToInt() in self.ProcessBase.handles:
					name = self.ProcessBase.handles[arguments.FileHandle.ToInt()]

				arguments.OutputBuffer.ParseChildren()

				if self.ProcessBase.verbose:
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
				return [arguments.OutputBuffer.GetFuzzBlockDescriptions(), "Receive %s" % name]

			self.Engine.RemoveBreakpoint(self, address)



		return [None, None]
