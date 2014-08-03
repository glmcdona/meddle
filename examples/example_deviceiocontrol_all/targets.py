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
			
			
			[reg_spec, stack_spec] = self.ProcessBase.types.winapi( parameters )
			arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)	
			
			name = "device unknown"
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
			fields["timestamp"] = str(datetime.datetime.now())
			fields["process_name"] = self.Engine.GetProcessName()
			fields["type"] = "InputBuffer"
			fields["pid"] = str(self.ProcessBase.pid)
			fields["device_name"] = name
			fields["device_h"] = str(arguments.FileHandle.ToInt())
			fields["data_base64"] = arguments.InputBuffer.BUFFER.ToBase64()
			self.ProcessBase.log_csv(fields)
			
			return [arguments.InputBuffer.GetFuzzBlockDescriptions(), name]
			
			
		elif event_name == "return buffer":
			# Find the create file arguments corresponding to this return
			if str(th) in self.buffers:
				arguments = self.buffers[str(th)]
				del self.buffers[str(th)]

				name = "device unknown"
				if arguments.FileHandle.ToInt() in self.ProcessBase.handles:
					name = self.ProcessBase.handles[arguments.FileHandle.ToInt()]

				arguments.OutputBuffer.ParseChildren()

				if self.ProcessBase.verbose:
					print name
					print arguments.OutputBuffer.BUFFER.ToString()

				# Log the event
				fields = {}
				fields["timestamp"] = str(datetime.datetime.now())
				fields["process_name"] = self.Engine.GetProcessName()
				fields["type"] = "OutputBuffer"
				fields["pid"] = str(self.ProcessBase.pid)
				fields["device_name"] = name
				fields["device_h"] = str(arguments.FileHandle.ToInt())
				fields["data_base64"] = arguments.OutputBuffer.BUFFER.ToBase64()
				self.ProcessBase.log_csv(fields)

				self.Engine.RemoveBreakpoint(self, address)
				return [arguments.OutputBuffer.GetFuzzBlockDescriptions(), name]

			self.Engine.RemoveBreakpoint(self, address)



		return [None, None]
