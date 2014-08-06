from target_base import *
from bisect import bisect
		

class Target_CleanModules(TargetBase):	
	
	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		#self.libraries = ["kernel32.dll","user32.dll"]
		self.libraries = []
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("a^",re.IGNORECASE) # match nothing
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = []
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("a^",re.IGNORECASE)

		self.hook_exports = False   # Don't hook matching exports
		self.hook_symbols = False  # Hook matching symbols from pdb

		# Don't log calls from these modules
		self.ProcessBase.clean_module_bases = []
		self.ProcessBase.clean_module_sizes = []
		self.ProcessBase.clean_modules_names = ["ntdll.dll","kernel32.dll","kernelbase.dll","advapi32.dll","msvcrt.dll","sechost.dll","rpcrt4.dll","sspicli.dll","cryptbase.dll","gdi32.dll","user32.dll","lpk.dll","usp10.dll","comdlg32.dll","shlwapi.dll","comctl32.dll","shell32.dll","winspool.drv","ole32.dll","oleaut32.dll","version.dll","ntdll.dll","kernel32.dll","kernelbase.dll","advapi32.dll","msvcrt.dll","sechost.dll","rpcrt4.dll","sspicli.dll","cryptbase.dll","gdi32.dll","user32.dll","lpk.dll","usp10.dll","comdlg32.dll","shlwapi.dll","comctl32.dll","shell32.dll","winspool.drv","ole32.dll","oleaut32.dll","version.dll"]

	def add_hooks(self):
		libraries = self.Engine.GetLoadedModules()
		
		for library_path in libraries:
			# Check to see if this library should be looked at
			library_name = library_path.split("\\")[-1].split("/")[-1].lower()

			# Add it to the clean library list maybe
			if library_name in self.ProcessBase.clean_modules_names:
				# Load the header
				header = self.Engine.GetLibraryHeader(library_name)
				library_base = self.Engine.GetModuleBase(library_name)
				library_size = header.optHeader.SizeOfImage
				insert_point = bisect (self.ProcessBase.clean_module_bases, library_base)
				self.ProcessBase.clean_module_bases.insert(insert_point, library_base)
				self.ProcessBase.clean_module_sizes.insert(insert_point, library_size)
	
	def module_loaded(self, library_path, library_base):
		TargetBase.module_loaded(self, library_path, library_base)

		# Any module loaded is considered a clean source.
		library_size = self.Engine.GetLibraryHeader(library_base).optHeader.SizeOfImage
		insert_point = bisect (self.ProcessBase.clean_module_bases, library_base)
		self.ProcessBase.clean_module_bases.insert(insert_point, library_base)
		self.ProcessBase.clean_module_sizes.insert(insert_point, library_size)

	def breakpoint_hit(self, event_name, address, context, th):
		return [[],[]]

class Target_LogUntrusted(TargetBase):	
	
	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		#self.libraries = ["kernel32.dll","user32.dll"]
		#self.libraries = ["ntdll.dll"]
		self.libraries = []
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("^((?!user32).)*$",re.IGNORECASE) # match nothing
		#self.libraries_regex = re.compile("a^",re.IGNORECASE) # match everything
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = []
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("^((?!DbgBreakPoint|SList|KiUserCallbackDispatcher|memcpy).)*$",re.IGNORECASE)

		self.hook_exports = True   # Don't hook matching exports
		self.hook_symbols = False  # Hook matching symbols from pdb


	def breakpoint_hit(self, event_name, address, context, th):
		# Parse the return address
		reg_spec = []
		stack_spec = [{"name":"returnAddress", "size": self.ProcessBase.types.size_ptr(), "type":None, "fuzz":NOFUZZ}]
		arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)

		# Check if the return address is in a trusted module
		return_address = arguments.returnAddress.ToLong()
		if return_address != 0:
			closest_module = bisect (self.ProcessBase.clean_module_bases, return_address ) - 1

			
			if closest_module >= 0 and closest_module < len(self.ProcessBase.clean_module_bases) and return_address >= self.ProcessBase.clean_module_bases[closest_module] and return_address - self.ProcessBase.clean_module_bases[closest_module] < self.ProcessBase.clean_module_sizes[closest_module]:
				# Return address is in a clean module
				#print "CLEAN %s" % event_name
				pass
			else:
				# Return address is in an unclean module
				#for base in self.ProcessBase.clean_module_bases:
				#	self.ProcessBase.log_event("%x\r\n" % base)
				
				#self.ProcessBase.log_event("%x ret closest %x size %x\r\n" % (return_address, self.ProcessBase.clean_module_bases[closest_module], self.ProcessBase.clean_module_sizes[closest_module]) )
				# Attempt a rough parsing of any string arguments from the arguments
				parameters = [ {"name": "Arg1", "size": self.ProcessBase.types.size_ptr(),
								"type": None, "fuzz": NOFUZZ },
							   
							   {"name": "Arg2", "size": self.ProcessBase.types.size_ptr(),
								"type": None, "fuzz": NOFUZZ },
							   
							   {"name": "Arg3",	"size": self.ProcessBase.types.size_ptr(),
								"type": None, "fuzz": NOFUZZ },
							   
							   {"name": "Arg4", "size": self.ProcessBase.types.size_ptr(),
								"type": None, "fuzz": NOFUZZ },

							   {"name": "Arg5", "size": self.ProcessBase.types.size_ptr(),
								"type": None, "fuzz": NOFUZZ},

							   {"name": "Arg6", "size": self.ProcessBase.types.size_ptr(),
								"type": None, "fuzz": NOFUZZ } ]
				[reg_spec, stack_spec] = self.ProcessBase.types.winapi( parameters )
				arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)

				strings = [arguments.Arg1.ReadString(),arguments.Arg2.ReadString(),arguments.Arg3.ReadString(),arguments.Arg4.ReadString(),arguments.Arg5.ReadString(),arguments.Arg6.ReadString()]
				strings = [i for i in strings if len(i) >= 4]

				self.ProcessBase.log_event("%s called from 0x%x: %s\r\n" % (event_name, return_address, ",".join(strings).replace("\r","\\r").replace("\n","\\n")))

		return [[],[]]


class Target_LogRegistry(TargetBase):	
	
	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = []
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("^((?!user32).)*$",re.IGNORECASE)
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = [x.lower() for x in ["NtQueryValueKey", "NtSetValueKey"]]
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("a^",re.IGNORECASE)

		self.hook_exports = True   # Don't hook matching exports
		self.hook_symbols = False  # Hook matching symbols from pdb

		self.buffers = {}

	def breakpoint_hit(self, event_name, address, context, th):
		# Parse the return address
		reg_spec = []
		if event_name.lower().find("ntqueryvaluekey") >= 0:
			parameters = [ {"name": "KeyHandle", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "ValueName", "size": self.ProcessBase.types.size_ptr(),
							"type": self.ProcessBase.types.parse_UNICODE_STRING, "fuzz": NOFUZZ },
						   
						   {"name": "KeyValueInformationClass",	"size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "KeyValueInformation", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "Length", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ},

						   {"name": "ResultLength", "size": self.ProcessBase.types.size_ptr(),
							"type": self.ProcessBase.types.parse_DWORD, "fuzz": NOFUZZ } ]
			[reg_spec, stack_spec] = self.ProcessBase.types.winapi( parameters )
			arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)

			self.buffers[str(th)] = arguments

			self.Engine.AddBreakpoint(self, arguments.returnAddress.ToPtr(), "return buffer")

			# Log this key was opened
			name = "unknown"
			if arguments.KeyHandle.ToInt() in self.ProcessBase.handles:
				name = self.ProcessBase.handles[arguments.KeyHandle.ToInt()]

			valueName = arguments.ValueName.Buffer.ReadString()
			if len(valueName) == 0:
				valueName = "(default)"

			self.ProcessBase.log_event("NtQueryValueKey\r\n\tKey: %s\r\n\tName: %s\r\n" % (name, valueName))

		elif event_name.lower().find("return buffer") >= 0:
			# Find the create file arguments corresponding to this return
			if str(th) in self.buffers:
				arguments = self.buffers[str(th)]
				del self.buffers[str(th)]

				# Check for error codes
				return_value = context.rax
				if return_value == 0: # STATUS_SUCCESS
					arguments.ResultLength.ParseChildren() # Update the "ResultLength" field
					result_length = arguments.ResultLength.dword.ToInt()

					parameters = [ {"name": "KeyValueInformationBuffer", "size": result_length,
									"type": None, "fuzz": NOFUZZ } ]
					read_buffer = self.Engine.ParseStructure(parameters, arguments.KeyValueInformation.ToLong())

					name = "unknown"
					if arguments.KeyHandle.ToInt() in self.ProcessBase.handles:
						name = self.ProcessBase.handles[arguments.KeyHandle.ToInt()]

			self.Engine.RemoveBreakpoint(self, address)

		elif event_name.lower().find("ntsetvaluekey") >= 0:
			parameters = [ {"name": "KeyHandle", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "ValueName", "size": self.ProcessBase.types.size_ptr(),
							"type": self.ProcessBase.types.parse_UNICODE_STRING, "fuzz": NOFUZZ },
						   
						   {"name": "TitleIndex",	"size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "Type", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "Data", "size": self.ProcessBase.types.size_ptr(),
							"type": self.ProcessBase.types.parse_BUFFER, "type_args": "DataSize", "fuzz": NOFUZZ},

						   {"name": "DataSize", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ } ]
			[reg_spec, stack_spec] = self.ProcessBase.types.winapi( parameters )
			arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)

			name = "unknown"
			if arguments.KeyHandle.ToInt() in self.ProcessBase.handles:
				name = self.ProcessBase.handles[arguments.KeyHandle.ToInt()]

			valueName = arguments.ValueName.Buffer.ReadString()
			if len(valueName) == 0:
				valueName = "(default)"
			self.ProcessBase.log_event("NtSetValueKey\r\n\tKey: %s\r\n\tName:%s\r\n\tData:%s\r\n\t%s\r\n" % (name,valueName,arguments.Data.BUFFER.ToAscii(),arguments.Data.BUFFER.ToHex()))
			

		return [[],[]]




