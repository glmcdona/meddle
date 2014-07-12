import sys
import random
import re
import datetime
import os
import string
import time

# Basic target description that will be inherited from
NOFUZZ = False
FUZZ = True

class TargetBase:
	argument_description_is_static = True # Change this to False to call get_arguments() every
										  # breakpoint request.
	
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = ["ws2_32.dll"]
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("'a^'",re.IGNORECASE) # match nothing
		
		# List of function names to add hooks on. Must be lowercase.
		self.functions = ["recv"]
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("'a^'",re.IGNORECASE) # match nothing

		self.hook_exports = True   # Hook matching exports
		self.hook_symbols = False  # Don't hook matching symbols from pdb
		
	def on_attached(self):
		# Place the hooks on any libraries that have already been loaded
		self.add_hooks()
		
	
	def module_loaded(self, library_path, library_base):
		library_name = library_path.split("\\")[-1].split("/")[-1].lower()
		self.add_hooks_base(library_name, library_path, library_base)
		
	
	def add_hooks_base(self, library_name, library_path, library_base):
		# Check to see if this library should be looked at
		if (library_name.lower() in self.libraries) or re.match(self.libraries_regex, library_name):
			if self.hook_exports:
				# Load the header
				header = self.Engine.GetLibraryHeader(library_base)

				# Hook the exports of this library
				self.add_hooks_exports_header(library_name, library_path, header)

			if self.hook_symbols:
				# Hook the symbols of this library
				self.add_hooks_symbols(library_name, library_path, library_base)
	
	
	def add_hooks(self):
		libraries = self.Engine.GetLoadedModules()
		
		for library_path in libraries:
			# Check to see if this library should be looked at
			library_name = library_path.split("\\")[-1].split("/")[-1].lower()
			if library_name in self.libraries or re.match(self.libraries_regex, library_name):
				if self.hook_exports:
					# Load the header
					header = self.Engine.GetLibraryHeader(library_name)

					# Hook the exports of this library
					self.add_hooks_exports_header(library_name, library_path, header)

				if self.hook_symbols:
					# Hook the symbols of this library
					self.add_hooks_symbols(library_name, library_path, self.Engine.GetModulesBase(library_name))
	

	def add_hooks_exports_header(self, library_name, library_path, header):
		# Load the exports
		exports = self.Engine.GetExportedFunctions(header)
		
		# Consider each export
		for export in exports:
			if export.lower() in self.functions or re.match(self.functions_regex, export):
				# Lookup the corresonding address
				address = self.Engine.GetProcedureAddress(header, export)
				
				# Add the breakpoint with eventname "{module}::{function name}"
				self.Engine.AddBreakpoint(self, address, "%s::%s" % (library_name, export))
				#self.ProcessBase.log( "adding hook %s, 0x%x" % ( "%s::%s" % (library_name, export), address ) )

	def add_hooks_symbols(self, library_name, library_path, library_base):
		# Extract or load the symbols for this library		
		if not os.path.isdir("symbols"):
			os.mkdir("symbols")

		symbols = "symbols\\%s.symbols" % library_name
		if not os.path.isfile(symbols):
			os.system("vcvars32.bat & dumpbin /pdata \"%s\" > %s.full" % (library_path, symbols) )
			f = open("%s.full" % symbols, "rb")
			symbol_rows = f.read().split("Function Name")[-1].strip().split("\r\n\r\n")[0].split("\r\n")
			f.close()

			f = open(symbols, "wb")
			for line in symbol_rows:
				if len(line.split(" ")) >= 7: # Has a name assigned to it
					f.write(line.split(" ")[3] + " " + line.split(" ")[7] + "\r\n")
			f.close()
		
		# Read in the existing symbols
		f = open(symbols, "rb")
		symbol_rows = f.readlines()
		f.close()

		# Walk through the symbols, setting breakpoints
		for symbol in symbol_rows:
			split_symbol = symbol.split(" ")
			if len(split_symbol) == 2:
				symbol_name = split_symbol[1].strip()
				if re.match(self.functions_regex, symbol_name) or symbol_name.lower() in self.functions:
					# Add a breakpoint
					symbol_address = int(split_symbol[0],16) + library_base
					self.Engine.AddBreakpoint(self, symbol_address, "%s::%s" % (library_name, symbol_name))

	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
	
	
	def get_name(self):
		return self.__class__.__name__

		

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
		self.libraries = ["ws2_32.dll", "mstscax.dll"]
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("a^",re.IGNORECASE) # match nothing
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = ["send"]
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("a^",re.IGNORECASE) # match nothing

		self.hook_exports = True   # Hook matching exports
		self.hook_symbols = False  # Don't hook matching symbols from pdb

		
	def breakpoint_hit(self, event_name, address, context, th):
		parameters = [ {"name": "socket", "size": self.ProcessBase.types.size_ptr(),
						"type": None, "fuzz": NOFUZZ },
					   
					   {"name": "buffer", "size": self.ProcessBase.types.size_ptr(),
						"type": self.ProcessBase.types.parse_BUFFER, "size_override": "size",
						"fuzz": NOFUZZ },
					   
					   {"name": "size",	"size": self.ProcessBase.types.size_ptr(),
						"type": None, "fuzz": NOFUZZ },
					   
					   {"name": "flags", "size": self.ProcessBase.types.size_ptr(),
						"type": None, "fuzz": NOFUZZ } ]
		
		[reg_spec, stack_spec] = self.ProcessBase.types.pascal( parameters )
		
		arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)		
		
		if self.ProcessBase.verbose:
			#print arguments.buffer.BUFFER.ToString("Sent")
			#print arguments.ToString()
			print "Sent size = %i" % arguments.size.ToInt()
			print arguments.buffer.BUFFER.ToString()
		
		return [arguments.GetFuzzBlockDescriptions(), "Winsock Send Event"]



		
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