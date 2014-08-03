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
		count = 0
		for export in exports:
			if export.lower() in self.functions or re.match(self.functions_regex, export):
				# Lookup the corresonding address
				address = self.Engine.GetProcedureAddress(header, export)
				
				# Add the breakpoint with eventname "{module}::{function name}"
				self.Engine.AddBreakpoint(self, address, "%s::%s" % (library_name, export))
				count+=1
		
		if self.ProcessBase.verbose:
			print "added %i hooks on exports in %s" % ( count, library_name ) 

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
		count = 0
		for symbol in symbol_rows:
			split_symbol = symbol.split(" ")
			if len(split_symbol) == 2:
				symbol_name = split_symbol[1].strip()
				if re.match(self.functions_regex, symbol_name) or symbol_name.lower() in self.functions:
					# Add a breakpoint
					symbol_address = int(split_symbol[0],16) + library_base
					self.Engine.AddBreakpoint(self, symbol_address, "%s::%s" % (library_name, symbol_name))
					count+=1

		if self.ProcessBase.verbose:
			print "added %i hooks on symbols in %s" % ( count, library_name ) 

	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
	
	
	def get_name(self):
		return self.__class__.__name__


class Target_Handles(TargetBase):

	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		self.buffers = {}
		self.ProcessBase.handles = {}
		self.ProcessBase.handles[0] = "invalid handle"
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = ["ntdll.dll"]
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("a^",re.IGNORECASE) # match nothing
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = ["ntopenfile","ntcreateevent","ntcreatefile","zwopenfile","zwcreateevent","zwcreatefile","zwopenkey","zwcreatekey","ntopenkey","ntcreatekey","zwopenkeyex","ntopenkeyex"]
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("a^",re.IGNORECASE)

		self.hook_exports = True   # Hook matching exports
		self.hook_symbols = False  # Don't hook matching symbols from pdb
		
	def breakpoint_hit(self, event_name, address, context, th):
		if event_name == "return handle":
			if str(th) in self.buffers:
				# Extract the handle name
				old_args = self.buffers[str(th)]
				name = old_args.PObjectAttributes.ObjectName.Buffer.ReadString()
				root_name = ""
				root_handle = old_args.PObjectAttributes.RootDirectory.ToPtr()
				if root_handle != 0:
					# Relative to a root handle
					if root_handle in self.ProcessBase.handles:
						root_name = self.ProcessBase.handles[root_handle]
					else:
						root_name = "(unknown root 0x%x)" % root_handle
				handle = self.Engine.ReadDword(old_args.hFile.ToPtr())

				del self.buffers[str(th)]

				if handle != 0:
					# Add it to the process description
					#self.ProcessBase.log_event("HANDLERET LOG: " + hex(handle) + "->" + os.path.join(root_name,name) + "\r\n")
					if root_handle != 0:
						self.ProcessBase.handles[handle] = os.path.join(root_name,name)
					else:
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
			[reg_spec, stack_spec] = self.ProcessBase.types.winapi( parameters )
			arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)

			if arguments.PObjectAttributes.ToLong() != 0:
				# Record this filename. We don't know which handle yet.
				self.buffers[str(th)] = arguments;

				# Add a breakpoint on the return address to gather the resulting handle
				self.Engine.AddBreakpoint(self, arguments.returnAddress.ToPtr(), "return handle")

		return [None, None]


class Target_Fork(TargetBase):	
	
	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = ["kernel32.dll"]
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("a^",re.IGNORECASE)
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = [x.lower() for x in ["CreateProcessW"]]
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("a^",re.IGNORECASE)
		#self.functions_regex = re.compile(".*reg.*",re.IGNORECASE)

		self.hook_exports = True   # Don't hook matching exports
		self.hook_symbols = False  # Hook matching symbols from pdb

		self.buffers = {}

	def breakpoint_hit(self, event_name, address, context, th):
		if event_name.lower().find("createprocessw") >= 0:
			parameters = [ {"name": "lpApplicationName", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "lpCommandLine", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "lpProcessAttributes",	"size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },
						   
						   {"name": "lpThreadAttributes", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "bInheritHandles", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ},

						   {"name": "dwCreationFlags", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "lpEnvironment", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "lpCurrentDirectory", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "lpStartupInfo", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ },

						   {"name": "lpProcessInformation", "size": self.ProcessBase.types.size_ptr(),
							"type": None, "fuzz": NOFUZZ } ]
			[reg_spec, stack_spec] = self.ProcessBase.types.winapi( parameters )
			arguments = self.Engine.ParseArguments(stack_spec, reg_spec, context)

			# Force it to start suspended
			CREATE_SUSPENDED = 0x00000004
			suspend_switched = False
			if not (arguments.dwCreationFlags.ToLong() & CREATE_SUSPENDED):
				# Switch it to be created suspended
				arguments.dwCreationFlags.SetDword(arguments.dwCreationFlags.ToLong() | CREATE_SUSPENDED, context)
				suspend_switched = True

			# Add a breakpoint after the process has been created
			self.buffers[str(th)] = [arguments, suspend_switched]
			self.Engine.AddBreakpoint(self, arguments.returnAddress.ToPtr(), "return process create")

		elif event_name.lower().find("return process create") >= 0:
			# Find the create file arguments corresponding to this return
			if str(th) in self.buffers:
				[arguments, suspend_switched] = self.buffers[str(th)]
				del self.buffers[str(th)]

				# Parse the lpProcessInformation now. It is set after the call
				spec = self.ProcessBase.types.parse_PROCESS_INFORMATION(None, None, "", None)
				new_process = self.Engine.ParseStructure(spec, arguments.lpProcessInformation.ToLong())

				# Fork our measuring by creating a new monitoring process
				new_pid = new_process.dwProcessId.ToLong()
				new_tid = new_process.dwThreadId.ToLong()
				new_ph = new_process.hProcess.ToLong()
				self.ProcessBase.Controller.process_fork(new_pid, new_tid, new_ph, suspend_switched)


			self.Engine.RemoveBreakpoint(self, address)

		return [[],[]]