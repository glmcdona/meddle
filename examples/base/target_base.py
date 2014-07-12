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

	