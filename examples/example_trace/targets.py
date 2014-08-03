from target_base import *
		

class Target_PrintExports(TargetBase):	
	
	# Override __init__()
	def __init__(self, Engine, ProcessBase):
		self.Engine = Engine
		self.ProcessBase = ProcessBase
		
		# List of libraries to potentially add hooks on.  Must be lowercase.
		self.libraries = []
		
		# Regex library name match pattern to add hooks on
		self.libraries_regex = re.compile("^((?!user32).)*$",re.IGNORECASE)
		
		# List of function names to add hooks on.  Must be lowercase.
		self.functions = []
		
		# Regex function name match pattern to add hooks on
		self.functions_regex = re.compile("^((?!DbgBreakPoint|SList|KiUserCallbackDispatcher).)*$",re.IGNORECASE)

		self.hook_exports = True   # Don't hook matching exports
		self.hook_symbols = False  # Hook matching symbols from pdb
	

	def breakpoint_hit(self, event_name, address, context, th):
		print event_name
		return [[],[]]

