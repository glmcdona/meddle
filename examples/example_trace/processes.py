from process_base import *
from targets import *


class ProcessTrace(ProcessBase):
	def __init__(self, path_to_exe, command_line, Controller, crashdump_folder, breakpoint_handler, pid, ph, unique_identifier, verbose):
		# Specific options
		self.path_to_exe = bytes(path_to_exe,'utf-8')
		self.command_line = bytes(command_line,'utf-8')
		
		# Initialize
		self.initialize(Controller, self.__class__.__name__, crashdump_folder, breakpoint_handler, pid, ph, unique_identifier, verbose)
		
	def on_debugger_attached(self, Engine):
		# Set the types
		self.Engine = Engine
		self.types = meddle_types(Engine)
		
		# Add the targets
		#Engine.AddTarget(Target_RDP_RC4)
		#Engine.AddTarget(Target_Handles)
		Engine.AddTarget(Target_PrintExports)
		
		# Handle process loaded
		Engine.HandleProcessLoaded()
		
		# Resume the process that we created suspended. This is called just after the debugger has been attached.
		if self.start_th >= 0:
			windll.kernel32.ResumeThread(self.start_th);

	def log_csv(self, fields):
		self.logger.log_event(fields)
		
	
	
		
		
	