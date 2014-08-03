from process_base import *
from targets import *


class ProcessSandbox(ProcessBase):
	def __init__(self, Controller, crashdump_folder, breakpoint_handler, pid, unique_identifier, verbose, logger, path_to_exe, command_line, new_th, resume_th, new_ph):
		# Specific options
		self.path_to_exe = bytes(path_to_exe,'utf-8')
		self.command_line = bytes(command_line,'utf-8')
		self.logger = logger
		
		# Initialize
		self.initialize(Controller, self.__class__.__name__, crashdump_folder, breakpoint_handler, pid, new_ph, unique_identifier, verbose)

		# Resume thread upon attach
		if resume_th:
			self.start_th = new_th
		
	def on_debugger_attached(self, Engine):
		# Set the types
		self.Engine = Engine
		self.types = meddle_types(Engine)
		
		# Add the targets
		#Engine.AddTarget(Target_RDP_RC4)
		Engine.AddTarget(Target_Handles)
		Engine.AddTarget(Target_CleanModules)
		Engine.AddTarget(Target_LogRegistry)
		
		Engine.AddTarget(Target_LogUntrusted)
		Engine.AddTarget(Target_Fork)
		#Engine.AddTarget(Target_DeviceIoControl)
		
		# Handle process loaded
		Engine.HandleProcessLoaded()

	def log_event(self, data):
		self.logger.log_event(self.pid, data)
		
	
	
		
		
	