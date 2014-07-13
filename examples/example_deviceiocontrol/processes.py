from process_base import *
from targets import *


class ProcessDeviceIo(ProcessBase):
	def __init__(self, Controller, crashdump_folder, breakpoint_handler, pid, unique_identifier, verbose, logger):
		# Specific options
		self.path_to_exe = b"C:\\Windows\\System32\\notepad.exe"
		self.command_line = b"notepad.exe"
		self.logger = logger
		
		# Initialize
		self.initialize(Controller, self.__class__.__name__, crashdump_folder, breakpoint_handler, pid, unique_identifier, verbose)
		
	def on_debugger_attached(self, Engine):
		# Set the types
		self.Engine = Engine
		self.types = meddle_types(Engine)
		
		# Add the targets
		#Engine.AddTarget(Target_RDP_RC4)
		Engine.AddTarget(Target_Handles)
		Engine.AddTarget(Target_DeviceIoControl)
		
		# Handle process loaded
		Engine.HandleProcessLoaded()
		
		# Resume the process that we created suspended. This is called just after the debugger has been attached.
		if self.start_th >= 0:
			windll.kernel32.ResumeThread(self.start_th);

	def log_csv(self, fields):
		self.logger.log_event(fields)
		
	
	
		
		
	