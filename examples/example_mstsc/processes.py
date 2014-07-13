from process_base import *
from targets import *

class ProcessRdp(ProcessBase):
	def __init__(self, Controller, crashdump_folder, breakpoint_handler, pid, unique_identifier, verbose, server):
		# Specific options
		self.path_to_exe = b"C:\\Windows\\System32\\mstsc.exe"
		self.command_line = bytes("mstsc.exe /v:%s" % server,'utf-8')
		
		# Initialize
		self.initialize(Controller, self.__class__.__name__, crashdump_folder, breakpoint_handler, pid, unique_identifier, verbose)
		
	def on_debugger_attached(self, Engine):
		# Set the types
		self.Engine = Engine
		self.types = meddle_types(Engine)
		
		# Add the targets
		#Engine.AddTarget(Target_RDP_RC4)
		Engine.AddTarget(Target_Winsock_Send)
		
		# Handle process loaded
		Engine.HandleProcessLoaded()
		
		# Resume the process that we created suspended. This is called just after the debugger has been attached.
		if self.start_th >= 0:
			windll.kernel32.ResumeThread(self.start_th);

		
		
	