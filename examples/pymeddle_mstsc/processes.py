import datetime
import random
import clr
import sys
import os
import subprocess
import capture
from ctypes import *
from ctypes.wintypes import BOOL
from time import *
from meddle_types import *
from targets import *
from breakpoint_handler import *


BYTE      = c_ubyte
WORD      = c_ushort
DWORD     = c_ulong
LPBYTE    = POINTER(c_ubyte)
LPTSTR    = POINTER(c_char) 
HANDLE    = c_void_p
PVOID     = c_void_p
LPVOID    = c_void_p
UNIT_PTR  = c_ulong
SIZE_T    = c_ulong

class STARTUPINFO(Structure):
    _fields_ = [("cb",            DWORD),        
                ("lpReserv/ed",    LPTSTR), 
                ("lpDesktop",     LPTSTR),  
                ("lpTitle",       LPTSTR),
                ("dwX",           DWORD),
                ("dwY",           DWORD),
                ("dwXSize",       DWORD),
                ("dwYSize",       DWORD),
                ("dwXCountChars", DWORD),
                ("dwYCountChars", DWORD),
                ("dwFillAttribute",DWORD),
                ("dwFlags",       DWORD),
                ("wShowWindow",   WORD),
                ("cbReserved2",   WORD),
                ("lpReserved2",   LPBYTE),
                ("hStdInput",     HANDLE),
                ("hStdOutput",    HANDLE),
                ("hStdError",     HANDLE),]

class PROCESS_INFORMATION(Structure):
    _fields_ = [("hProcess",    HANDLE),
                ("hThread",     HANDLE),
                ("dwProcessId", DWORD),
                ("dwThreadId",  DWORD),]

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [("BaseAddress", PVOID),
                ("AllocationBase", PVOID),
                ("AllocationProtect", DWORD),
                ("RegionSize", SIZE_T),
                ("State", DWORD),
                ("Protect", DWORD),
                ("Type", DWORD),]

class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [("Length", DWORD),
                ("SecDescriptor", LPVOID),
                ("InheritHandle", BOOL)]



class ProcessBase:
	print_debugger_messages = False

	def __init__(self, Controller, crashdump_folder, breakpoint_handler, pid, unique_identifier, verbose):
		self.initialize(Controller, self.__class__.__name__, crashdump_folder, breakpoint_handler, pid, unique_identifier, verbose)
		self.start()

	def __del__(self):
		try:
			close(self.hlogfile)
		except:
			pass
		
	def initialize(self, Controller, process_name, crashdump_folder, breakpoint_handler, pid, unique_identifier, verbose):
		# General initialize
		self.unique_identifier = unique_identifier
		self.nokill = False
		self.attacked = False
		self.terminated = False
		self.Controller = Controller
		self.process_name = process_name
		self.breakpoint_handler = breakpoint_handler
		self.process_information = 0
		self.pid = -1
		self.ph = -1
		self.start_th = -1 # starting thread handle
		self.crashdump_binary = "C:\\Program Files (x86)\\Sysinternals\\procdump.exe"
		self.crashdump_folder = crashdump_folder
		self.verbose = verbose
		
		# Set the logfile and try delete
		if not os.path.isdir("logfiles"):
			os.mkdir("logfiles")

		self.logfile = "logfiles\\%s.log" % str(self.unique_identifier)
		self.hlogfile = open(self.logfile,"w+")
		
		# Attach or start the process
		if pid != -1:
			# Attach to existing process
			self.pid = process_information.dwProcessId
			self.start_th = -1
			self.ph = windll.kernel32.OpenProcess(2035711,True,self.pid)
		else:
			# Start and attach to new process, throws exception on fail
			self.start_new_process(self.path_to_exe, self.command_line)		
		
		# Log the new process
		self.log("Process Name: %s\r\nPid: %i\r\nUnique Identifier: %i\r\nTimestamp: %s\r\n" % (self.process_name, self.pid, self.unique_identifier, str(datetime.datetime.now())))
		self.log(self.breakpoint_handler.to_string())
	
	
	def start_new_process(self, path_to_exe, commandline):
		# Create a new process and attach to it.
	
		# Constants
		CREATE_NEW_CONSOLE = 0x00000010
		CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000
		CREATE_SUSPENDED = 0x00000004
		
		# Build startup info
		startupinfo = STARTUPINFO()
		process_information = PROCESS_INFORMATION()
		security_attributes = SECURITY_ATTRIBUTES()
		startupinfo.dwFlags = 0x0
		startupinfo.wShowWindow = 0x1
		startupinfo.cb = sizeof(startupinfo)
		security_attributes.Length = sizeof(security_attributes)
		security_attributes.SecDescriptior = None
		security_attributes.InheritHandle = True
		
		# Create suspended
		if windll.kernel32.CreateProcessA(path_to_exe,
										commandline,
										None,
										None,
										False,
										CREATE_SUSPENDED,
										None, # lpEnvironment
										None,
										byref(startupinfo),
										byref(process_information)):
			
			# Set information based on the new process
			self.pid = process_information.dwProcessId
			self.start_th = process_information.hThread
			self.ph = process_information.hProcess
			return True
		
		raise "Failed to CreateProcessA instance of '%s'. GetLastError = 0x%x." % (self.process_name, windll.kernel32.GetLastError())
		return False
	
	def breakpoint_hit(self, target, event_name, address, context, th):
		return self.breakpoint_handler.breakpoint_hit(self, target, event_name, address, context, th)
	
	def on_exception_last_chance(self, address, exception_code, full_exception):
		self.log("Last chance exception in pid %i.\r\naddress: 0x%x\r\nerror: %s\r\n" % (self.pid, address, full_exception.ToString()))
		
		# Tell self that when we stop not to kill the process
		self.nokill = True
		
		# Detach debugger
		self.Engine.Detach()
		
		# Manually take a dump of the current state
		out = self.take_dump()
		
		self.log("crashdump result: %s\r\n" % out)

	def on_exception_first_chance(self, address, exception_code, full_exception):
		self.log("First chance exception in pid %i.\r\naddress: 0x%x\r\nerror: %s\r\n" % (self.pid, address, full_exception.ToString()))
		
	def take_dump(self):
		# Create a crashdump of the process since watson seems to not always take a dump.
		self.log("Taking crashdump pid %i...\r\n" % self.pid)
		result = subprocess.Popen([self.crashdump_binary, "-ma", str(self.pid), self.crashdump_folder], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err = result.communicate()
		return out
	
	def on_process_terminated(self):
		self.log("Process terminated pid %i.\r\n" % self.pid)
		self.terminated = True
		
	def get_pid(self):
		return self.pid
		
	def get_name(self):
		return self.__class__.__name__
		
	def set_attacked(self):
		self.attacked = True
	
	def module_loaded(self, name, base):
		pass
		
	def log(self, data, flush=True):
		if self.verbose:
			print data
		
		self.hlogfile.write(data + "\r\n")

		if flush:
			self.hlogfile.flush()
	
	def stop(self):
		self.log("Stopping pid %i...\r\n" % self.pid)
		
		if self.pid != -1:
			# Kill the process
			if not self.ph:
				print "ERROR: No process handle found, unable to stop process."
				return
			windll.kernel32.TerminateProcess(self.ph,0)
			windll.kernel32.CloseHandle(self.ph)
		self.on_process_terminated()
	
	def on_debugger_attached(self):
		# Resume the process that we created suspended. This is called just after the debugger has been attached.
		if self.start_th >= 0:
			windll.kernel32.ResumeThread(self.start_th);

	def handle_process_loaded(self):
		# This is called after the process image has first been loaded. This is triggered on the next
		# LoadLibrary event after kernel32.dll - ensureing that it has been loaded. The 'Targets' are
		# created and initialized just prior to calling this. At this points usually only the following
		# dlls are loaded:
		#   ntdll.dll
		#   kernel32.dll
		#   main process module (eg. notepad.exe)
		pass
		#print self.Engine.GetExportedFunctions("ntdll.dll")
	
	
class ProcessRdp(ProcessBase):
	def __init__(self, Controller, crashdump_folder, breakpoint_handler, pid, unique_identifier, verbose):
		# Specific options
		self.path_to_exe = b"C:\\Windows\\System32\\mstsc.exe"
		self.command_line = b"mstsc.exe /v:192.168.110.134"
		
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

class ProcessNotepad(ProcessBase):
	def __init__(self, Controller, crashdump_folder, breakpoint_handler, pid, unique_identifier, verbose):
		# Specific options
		self.path_to_exe = b"C:\\Windows\\System32\\notepad.exe"
		self.command_line = b"notepad.exe"
		
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

		
		self.hlogfile.write(data + "\r\n")

		if flush:
			self.hlogfile.flush()
		

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
		
	
	
		
		
	