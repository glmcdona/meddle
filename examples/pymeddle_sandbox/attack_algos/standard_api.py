import sys
from ctypes import *
PAGE_READWRITE      = 0x04
PROCESS_ALL_ACCESS  = (0x000F0000 | 0x00100000 | 0xFFF)
VIRTUAL_MEM         = (0x1000 | 0x2000)
kernel32            = windll.kernel32


class AttackAlgo:
	# attack_request member variables:
	#     .library: string
	#          Library name of the target. Often "ntdll.dll" or "kernel32.dll".
	#
	#     .export_name: string
	#          Export from the library to target. Eg "DeviceIoControl".
	#
	#     .pid: integer
	#          PID of the process that thit the breakpoint.
	#
	#     .thread_context: structure
	#          .thread_handle
	#          .eip
	#          .esp
	#          .ebp
	#
	#     .args: list[list[bytes]]
	#           args[0] is the first argument input as a list[bytes], usually 4 or 8 bytes.
	#           args[1] is the first argument input as a list[bytes], usually 4 or 8 bytes.
	#           ...
	#
	#     .static_blocks: list[[address list[bytes]]]
	#           Specifies the list of address and datablock pairs. These were determined by
	#           the engine to be blocks that should not be fuzzed based on dereferncing and
	#           the argument flags of the api call. Normally these should be recreated by the
	#           command Engine.recreate(pid,static_blocks) without any fuzzing.
	#
	#     .fuzz_blocks: list[[address list[bytes]]]
	#           Specifies the list of address and datablock pairs to fuzz. Typically you would
	#           change only a single value in one of these blocks for each attack, recreating
	#           it using the built in function Engine.recreate(pid,fuzzed_blocks).
	#           
	#
	# attack_request member functions:
	#     .library: Library name of the target. Often "ntdll.dll" or "kernel32.dll".
	#     . 

	def attack(Engine, attack_request):
		# Target application is paused at breakpoint, and an attack has
		# been requested. In this attack sequence, the target application
		# is used to carry out the fuzzing attacks by CreateRemoteThreadEx()
		
		pid = attack_request.pid
		
		# Attach to the target process
		ph = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
		if not ph:
			print "ERROR: Failed to OpenProcess pid: 0x%x" % pid
			return
		
		# Fuzz the data blocks, but keeping the original copy intact. Python FuzzAlgo.fuzz() is defined
		# in 'config_attack_descriptions.xml', and can be configured. Typically this will randomize
		# one dword in an organised manner.
		for i in range(options_repeat_count):
			more_fuzzing = false
			[fuzzed_blocks, more_fuzzing] = FuzzAlgo.fuzz( copy.deepcopy(attack_request.fuzz_blocks) )
			while more_fuzzing:
				# Inject the static and fuzzed blocks, should be done in this order incase of overlapping regions
				Engine.recreate(pid, attack_request.static_blocks);
				Engine.recreate(pid, attack_request.fuzzed_blocks); # calls C# function to write the blocks into the remote process.
				
				# Create a remote thread to call this function now that the fuzzed scenerio has been created
				tid = c_ulong(0)
				arg_address = attack_request.thread_context.esp # Steal the stack from the paused thread
				if not kernel32.CreateRemoteThread(ph, None, 0, Engine.thread_context.eip, arg_address, 0, byref(thread_id)):
					print "ERROR: Failed to create remote thread into %s pid: 0x%x" % (attack_request.export_name, pid)
					return
				
				# Restore the original blocks, so that hopefully the target process will be back to normal.
				Engine.recreate(pid, fuzz_blocks);
				Engine.recreate(pid, original_blocks);
				
				# Fuzz another block
				[fuzzed_blocks, more_fuzzing] = FuzzAlgo.fuzz( copy.deepcopy(attack_request.fuzz_blocks) )
		
		
		kernel32.CloseHandle(ph)
		
		# Resume the paused process
		Engine.resume()