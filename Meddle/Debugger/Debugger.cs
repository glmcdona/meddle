using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Samples.Debugging.Native;
using MeddleFramework;

namespace Meddle
{

    public class BREAKPOINT_INFO
    {
        public Context Context;
        public Breakpoint Breakpoint;

        public BREAKPOINT_INFO(Context context, Breakpoint breakpoint)
        {
            Context = context;
            Breakpoint = breakpoint;
        }
    }

    public class Debugger
    {
        private int _pid;
        private Process _process;
        private bool _processingEvents = true;
        private Thread _eventProcessor = null;
        private bool _handledFirstLoad = false;
        private Hashtable _breakpoints = null;
        private Hashtable _breakpointInfo = null;
        private bool _attached = false;
        private bool _keepOnExit = false;


        public Debugger(int pid, Process process)
        {
            _pid = pid;
            _process = process;
            _breakpoints = new Hashtable();
            
            // Attach as debugger and create the handler loop
            _eventProcessor = new Thread(DebugEventHandler);
            _eventProcessor.Start();

            while (!_attached)
            {
                Thread.Sleep(5);
            }
        }

        public void AddBreakpoint(Target target, IntPtr address, Process process, string name)
        {
            if (_breakpoints.Contains(address))
            {
                ((Breakpoint)_breakpoints[address]).AddTargetHandler(target, name);
            }
            else
            {
                _breakpoints.Add(address, new Breakpoint(process, address, target, name));
            }

        }

        public void RemoveBreakpoint(Target target, IntPtr address, Process process)
        {
            if (_breakpoints.Contains(address))
            {
                ((Breakpoint)_breakpoints[address]).RemoveTargetHandler(target);
            }
        }

        private bool ProcessBreakpointEvent(IntPtr hThread, Breakpoint breakpoint, ref Context context, ref Hashtable names)
        {
            // Handle the event
            if (breakpoint.ProcessBreakpointEvent(hThread, ref context))
            {
                foreach (string name in breakpoint.Names)
                {
                    if (names.Contains(name))
                        names[name] = ((int)names[name]) + 1;
                    else
                        names.Add(name, 1);
                }
                return true;
            }
            return false;
        }

        private void PrintReport(Hashtable numEventsByTarget)
        {
            Console.WriteLine("\nhandled " + numEventsByTarget.Count.ToString() + " breakpoints in the last second handled by <targets>:");

            foreach (string name in numEventsByTarget.Keys)
                Console.WriteLine(name + " " + numEventsByTarget[name]);
        }

        private List<IntPtr> SuspendAllThreads(int noPauseId)
        {
            List<IntPtr> suspendedThreads = new List<IntPtr>(10);
            foreach (System.Diagnostics.ProcessThread thread in this._process.ProcessDotNet.Threads)
            {
                if (thread.Id != noPauseId)
                {
                    IntPtr hThread = IntPtr.Zero;
                    hThread = NativeMethods.OpenThread(ThreadAccess.THREAD_ALL_ACCESS, true, (uint)thread.Id);
                    if (SuspendThread(hThread) != -1)
                    {
                        suspendedThreads.Add(hThread);
                    }
                    else
                    {
                        CloseHandle(hThread);
                    }
                }
            }
            return suspendedThreads;
        }

        private void ResumeAllThreads(List<IntPtr> suspendedThreads)
        {
            foreach (IntPtr hThread in suspendedThreads)
            {
                if (ResumeThread(hThread) == -1)
                {
                    Console.WriteLine(string.Format("ERROR: Failed to resume suspended thread."));
                }
                CloseHandle(hThread);
            }
        }

        List<IntPtr> suspended;
        public void HandleNativeDebugEvent(ExceptionNativeEvent em, ref Hashtable numEventsByTarget, ref bool wx86BreakpointReceived)
        {
            switch (em.ExceptionCode)
            {
                case ExceptionCode.STATUS_WX86_BREAKPOINT:
                case ExceptionCode.STATUS_BREAKPOINT:
                    if (em.ExceptionCode == ExceptionCode.STATUS_WX86_BREAKPOINT && !wx86BreakpointReceived)
                    {
                        Console.WriteLine(string.Format("WOW64 load breakpoint event."));
                        wx86BreakpointReceived = true;
                        em.ClearException();
                    }

                    if (_breakpoints.Contains(em.Address))
                    {
                        // Get the thread context
                        IntPtr hThread = NativeMethods.OpenThread(ThreadAccess.THREAD_ALL_ACCESS, true, (uint)em.ThreadId);
                        Context context = new Context(_process, hThread);

                        // Suspend all threads
                        //suspended = SuspendAllThreads((int)em.ThreadId);

                        // Save the thread context with the threadId to use it in the EXCEPTION_SINGLE_STEP handler.
                        if (_breakpointInfo.Contains((uint)em.ThreadId))
                            _breakpointInfo[(uint)em.ThreadId] = em.Address;
                        else
                            _breakpointInfo.Add((uint)em.ThreadId, em.Address);

                        // Set the trap flag
                        context.SetStepFlag();

                        // Backup IP by 1
                        context.BackupIpBy1();

                        // Process the breakpoint event
                        bool processed = ProcessBreakpointEvent(hThread, (Breakpoint)_breakpoints[em.Address], ref context, ref numEventsByTarget);

                        if (!context.SetContext(hThread))
                            Console.WriteLine("Error setting thread context after breakpoint. Error code: " +
                                              GetLastError().ToString());

                        // Write the original byte back
                        ((Breakpoint)_breakpoints[em.Address]).ClearBreakpoint();

                        CloseHandle(hThread);

                        // Clear the exception
                        em.ClearException();
                    }
                    break;


                case ExceptionCode.STATUS_WX86_SINGLE_STEP:
                case ExceptionCode.STATUS_SINGLESTEP:

                    // Get the context from the STATUS_BREAKPOINT event
                    if (_breakpointInfo.Contains((uint)em.ThreadId))
                    {
                        IntPtr bp_addr = (IntPtr)_breakpointInfo[(uint)em.ThreadId];
                        _breakpointInfo.Remove((uint)em.ThreadId);

                        if (_breakpoints.Contains(bp_addr))
                        {
                            // Restore the breakpoint
                            try
                            {
                                ((Breakpoint)_breakpoints[bp_addr]).SetBreakpoint();
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(string.Format("ERROR: Debugger failed to set breakpoint again after single step."));
                            }
                        }
                        
                        // Clear the exception
                        em.ClearException();

                        // Resume all threads
                        //ResumeAllThreads(suspended);
                        //suspended = new List<IntPtr>(0);

                    }
                    else
                    {
                        Console.WriteLine(string.Format("ERROR: Failed to find entry for thread id."));
                        em.ClearException();
                    }

                    
                    break;



                default:
                    //Console.WriteLine(string.Format("\n APPLICATION CRASH: Unhandled native debug event:\nException Code: {0}\nEvent Code: {1}\nAddress: {2}\n", em.ExceptionCode.ToString("X"), em.EventCode.ToString(), em.Address.ToString("X")));

                    if (em.FirstChance)
                    {
                        // The debugee should be given a chance to handle this exception, but the python code might care to log it.
                        this._process.HandleFirstChanceException(em);
                    }
                    else
                    {
                        // Unhandled last chance exception. Application crashed.

                        // Hand it off to the process handler
                        this._process.HandleLastChanceException(em);
                    }
                    
                    // Clear the exception, only for test purposes. We shouldn't clear this.
                    //em.ClearException();
                    break;
            }


        }

        public void Detach()
        {
            // Detach the debugger without killing the process
            _processingEvents = false;

            // Remove all breakpoints
            RemoveBreakpoints();
        }

        public void RemoveBreakpoints()
        {
            // Remove all breakpoints
            foreach (Breakpoint bp in _breakpoints.Values)
            {
                bp.ClearBreakpoint();
            }
        }

        public bool HandleProcessReady(bool wx86bp)
        {
            // Check if the process is ready yet
            try
            {
                // Triggers exception if too early in load process
                string tmp = _process.ProcessDotNet.MainModule.FileName;

                // If it is WOW64, then we need to wait for the STATUS_WX86_BREAKPOINT event before stating that the debugger is attached
                if (IntPtr.Size == 8 && !wx86bp && !_process.IsWin64)
                {
                    // Check to see if kernel32.dll is loaded yet
                    string[] modules = _process.GetLoadedModules();
                    foreach (string module in modules)
                    {
                        if (module.EndsWith("\\ntdll.dll", StringComparison.InvariantCultureIgnoreCase))
                        {
                            _process.PyProcess.on_debugger_attached(_process);
                            return true;
                        }
                    }

                    return false; // Wait for STATUS_WX86_BREAKPOINT
                }
                


                // Tell the python code that the debugger is attached
                try
                {
                    _process.PyProcess.on_debugger_attached(_process);
                    return true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(string.Format("ERROR: Python class 'Process' {0} failed when executing 'on_debugger_attached()':", _process.GetName()));
                    Console.WriteLine(ex.ToString());
                }
            }
            catch (Exception e)
            {}

            return false;
        }

        public void DebugEventHandler()
        {
            NativePipeline dbg = new NativePipeline();
            NativeDbgProcess process = dbg.Attach(_pid);
            _attached = true;

            // Tell the process it is ready to resume
            try
            {
                _process.PyProcess.on_handle_first_bp();
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("ERROR: Python class 'Process' {0} failed when executing 'on_handle_first_bp()':", _process.GetName()));
                Console.WriteLine(ex.ToString());
                // attempt to continue anyways
            }
            

            // Initialize the printing variables
            DateTime numEvents_lastPrintTime = DateTime.Now;
            Hashtable numEventsByTarget = new Hashtable(0x1000);
            _breakpointInfo = new Hashtable(10);
            bool printReport = false;
            bool processReady = false;
            bool loaderBreakpointReceived = false;
            bool wx86BreakpointReceived = false;
            
            while (_processingEvents)
            {
                if (DateTime.Now.Subtract(numEvents_lastPrintTime).TotalSeconds >= 1)
                {
                    // Print the number of events in the last second
                    if (printReport && numEventsByTarget.Count > 0)
                        PrintReport(numEventsByTarget);

                    numEvents_lastPrintTime = DateTime.Now;
                    numEventsByTarget.Clear();
                }

                // Check to see if the process has loaded
                if (!processReady)
                    processReady = HandleProcessReady(wx86BreakpointReceived);

                NativeEvent e = dbg.WaitForDebugEvent(100);

                // Check to see if the process has loaded
                if (!processReady)
                    processReady = HandleProcessReady(wx86BreakpointReceived);

                if (_keepOnExit && dbg.KillOnExit)
                    dbg.KillOnExit = false;

                if (e != null)
                {
                    //Console.WriteLine(e.ToString());
                    e.Process.HandleIfLoaderBreakpoint(e, ref loaderBreakpointReceived);

                    switch (e.EventCode)
                    {
                        case NativeDebugEventCode.EXCEPTION_DEBUG_EVENT:
                            HandleNativeDebugEvent((ExceptionNativeEvent)e, ref numEventsByTarget, ref wx86BreakpointReceived);
                            break;

                        case NativeDebugEventCode.LOAD_DLL_DEBUG_EVENT:
                            // Start of the process, ntdll.dll and kernel32.dll should now be loaded. Trigger a Process.HandleProcessLoaded() event.
                            if (_process.PyProcess.print_debugger_messages)
                                Console.WriteLine(e.ToString());

                            //Console.WriteLine(((LoadDllNativeEvent)e).Module.Name );
                            _process.HandleModuleLoaded((LoadDllNativeEvent)e);

                            break;

                        case NativeDebugEventCode.EXIT_PROCESS_DEBUG_EVENT:
                            // Process crashed, send Process.ProcessTerminated() event and finish.
                            if (printReport && numEventsByTarget.Count > 0)
                                PrintReport(numEventsByTarget);
                            _process.HandleProcessTerminated();
                            dbg.Dispose();
                            _attached = false;
                            return;

                        default:
                            break;
                    }

                    // Resume event
                    dbg.ContinueEvent(e);
                }
            }

            // Detach
            dbg.KillOnExit = false;
            _attached = false;
        }

        public void SetKeepOnExit()
        {
            _keepOnExit = true;
        }


        [DllImport("kernel32")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flAllocationType,
                                                   uint flProtect);

        [DllImport("kernel32")]
        public static extern bool DebugActiveProcess(Int32 hProcess);

        [DllImport("kernel32")]
        public static extern bool DebugSetProcessKillOnExit(bool KillOnExit);

        [DllImport("kernel32")]
        public static extern bool DebugActiveProcessStop(Int32 hProcess);

        [DllImport("kernel32")]
        public static extern uint GetLastError();

        [DllImport("kernel32.dll", EntryPoint = "WaitForDebugEvent")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WaitForDebugEvent([In] ref DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

        [DllImport("kernel32.dll")]
        static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll")]
        static extern bool QueryThreadCycleTime(IntPtr hThread, out UInt64 CycleTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern uint ResumeThread(IntPtr hThread);

       
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DEBUG_EVENT
    {

        public DebugEventType dwDebugEventCode;
        public int dwProcessId;
        public int dwThreadId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 86, ArraySubType = UnmanagedType.U1)]
        byte[] debugInfo;

        public EXCEPTION_DEBUG_INFO Exception
        {
            get { return GetDebugInfo<EXCEPTION_DEBUG_INFO>(); }
        }

        public CREATE_THREAD_DEBUG_INFO CreateThread
        {
            get { return GetDebugInfo<CREATE_THREAD_DEBUG_INFO>(); }
        }

        public CREATE_PROCESS_DEBUG_INFO CreateProcessInfo
        {
            get { return GetDebugInfo<CREATE_PROCESS_DEBUG_INFO>(); }
        }

        public EXIT_THREAD_DEBUG_INFO ExitThread
        {
            get { return GetDebugInfo<EXIT_THREAD_DEBUG_INFO>(); }
        }

        public EXIT_PROCESS_DEBUG_INFO ExitProcess
        {
            get { return GetDebugInfo<EXIT_PROCESS_DEBUG_INFO>(); }
        }

        public LOAD_DLL_DEBUG_INFO LoadDll
        {
            get { return GetDebugInfo<LOAD_DLL_DEBUG_INFO>(); }
        }

        public UNLOAD_DLL_DEBUG_INFO UnloadDll
        {
            get { return GetDebugInfo<UNLOAD_DLL_DEBUG_INFO>(); }
        }

        public OUTPUT_DEBUG_STRING_INFO DebugString
        {
            get { return GetDebugInfo<OUTPUT_DEBUG_STRING_INFO>(); }
        }

        public RIP_INFO RipInfo
        {
            get { return GetDebugInfo<RIP_INFO>(); }
        }

        private T GetDebugInfo<T>() where T : struct
        {
            var structSize = Marshal.SizeOf(typeof(T));
            var pointer = Marshal.AllocHGlobal(structSize);
            Marshal.Copy(debugInfo, 0, pointer, structSize);

            var result = Marshal.PtrToStructure(pointer, typeof(T));
            Marshal.FreeHGlobal(pointer);
            return (T)result;
        }
    }

    public enum DebugEventType : int
    {
        CREATE_PROCESS_DEBUG_EVENT = 3, //Reports a create-process debugging event. The value of u.CreateProcessInfo specifies a CREATE_PROCESS_DEBUG_INFO structure.
        CREATE_THREAD_DEBUG_EVENT = 2, //Reports a create-thread debugging event. The value of u.CreateThread specifies a CREATE_THREAD_DEBUG_INFO structure.
        EXCEPTION_DEBUG_EVENT = 1, //Reports an exception debugging event. The value of u.Exception specifies an EXCEPTION_DEBUG_INFO structure.
        EXIT_PROCESS_DEBUG_EVENT = 5, //Reports an exit-process debugging event. The value of u.ExitProcess specifies an EXIT_PROCESS_DEBUG_INFO structure.
        EXIT_THREAD_DEBUG_EVENT = 4, //Reports an exit-thread debugging event. The value of u.ExitThread specifies an EXIT_THREAD_DEBUG_INFO structure.
        LOAD_DLL_DEBUG_EVENT = 6, //Reports a load-dynamic-link-library (DLL) debugging event. The value of u.LoadDll specifies a LOAD_DLL_DEBUG_INFO structure.
        OUTPUT_DEBUG_STRING_EVENT = 8, //Reports an output-debugging-string debugging event. The value of u.DebugString specifies an OUTPUT_DEBUG_STRING_INFO structure.
        RIP_EVENT = 9, //Reports a RIP-debugging event (system debugging error). The value of u.RipInfo specifies a RIP_INFO structure.
        UNLOAD_DLL_DEBUG_EVENT = 7, //Reports an unload-DLL debugging event. The value of u.UnloadDll specifies an UNLOAD_DLL_DEBUG_INFO structure.
    }

    public enum EventCode : uint
    {
        STATUS_SUCCESS = 0x00000000,
        STATUS_ABANDONED_WAIT_0 = 0x00000080,
        STATUS_USER_APC = 0x000000C0,
        STATUS_TIMEOUT = 0x00000102,
        STATUS_PENDING = 0x00000103,
        STATUS_GUARD_PAGE_VIOLATION = 0x80000001,
        STATUS_DATATYPE_MISALIGNMENT = 0x80000002,
        STATUS_BREAKPOINT = 0x80000003,
        STATUS_SINGLE_STEP = 0x80000004,
        STATUS_BUFFER_OVERFLOW = 0x80000005,
        STATUS_UNSUCCESSFUL = 0xC0000001,
        STATUS_ACCESS_VIOLATION = 0xC0000005,
        STATUS_IN_PAGE_ERROR = 0xC0000006,
        STATUS_INVALID_PARAMETER = 0xC000000D,
        STATUS_NO_MEMORY = 0xC0000017,
        STATUS_CONFLICTING_ADDRESSES = 0xC0000018,
        STATUS_ILLEGAL_INSTRUCTION = 0xC000001D,
        STATUS_BUFFER_TOO_SMALL = 0xC0000023,
        STATUS_NONCONTINUABLE_EXCEPTION = 0xC0000025,
        STATUS_INVALID_DISPOSITION = 0xC0000026,
        STATUS_UNWIND = 0xC0000027,
        STATUS_BAD_STACK = 0xC0000028,
        STATUS_INVALID_UNWIND_TARGET = 0xC0000029,
        STATUS_UNKNOWN_REVISION = 0xC0000058,
        STATUS_INVALID_SECURITY_DESCR = 0xC0000079,
        STATUS_ARRAY_BOUNDS_EXCEEDED = 0xC000008C,
        STATUS_FLOAT_DENORMAL_OPERAND = 0xC000008D,
        STATUS_FLOAT_DIVIDE_BY_ZERO = 0xC000008E,
        STATUS_FLOAT_INEXACT_RESULT = 0xC000008F,
        STATUS_FLOAT_INVALID_OPERATION = 0xC0000090,
        STATUS_FLOAT_OVERFLOW = 0xC0000091,
        STATUS_FLOAT_STACK_CHECK = 0xC0000092,
        STATUS_FLOAT_UNDERFLOW = 0xC0000093,
        STATUS_INTEGER_DIVIDE_BY_ZERO = 0xC0000094,
        STATUS_INTEGER_OVERFLOW = 0xC0000095,
        STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096,
        STATUS_INVALID_PARAMETER_2 = 0xC00000F0,
        STATUS_STACK_OVERFLOW = 0xC00000FD,
        STATUS_CONTROL_C_EXIT = 0xC000013A
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_DEBUG_INFO
    {
        public EXCEPTION_RECORD ExceptionRecord;
        public uint dwFirstChance;
    }


    public delegate uint PTHREAD_START_ROUTINE(IntPtr lpThreadParameter);

    [StructLayout(LayoutKind.Sequential)]
    public struct CREATE_THREAD_DEBUG_INFO
    {
        public IntPtr hThread;
        public IntPtr lpThreadLocalBase;
        public PTHREAD_START_ROUTINE lpStartAddress;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CREATE_PROCESS_DEBUG_INFO
    {
        public IntPtr hFile;
        public IntPtr hProcess;
        public IntPtr hThread;
        public IntPtr lpBaseOfImage;
        public uint dwDebugInfoFileOffset;
        public uint nDebugInfoSize;
        public IntPtr lpThreadLocalBase;
        public PTHREAD_START_ROUTINE lpStartAddress;
        public IntPtr lpImageName;
        public ushort fUnicode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXIT_THREAD_DEBUG_INFO
    {
        public uint dwExitCode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXIT_PROCESS_DEBUG_INFO
    {
        public uint dwExitCode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LOAD_DLL_DEBUG_INFO
    {
        public IntPtr hFile;
        public IntPtr lpBaseOfDll;
        public uint dwDebugInfoFileOffset;
        public uint nDebugInfoSize;
        public IntPtr lpImageName;
        public ushort fUnicode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNLOAD_DLL_DEBUG_INFO
    {
        public IntPtr lpBaseOfDll;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OUTPUT_DEBUG_STRING_INFO
    {
        [MarshalAs(UnmanagedType.LPStr)]
        public string lpDebugStringData;
        public ushort fUnicode;
        public ushort nDebugStringLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RIP_INFO
    {
        public uint dwError;
        public uint dwType;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_RECORD
    {
        public uint ExceptionCode;
        public uint ExceptionFlags;
        public IntPtr ExceptionRecord;
        public IntPtr ExceptionAddress;
        public uint NumberParameters;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)]
        public uint[] ExceptionInformation;
    }



    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct FREE_DETAILS
    {
        public uint freeLoc;
        public uint sequenceNumber;
        public byte[] data;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ALLOC_DETAILS
    {
        public uint caller;
        public uint arg1;
        public uint arg2;
        public uint arg3;
        public uint sequenceNumber;
        public uint allocLoc;
        public static uint SIZE = 24;
    }


    /// <summary>
    /// x86 context
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct Context32
    {
        public CONTEXT_FLAGS ContextFlags;

        public int Dr0;
        public int Dr1;
        public int Dr2;
        public int Dr3;
        public int Dr6;
        public int Dr7;

        [MarshalAs(UnmanagedType.Struct)]
        public FloatingSaveArea FloatSave;

        public int SegGs;
        public int SegFs;
        public int SegEs;
        public int SegDs;

        public UInt32 edi;
        public UInt32 esi;
        public UInt32 ebx;
        public UInt32 edx;
        public UInt32 ecx;
        public UInt32 eax;

        public UInt32 ebp;
        public UInt32 eip;
        public int SegCs;
        public int EFlags;
        public UInt32 esp;
        public int SegSs;

        public unsafe fixed byte ExtendedRegisters[512];
    }

    public enum CONTEXT_FLAGS : uint
    {

        CONTEXT_i386 = 0x10000,
        CONTEXT_i486 = 0x10000,   //  same as i386
        CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
        CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
        CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
        CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
        CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
        CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
        CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
        CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
    }

    /// <summary>
    /// AMD64 context.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT
    {
        public long P1Home;
        public long P2Home;
        public long P3Home;
        public long P4Home;
        public long P5Home;
        public long P6Home;

        public CONTEXT_FLAGS ContextFlags;
        public int MxCsr;

        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public int EFlags;

        public long Dr0;
        public long Dr1;
        public long Dr2;
        public long Dr3;
        public long Dr6;
        public long Dr7;

        public UInt64 rax;
        public UInt64 rcx;
        public UInt64 rdx;
        public UInt64 rbx;
        public UInt64 rsp;
        public UInt64 rbp;
        public UInt64 rsi;
        public UInt64 rdi;
        public UInt64 r8;
        public UInt64 r9;
        public UInt64 r10;
        public UInt64 r11;
        public UInt64 r12;
        public UInt64 r13;
        public UInt64 r14;
        public UInt64 r15;

        public UInt64 rip;

        public XmmSaveArea32 FltSave;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
        public M128A[] VectorRegister;
        public long VectorControl;

        public long DebugControl;
        public long LastBranchToRip;
        public long LastBranchFromRip;
        public long LastExceptionToRip;
        public long LastExceptionFromRip;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FloatingSaveArea
    {
        public int ControlWord;
        public int StatusWord;
        public int TagWord;
        public int ErrorOffset;
        public int ErrorSelector;
        public int DataOffset;
        public int DataSelector;

        public unsafe fixed byte RegisterArea[80];

        public int Cr0NpxState;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct M128A
    {
        public ulong Low;
        public long High;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct XmmSaveArea32
    {
        public ushort ControlWord;
        public ushort StatusWord;
        public byte TagWord;
        public byte Reserved1;
        public ushort ErrorOpcode;
        public int ErrorOffset;
        public ushort ErrorSelector;
        public ushort Reserved2;
        public int DataOffset;
        public ushort DataSelector;
        public ushort Reserved3;
        public int MxCsr;
        public int MxCsrMask;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public M128A[] FloatRegisters;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public M128A[] XmmRegisters;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] Reserved4;
    }




}
