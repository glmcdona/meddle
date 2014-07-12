using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using IronPython.Runtime;
using MeddleFramework;
using Microsoft.Samples.Debugging.Native;

namespace Meddle
{
    public class Process
    {
        public System.Diagnostics.Process ProcessDotNet;
        public dynamic PyProcess = null;
        public readonly PythonBoss _pyBoss;
        private Controller _parent;

        private Debugger _debugger = null;
        
        private List<object> _targetsToLoad;
        private Hashtable _targets;

        public bool Initialized = false;

        private bool? _isWin64 = null;
        public bool IsWin64
        {
            get
            {
                if( _isWin64  == null )
                {
                    try{
                        _isWin64 = MemoryFunctions.IsWin64(ProcessDotNet);
                    }
                    catch(Exception e)
                    {
                        throw new Exception("Unable to determine if process is 32 or 64 bit yet.");
                    }
                }

                return (bool) _isWin64;
            }
        }



        private string _name = "";


        public void InvokeAllTargets(string name, object args)
        {
            foreach (Target target in _targets.Values)
            {
                target.Invoke(name, args);
            }
        }


        public Process(PythonBoss pyBoss, Controller parent, dynamic pyProcess)
        {
            _targets = new Hashtable(10);
            _pyBoss = pyBoss;
            _parent = parent;
            _targetsToLoad = new List<object>(10);
            PyProcess = pyProcess;
            _name = PyProcess.get_name();

            try
            {
                // Initialize the DotNet process class
                int pid = PyProcess.get_pid();

                if (pid >= 0)
                {
                    ProcessDotNet = System.Diagnostics.Process.GetProcessById(pid);

                    // Start the debugger instance
                    _debugger = new Debugger(pid, this);
                }
                else
                {
                    Console.WriteLine(string.Format("ERROR: Constructor of dot net class 'Process' {0} failed. Python process class returned 'get_pid()' of -1, this is invalid.", _name));
                    return;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(string.Format("ERROR: Constructor of python class 'Process' {0} failed:", _name));
                Console.WriteLine(e.ToString());
                return;
            }

            Initialized = true;
        }

        public string GetName()
        {
            return this._name;
        }


        ~Process()
        {
        }

        public void Detach()
        {
            // Detach the debugger and don't terminate the process.
            if (_debugger != null)
                _debugger.Detach();
        }

        public void HandleProcessLoaded()
        {
            // Actually create the _targets
            foreach (object targetClass in _targetsToLoad)
            {
                try
                {
                    // Initialize the target
                    Target newTarget = new Target(targetClass, _pyBoss, this);

                    try
                    {
                        newTarget.Initialize();

                        if (_targets.ContainsKey(newTarget.PyTarget))
                            Console.WriteLine(string.Format("WARNING: Constructor of python class 'Target' {0} attempted to add target handler '{1}' more than once.", targetClass.ToString(), Target.GetName(newTarget.PyTarget)));
                        else
                        {
                            _targets.Add(newTarget.PyTarget, newTarget);

                            try
                            {
                                newTarget.PyTarget.on_attached();
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(string.Format("ERROR: Python class 'Target' {0} failed to call 'on_attached()':", newTarget.GetName()));
                                Console.WriteLine(e.ToString());
                                return;
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(string.Format("ERROR: Constructor of python class 'Target' {0} failed:", newTarget.GetName()));
                        Console.WriteLine(e.ToString());
                        return;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(string.Format("ERROR: Constructor of python class 'Target' '{0}' failed:", targetClass.ToString()));
                    Console.WriteLine(e.ToString());
                    return;
                }
            }

            // Let the Process() class handle the process loaded event
            PyProcess.handle_process_loaded();
        }

        public void AddTarget(object targetClass)
        {
            if (!_targetsToLoad.Contains(targetClass))
                _targetsToLoad.Add(targetClass);
        }

        public void HandleProcessTerminated()
        {
            PyProcess.on_process_terminated();
        }

        public void AddBreakpoints(object targetHandler, List addresses)
        {
            // Add the specified breakpoint with targetHandlerName as the event handler
            try
            {
                if (_targets.Contains(targetHandler))
                {
                    Target target = (Target)_targets[targetHandler];
                    foreach (List address in addresses)
                    {
                        UInt64 address_uint = 0;
                        if (address[0] is Int64)
                            address_uint = (UInt64)(Int64)address[0];
                        else if (address[0] is UInt64)
                            address_uint = (UInt64)address[0];
                        else
                            address_uint = (UInt64)(int)address[0];
                        _debugger.AddBreakpoint(target, (IntPtr)address_uint, this, (string)address[1]);
                    }
                }
                else
                {
                    Console.WriteLine(string.Format("ERROR: Failed to find 'Target' breakpoint handler name '{0}' as specified by 'AddBreakpoint' argument.", Target.GetName(targetHandler)));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(string.Format("ERROR: Failed to call 'Engine.AddBreakpoints()'. This is likely are a result of improperly formed argument inputs to AddBreakpoints()."));
                Console.WriteLine(e.ToString());
                //throw e;
            }
        }

        public void AddBreakpoint(object targetHandler, long address, string eventName)
        {
            // Add the specified breakpoint with targetHandlerName as the event handler
            try
            {
                if (_targets.Contains(targetHandler))
                {
                    Target target = (Target)_targets[targetHandler];
                    _debugger.AddBreakpoint(target, (IntPtr)address, this, eventName);
                }
                else
                {
                    Console.WriteLine(string.Format("ERROR: Failed to find 'Target' breakpoint handler name '{0}' as specified by 'AddBreakpoint' argument.", Target.GetName(targetHandler)));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(string.Format("ERROR: Failed to call 'Engine.AddBreakpoints()'. This is likely are a result of improperly formed argument inputs to AddBreakpoints()."));
                Console.WriteLine(e.ToString());
                //throw e;
            }
        }

        public void RemoveBreakpoints(object targetHandler, List addresses)
        {
            // Remove the specified breakpoint with targetHandlerName as the event handler
            if (_targets.Contains(targetHandler))
            {
                Target target = (Target)_targets[targetHandler];
                foreach (long address in addresses)
                    _debugger.RemoveBreakpoint(target, (IntPtr)address, this);
            }
            else
            {
                Console.WriteLine(string.Format("ERROR: Failed to find 'Target' breakpoint handler name '{0}' as specified by 'AddBreakpoint' argument.", Target.GetName(targetHandler)));
            }
        }

        public void RemoveBreakpoint(object targetHandler, long address)
        {
            // Remove the specified breakpoint with targetHandlerName as the event handler
            if (_targets.Contains(targetHandler))
            {
                Target target = (Target)_targets[targetHandler];
                _debugger.RemoveBreakpoint(target, (IntPtr)address, this);
            }
            else
            {
                Console.WriteLine(string.Format("ERROR: Failed to find 'Target' breakpoint handler name '{0}' as specified by 'AddBreakpoint' argument.", Target.GetName(targetHandler)));
            }

        }

        public string ReadString(long address)
        {
            return MemoryFunctions.ReadString(this.ProcessDotNet, (ulong)address, MemoryFunctions.STRING_TYPE.auto);
        }

        public void HandleBreakpointEvent(Target target, Breakpoint breakpoint, IntPtr hThread, Context context, string eventName)
        {
            try
            {
                this.PyProcess.breakpoint_hit(target.PyTarget, eventName, context.GetIP(), context, hThread);
            }
            catch (Exception e)
            {
                _pyBoss.PrintError(e, string.Format("'Process' handler for instance '{0}' failed during attempt to call 'breakpoint_hit()':", _name));
            }
        }

        public void HandleFirstChanceException(ExceptionNativeEvent em)
        {
            try
            {
                this.PyProcess.on_exception_first_chance((Int64) em.Address, (uint) em.ExceptionCode, em);
            }
            catch (Exception e)
            {
                _pyBoss.PrintError(e, string.Format("'Process' handler for instance '{0}' failed during attempt to call 'on_exception_first_chance()':", _name));
            }
        }

        public void HandleLastChanceException(ExceptionNativeEvent em)
        {
            try
            {
                this.PyProcess.on_exception_last_chance((Int64)em.Address, (uint) em.ExceptionCode, em);
            }
            catch (Exception e)
            {
                _pyBoss.PrintError(e, string.Format("'Process' handler for instance '{0}' failed during attempt to call 'on_exception_last_chance()':", _name));
            }
        }

        public void HandleModuleLoaded(Microsoft.Samples.Debugging.Native.LoadDllNativeEvent loadDllNativeEvent)
        {
            // Call the process module_loaded() event
            try
            {
                this.PyProcess.module_loaded(loadDllNativeEvent.Module.Name, (Int64) loadDllNativeEvent.Module.BaseAddress);
            }
            catch (Exception e)
            {
                _pyBoss.PrintError(e, string.Format("'Process' handler for instance '{0}' failed during attempt to call 'module_loaded()':", _name));
            }

            // Call the target module_loaded() events
            foreach (Target target in _targets.Values)
            {
                target.HandleModuleLoaded(loadDllNativeEvent);
            }
        }

        public FunctionArguments ParseArguments(List stackSpec, List regSpec, Context context)
        {
            return new FunctionArguments(_pyBoss, context, stackSpec, regSpec, this);
        }

        public Arguments ParseStructure(List memorySpec, long address)
        {
            return new Arguments(_pyBoss, address, memorySpec, this, 0, null, "");
        }

        public List<FuzzBlock> GetFuzzBlockDescriptions(Int64 address, int size, string name)
        {
            return FuzzBlock.GetFuzzBlockDescriptions(this, address, size, (IsWin64 ? 8 : 4), name);
        }

        public List<FuzzBlock> GetFuzzBlockDescriptions(Int64 address, int size, int blocksize, string name)
        {
            return FuzzBlock.GetFuzzBlockDescriptions(this, address, size, blocksize, name);
        }

        public string[] GetExportedFunctions(IntPtr libraryBase)
        {
            return GetExportedFunctions((UInt64)libraryBase);
        }

        public string[] GetExportedFunctions(Int64 libraryBase)
        {
            return GetExportedFunctions((UInt64)libraryBase);
        }

        public string[] GetExportedFunctions(UInt64 libraryBase)
        {
            try
            {
                HeaderReader header = new HeaderReader(ProcessDotNet, libraryBase);

                List<string> result = new List<string>(header.exports.Count);
                foreach (export function in header.exports.Values)
                {
                    result.Add(function.Name);
                }
                return result.ToArray();
            }
            catch
            {
                return new string[0];
            }
        }

        public string[] GetExportedFunctions(HeaderReader header)
        {
            try
            {
                List<string> result = new List<string>(header.exports.Count);
                foreach (export function in header.exports.Values)
                {
                    result.Add(function.Name);
                }
                return result.ToArray();
            }
            catch
            {
                return new string[0];
            }
        }

        public string[] GetExportedFunctions(string library)
        {
            // Find the module
            foreach (System.Diagnostics.ProcessModule module in ProcessDotNet.Modules)
            {
                if (module.ModuleName.ToLower() == library.ToLower())
                {
                    // Found the module, parse it's pe header in-memory
                    HeaderReader header = new HeaderReader(ProcessDotNet, (ulong)module.BaseAddress);

                    List<string> result = new List<string>(header.exports.Count);
                    foreach (export function in header.exports.Values)
                    {
                        result.Add(function.Name);
                    }
                    return result.ToArray();
                }
            }

            return new string[0]; // No results
        }

        public string[] GetLoadedModules()
        {
            List<string> modules = new List<string>(ProcessDotNet.Modules.Count);

            foreach( System.Diagnostics.ProcessModule module in ProcessDotNet.Modules)
                modules.Add( module.FileName );
            
            return modules.ToArray();
        }

        public Int64 GetModulesBase(string library)
        {
            foreach (System.Diagnostics.ProcessModule module in ProcessDotNet.Modules)
            {
                if (module.FileName.EndsWith("\\" + library, StringComparison.InvariantCultureIgnoreCase ) )
                {
                    return (Int64) module.BaseAddress;
                }
            }

            throw new Exception("ERROR: Unable to find library base for name '" + library + "'.");
        }

        public HeaderReader GetModuleHeader(string library)
        {
            // Find the module
            foreach (System.Diagnostics.ProcessModule module in ProcessDotNet.Modules)
            {
                if (module.ModuleName.ToLower() == library.ToLower())
                {
                    // Found the module, parse it's pe header in-memory
                    HeaderReader header = new HeaderReader(ProcessDotNet, (ulong)module.BaseAddress);
                    return header;
                }
            }

            return null; // No results
        }

        public List<UInt64> MemoryFindAll(string library, List pattern)
        {
            // Find the module
            foreach (System.Diagnostics.ProcessModule module in ProcessDotNet.Modules)
            {
                if (module.ModuleName.ToLower() == library.ToLower())
                {
                    return MemoryFunctions.MemoryFindAll(ProcessDotNet, module.BaseAddress, (uint)module.ModuleMemorySize, pattern.ToArray<object>());
                }
            }

            return null; // No results
        }

        public int ReadByte(object address)
        {
            return (int)MemoryFunctions.readMemoryByte(ProcessDotNet, (IntPtr)(UInt64)address);
        }

        public int ReadWord(object address)
        {
            return (int)MemoryFunctions.readMemoryUShort(ProcessDotNet, (IntPtr)(UInt64)address);
        }

        public int ReadDword(Int64 address)
        {
            return (int)MemoryFunctions.readMemoryDword(ProcessDotNet, (IntPtr)address);
        }

        public UInt64 ReadQword(object address)
        {
            return (UInt64)MemoryFunctions.readMemoryQword(ProcessDotNet, (IntPtr)(UInt64)address);
        }

        public UInt64[] GetProcedureAddresses(string library, object procedures)
        {
            // Find the module
            foreach (System.Diagnostics.ProcessModule module in ProcessDotNet.Modules)
            {
                if (module.ModuleName.ToLower() == library.ToLower())
                {
                    // Found the module, parse it's pe header in-memory
                    HeaderReader header = new HeaderReader(ProcessDotNet, (ulong)module.BaseAddress);

                    Hashtable namesToAddresses = new Hashtable(header.exports.Count);
                    foreach (export function in header.exports.Values)
                    {
                        if (!namesToAddresses.Contains(function.Name.ToLower()))
                            namesToAddresses.Add(function.Name.ToLower(), function.Address);
                    }

                    // Resolve the provided imports
                    List<UInt64> result;
                    result = new List<UInt64>(10);
                    foreach (string procedure in (IEnumerable)procedures)
                    {
                        if (namesToAddresses.Contains(procedure.ToLower()))
                            result.Add((UInt64)namesToAddresses[procedure.ToLower()]);
                        else
                            result.Add(0);
                    }
                    return result.ToArray();
                }
            }
            return new UInt64[0];
        }

        public UInt64[] GetProcedureAddresses(IntPtr libraryBase, object procedures)
        {
            return GetProcedureAddresses((UInt64)libraryBase, procedures);
        }

        public UInt64[] GetProcedureAddresses(UInt64 libraryBase, object procedures)
        {
            // Found the module, parse it's pe header in-memory
            try
            {
                HeaderReader header = new HeaderReader(ProcessDotNet, libraryBase);

                Hashtable namesToAddresses = new Hashtable(header.exports.Count);
                foreach (export function in header.exports.Values)
                {
                    if (!namesToAddresses.Contains(function.Name.ToLower()))
                        namesToAddresses.Add(function.Name.ToLower(), function.Address);
                }

                // Resolve the provided imports
                List<UInt64> result;
                result = new List<UInt64>(10);
                foreach (string procedure in (IEnumerable)procedures)
                {
                    if (namesToAddresses.Contains(procedure.ToLower()))
                        result.Add((UInt64)namesToAddresses[procedure.ToLower()]);
                    else
                        result.Add(0);
                }
                return result.ToArray();
            }
            catch
            {
                return new UInt64[0];
            }
        }

        public HeaderReader GetLibraryHeader(Int64 libraryBase)
        {
            return GetLibraryHeader( (IntPtr) libraryBase );
        }

        public HeaderReader GetLibraryHeader(IntPtr libraryBase)
        {
            // Found the module, parse it's pe header in-memory
            try
            {
                return new HeaderReader(ProcessDotNet, (ulong)libraryBase);
            }
            catch
            {
                throw new Exception("Unknown failure in Engine.GetLibraryHeader().");
            }

            Console.WriteLine(string.Format("ERROR: Failed to call 'Engine.GetLibraryHeader()'."));
            return null;
        }

        public HeaderReader GetLibraryHeader(string library)
        {
            // Found the module, parse it's pe header in-memory
            try
            {
                // Find the module
                foreach (System.Diagnostics.ProcessModule module in ProcessDotNet.Modules)
                {
                    if (module.ModuleName.ToLower() == library.ToLower())
                    {
                        // Found the module, parse it's pe header in-memory
                        return new HeaderReader(ProcessDotNet, (ulong)module.BaseAddress);
                    }
                }
            }
            catch
            {
                throw new Exception("Unknown failure in Engine.GetLibraryHeader().");
            }

            Console.WriteLine(string.Format("ERROR: Failed to call 'Engine.GetLibraryHeader()'."));
            return null;
        }

        public UInt64 GetProcedureAddress(HeaderReader header, string procedure)
        {
            // Found the module, parse it's pe header in-memory
            try
            {
                if( header.exports.Contains(procedure.ToLower()) )
                {
                    return ((export) header.exports[procedure.ToLower()]).Address;
                }
            }
            catch
            {
                throw new Exception("Unknown failure in Engine.GetProcedureAddress().");
            }
            Console.WriteLine(string.Format("ERROR: Failed to call 'Engine.GetProcedureAddress()'. Was unable to resolve export {0}.", procedure));
            return 0;
        }

        public UInt64 GetProcedureAddress(IntPtr libraryBase, string procedure)
        {
            // Found the module, parse it's pe header in-memory
            try
            {
                HeaderReader header = new HeaderReader(ProcessDotNet, (ulong)libraryBase);

                foreach (export function in header.exports.Values)
                {
                    if (function.Name.ToLower() == procedure.ToLower())
                        return function.Address;
                }
            }
            catch
            {
                throw new Exception("Unknown failure in Engine.GetProcedureAddress().");
            }
            Console.WriteLine(string.Format("ERROR: Failed to call 'Engine.GetProcedureAddress()'. Was unable to resolve export {0}.", procedure));
            return 0;
        }

        public UInt64 GetProcedureAddress(string library, string procedure)
        {
            // Find the module
            foreach (System.Diagnostics.ProcessModule module in ProcessDotNet.Modules)
            {
                if (module.ModuleName.ToLower() == library.ToLower())
                {
                    // Found the module, parse it's pe header in-memory
                    HeaderReader header = new HeaderReader(ProcessDotNet, (ulong)module.BaseAddress);

                    List<string> result = new List<string>(header.exports.Count);
                    foreach (export function in header.exports.Values)
                    {
                        if (function.Name.ToLower() == procedure.ToLower())
                        {
                            return function.Address;
                        }
                    }
                }
            }
            return 0;
        }

        public void Attack()
        {

        }

        [DllImport("kernel32.dll")]
        static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern UIntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32")]
        public static extern IntPtr CreateRemoteThread(
          IntPtr hProcess,
          IntPtr lpThreadAttributes,
          uint dwStackSize,
          IntPtr lpStartAddress, // raw Pointer into remote process
          IntPtr lpParameter,
          uint dwCreationFlags,
          out uint lpThreadId
        );

        [DllImport("psapi.dll")]
        static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In] [MarshalAs(UnmanagedType.U4)] int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool EnumProcessModules(UInt32 hProcess,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U8)] [In][Out] ulong[] lphModule, uint cb, [MarshalAs(UnmanagedType.U4)] out UInt32 lpcbNeeded);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

        [Flags]
        private enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }

        [Flags]
        enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            Synchronize = 0x00100000
        }


    }
}
