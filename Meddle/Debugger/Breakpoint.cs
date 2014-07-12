using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IronPython.Runtime;
using MeddleFramework;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace Meddle
{
    public class Breakpoint
    {
        private Process _process;
        public IntPtr _address;
        //public string Name = "";
        public List<string> Names;

        private byte _savedByte;
        private bool _byteIsSaved = false;
        private bool _bpSet = false;
        private List<Target> _targets;

        public Breakpoint(Process process, IntPtr address, Target target, string name)
        {
            _process = process;
            _address = address;
            if (address == (IntPtr)0x77b98ec0)
                Console.WriteLine("TEST");
            _targets = new List<Target>(1);
            Names = new List<string>(1);
            _targets.Add(target);
            Names.Add(name);
            SetBreakpoint();
        }


        public void SetBreakpoint()
        {
            // Set breakpoint
            if (!_byteIsSaved)
            {
                _savedByte = MemoryFunctions.readMemoryByte(_process.ProcessDotNet, (ulong)_address);
                _byteIsSaved = true;
            }
            if (!_bpSet)
            {
                if (!MemoryFunctions.WriteMemory(_process.ProcessDotNet, _address, (byte)0xCC))
                {
                    

                    string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                    Console.WriteLine(errorMessage);
                    Console.WriteLine("Failed to set breakpoint: " + errorMessage);
                }
                else
                {
                    _bpSet = true;

                    // Flush the instruction cache after our change
                    if (!FlushInstructionCache((IntPtr)_process.ProcessDotNet.Handle, _address, (UIntPtr)1))
                        Console.WriteLine("Error flushing instruction cache.");
                }

                //Console.WriteLine("0x" + _address.ToString("X"));
            }

            // TODO: Remove this validation test code
            if (MemoryFunctions.readMemoryByte(_process.ProcessDotNet, _address) != 0xCC)
                Console.WriteLine("Failed to set breakpoint.");
        }

        public bool ProcessBreakpointEvent(IntPtr hThread, ref Context context)
        {
            // Process each target registered to this breakpoint
            List<Target> targets = new List<Target>(_targets);
            List<Target> processedTargets = new List<Target>(_targets.Count);

            foreach (Target target in targets)
            {
                // Ask the target to prcess the breakpoint event
                if (!processedTargets.Contains(target))
                {
                    int index = targets.IndexOf(target);
                    target.ProcessBreakpointEvent(this, hThread, ref context, Names[index]);
                    processedTargets.Add(target);
                }
            }

            return true;
        }

        public void ClearBreakpoint()
        {
            if (_bpSet)
            {
                // Clear breakpoint
                MemoryFunctions.WriteMemory(_process.ProcessDotNet, _address, _savedByte);
                _bpSet = false;

                // Flush the instruction cache after our change
                if (!FlushInstructionCache((IntPtr)_process.ProcessDotNet.Handle, _address, (UIntPtr)1))
                    Console.WriteLine("Error flushing instruction cache.");
            }
        }


        public void AddTargetHandler(Target target, string name)
        {
            _targets.Add(target);
            Names.Add(name);

            if (_targets.Count > 0)
                SetBreakpoint();
        }

        public void RemoveTargetHandler(Target target)
        {
            if (_targets.Contains(target))
            {
                int index = _targets.IndexOf(target);
                _targets.Remove(target);
                Names.RemoveAt(index);
            }
                
            if (_targets.Count == 0)
                ClearBreakpoint();
        }

        [DllImport("kernel32.dll")]
        static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);
    }

}
