using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Text;
using IronPython.Runtime;
using System.Runtime.InteropServices;
using Microsoft.Samples.Debugging.Native;
using System.Runtime.CompilerServices;
using Microsoft.CSharp.RuntimeBinder;

namespace Meddle
{
    public class Context
    {
        CONTEXT context64;
        Context32 context32;
        bool isContext64 = false;
        public bool HasChanged = false;
        IntPtr _hThread = IntPtr.Zero;

        // Important wrapped variables
        public int EFlags
        {
            get { return (isContext64 ? context64.EFlags : context32.EFlags); }
            set { if (isContext64) context64.EFlags = value; else context32.EFlags = value; }
        }
        public UInt64 edi
        {
            get { return (isContext64 ? context64.rdi : (UInt64)context32.edi); }
            set { if (isContext64) context64.rdi = value; else context32.edi = (UInt32)value; }
        }
        public UInt64 esi
        {
            get { return (isContext64 ? context64.rsi : (UInt64)context32.esi); }
            set { if (isContext64) context64.rsi = value; else context32.esi = (UInt32)value; }
        }
        public UInt64 ebx
        {
            get { return (isContext64 ? context64.rbx : (UInt64)context32.ebx); }
            set { if (isContext64) context64.rbx = value; else context32.ebx = (UInt32)value; }
        }
        public UInt64 edx
        {
            get { return (isContext64 ? context64.rdx : (UInt64)context32.edx); }
            set { if (isContext64) context64.rdx = value; else context32.edx = (UInt32)value; }
        }
        public UInt64 ecx
        {
            get { return (isContext64 ? context64.rcx : (UInt64)context32.ecx); }
            set { if (isContext64) context64.rcx = value; else context32.ecx = (UInt32)value; }
        }
        public UInt64 eax
        {
            get { return (isContext64 ? context64.rax : (UInt64)context32.eax); }
            set { if (isContext64) context64.rax = value; else context32.eax = (UInt32)value; }
        }
        public UInt64 ebp
        {
            get { return (isContext64 ? context64.rbp : (UInt64)context32.ebp); }
            set { if (isContext64) context64.rbp = value; else context32.ebp = (UInt32)value; }
        }
        public UInt64 eip
        {
            get { return (isContext64 ? context64.rip : (UInt64)context32.eip); }
            set { if (isContext64) context64.rip = value; else context32.eip = (UInt32)value; }
        }
        public UInt64 esp
        {
            get { return (isContext64 ? context64.rsp : (UInt64)context32.esp); }
            set { if (isContext64) context64.rsp = value; else context32.esp = (UInt32)value; }
        }

        public UInt64 rax
        {
            get { return (isContext64 ? context64.rax : (UInt64)context32.eax); }
            set { if (isContext64) context64.rax = value; else context32.eax = (UInt32)value; }
        }
        public UInt64 rcx
        {
            get { return (isContext64 ? context64.rcx : (UInt64)context32.ecx); }
            set { if (isContext64) context64.rcx = value; else context32.ecx = (UInt32)value; }
        }
        public UInt64 rdx
        {
            get { return (isContext64 ? context64.rdx : (UInt64)context32.edx); }
            set { if (isContext64) context64.rdx = value; else context32.edx = (UInt32)value; }
        }
        public UInt64 rbx
        {
            get { return (isContext64 ? context64.rbx : (UInt64)context32.ebx); }
            set { if (isContext64) context64.rbx = value; else context32.ebx = (UInt32)value; }
        }
        public UInt64 rsp
        {
            get { return (isContext64 ? context64.rsp : (UInt64)context32.esp); }
            set { if (isContext64) context64.rsp = value; else context32.esp = (UInt32)value; }
        }
        public UInt64 rbp
        {
            get { return (isContext64 ? context64.rbp : (UInt64)context32.ebp); }
            set { if (isContext64) context64.rbp = value; else context32.ebp = (UInt32)value; }
        }
        public UInt64 rsi
        {
            get { return (isContext64 ? context64.rsi : (UInt64)context32.esi); }
            set { if (isContext64) context64.rsi = value; else context32.esi = (UInt32)value; }
        }
        public UInt64 rdi
        {
            get { return (isContext64 ? context64.rdi : (UInt64)context32.edi); }
            set { if (isContext64) context64.rdi = value; else context32.edi = (UInt32)value; }
        }
        public UInt64 rip
        {
            get { return (isContext64 ? context64.rip : (UInt64)context32.eip); }
            set { if (isContext64) context64.rip = value; else context32.eip = (UInt32)value; }
        }
        public UInt64 r8
        {
            get { return (isContext64 ? context64.r8 : 0); }
            set { if (isContext64) context64.r8 = value; }
        }
        public UInt64 r9
        {
            get { return (isContext64 ? context64.r9 : 0); }
            set { if (isContext64) context64.r9 = value; }
        }
        public UInt64 r10
        {
            get { return (isContext64 ? context64.r10 : 0); }
            set { if (isContext64) context64.r10 = value; }
        }
        public UInt64 r11
        {
            get { return (isContext64 ? context64.r11 : 0); }
            set { if (isContext64) context64.r11 = value; }
        }
        public UInt64 r12
        {
            get { return (isContext64 ? context64.r12 : 0); }
            set { if (isContext64) context64.r12 = value; }
        }
        public UInt64 r13
        {
            get { return (isContext64 ? context64.r13 : 0); }
            set { if (isContext64) context64.r13 = value; }
        }
        public UInt64 r14
        {
            get { return (isContext64 ? context64.r14 : 0); }
            set { if (isContext64) context64.r14 = value; }
        }
        public UInt64 r15
        {
            get { return (isContext64 ? context64.r15 : 0); }
            set { if (isContext64) context64.r15 = value; }
        }

        public Context(CONTEXT context64, IntPtr hThread)
        {
            _hThread = hThread;
            isContext64 = true;
            this.context64 = context64;
        }

        public Context(Context32 context32)
        {
            isContext64 = false;
            this.context32 = context32;
        }

        public Context(Process process)
        {
            isContext64 = process.IsWin64;
            if (process.IsWin64)
            {
                context64 = new CONTEXT();
                context64.ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL;
            }
            else
            {
                context32 = new Context32();
                context32.ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL;
            }
        }

        public Context(Process process, IntPtr hThread)
        {
            isContext64 = process.IsWin64;
            if (process.IsWin64)
            {
                context64 = new CONTEXT();
                context64.ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL;
            }
            else
            {
                context32 = new Context32();
                context32.ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL;
            }
            GetContext(hThread);
            //if (!GetContext(hThread))
            //  throw new Exception("Failed to GetContext(), get last error: " + Debugger.GetLastError().ToString());
        }

        public bool GetContext(IntPtr hThread)
        {
            HasChanged = false;
            _hThread = hThread;
            if (!isContext64 && sizeof(long) == 8)
                return Wow64GetThreadContext(hThread, ref context32);
            else if (!isContext64)
                return GetThreadContext(hThread, ref context32);
            else
                return GetThreadContext(hThread, ref context64);
        }

        public bool SetContext()
        {
            if (_hThread != IntPtr.Zero)
            {
                HasChanged = false;
                if (!isContext64 && sizeof(long) == 8)
                    return Wow64SetThreadContext(_hThread, ref context32);
                else if (!isContext64)
                    return SetThreadContext(_hThread, ref context32);
                else
                    return SetThreadContext(_hThread, ref context64);
            }
            else
            {
                throw new Exception("ERROR: Unable to set thread context since handle is null.");
            }
        }

        public bool SetContext(IntPtr hThread)
        {
            HasChanged = false;
            if (!isContext64 && sizeof(long) == 8)
                return Wow64SetThreadContext(hThread, ref context32);
            else if (!isContext64)
                return SetThreadContext(hThread, ref context32);
            else
                return SetThreadContext(hThread, ref context64);
        }

        public bool BackupIpBy1()
        {
            if (isContext64)
                this.context64.rip = (UInt64)(this.context64.rip - 1);
            else
                this.context32.eip = (UInt32)(this.context32.eip - 1);
            return true;
        }

        public void SetStepFlag()
        {
            if (isContext64)
                this.context64.EFlags |= 0x100;
            else
                this.context32.EFlags |= 0x100;
        }

        public ulong GetSP()
        {
            if (isContext64)
                return context64.rsp;
            else
                return context32.esp;
        }

        public long GetIP()
        {
            if (isContext64)
                return (long)context64.rip;
            else
                return (long)context32.eip;
        }

        public object GetMember(string name)
        {
            return this.GetType().GetProperty(name).GetValue(this);
        }

        public void SetMember(string name, object value)
        {
            this.GetType().GetProperty(name).SetValue(this, value);
        }

        [DllImport("kernel32.dll")]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll")]
        static extern bool GetThreadContext(IntPtr hThread, ref Context32 lpContext);

        [DllImport("kernel32.dll")]
        static extern bool Wow64GetThreadContext(IntPtr hThread, ref Context32 lpContext);

        [DllImport("kernel32.dll")]
        static extern bool SetThreadContext(IntPtr hThread, [In] ref CONTEXT lpContext);

        [DllImport("kernel32.dll")]
        static extern bool SetThreadContext(IntPtr hThread, [In] ref Context32 lpContext);

        [DllImport("kernel32.dll")]
        static extern bool Wow64SetThreadContext(IntPtr hThread, [In] ref Context32 lpContext);


    }



}
