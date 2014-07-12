//---------------------------------------------------------------------
//  This file is part of the CLR Managed Debugger (mdbg) Sample.
// 
//  Copyright (C) Microsoft Corporation.  All rights reserved.
//
// Part of managed wrappers for native debugging APIs.
//---------------------------------------------------------------------


using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;

using Microsoft.Samples.Debugging.Native;
using Microsoft.Samples.Debugging.Native.Private;

namespace Microsoft.Samples.Debugging.Native
{
    /// <summary>
    /// Local Native Process being debugged
    /// </summary>
    public class NativeDbgProcess : IMemoryReader, IDisposable
    {
        #region Lifetime
        internal NativeDbgProcess(int id)
        {
            m_id = id;
        }

        /// <summary>
        /// Finalizer for NativeDbgProcess
        /// </summary>
        ~NativeDbgProcess()
        {
            Dispose(false);
        }

        /// <summary>
        /// Implementation of IDisposable.Dispose 
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Dispose worker
        /// </summary>
        /// <param name="disposing">true if releasing managed resources</param>
        protected virtual void Dispose(bool disposing)
        {
            // if disposing == false, only cleanup native resources
            // else clean up both managed + native resources.

            //
            // Native resources
            //
            if (m_handle != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(m_handle);
                m_handle = IntPtr.Zero;
            }


            if (disposing)
            {
                // remove all remaining modules
                foreach (NativeDbgModule module in this.m_modules.Values)
                {
                    module.CloseHandle();
                }
                m_modules.Clear();
            }
        }
        #endregion Lifetime

        int m_id;

        /// <summary>
        /// OS Process ID (pid)
        /// </summary>
        public int Id
        {
            get { return m_id; }
        }

        #region Process handle

        /// <summary>
        /// Post a request for the process terminate.
        /// </summary>
        /// <param name="exitCode">exit code to supply</param>
        /// <remarks>
        /// Terminate only posts a request to terminate. It makes no gaurantees when the process actually
        /// terminates (or even that the termination actually succeed)
        /// The debugger must still pump debug events even after Terminate is called.
        /// Additional debug events may still be sent. This commonly includes Exit Thread events and
        /// eventually an ExitProcess event.
        /// It may include other events too. For example, on WinXp, if Terminate
        /// is called at the CreateProcess event, the load dll event for ntdll is still dispatched.
        /// </remarks>
        public void TerminateProcess(int exitCode)
        {
            // Since process can exit asynchrously, it may already have exited when we called this.
            // Ignore failures.
            NativeMethods.TerminateProcess(m_handle, unchecked((uint)exitCode));
        }

        /// <summary>
        /// Break into the debuggee.
        /// </summary>
        /// <remarks>This causes the debuggee to fire a debug event which the debugger will
        /// then pickup via WaitForDebugEvent.</remarks>
        public void Break()
        {
            bool fOk = NativeMethods.DebugBreakProcess(m_handle);
            if (!fOk)
            {
                throw new InvalidOperationException("DebugBreak failed.");
            }
        }

        /// <summary>
        /// Determine if the process has really exited, by checking the process handle.
        /// </summary>
        /// <returns>true if process handle is signaled, else false</returns>
        public bool IsExited()
        {
            // If process handle is nulled out, then it's exited.
            if (m_handle == IntPtr.Zero)
            {
                return true;
            }

            // If the process handle is signaled, then the process has exited.
            int ret = NativeMethods.WaitForSingleObject(m_handle, 0);
            if (ret == 0) // WAIT_OBJECT_0
            {
                return true;
            }
            return false;
        }


        // We don't own this handle. We get it from CreateProcess debug event,
        // and continuing ExitProcess debug event will call CloseHandle() on it. 
        // If the ExitProcess debug event is never called, then we'll Dispose it.
        IntPtr m_handle;

        // Expose the handle internally so that other things in the NativeDbgProcess tree can access it
        // to use with the native win32 APIs.
        internal IntPtr Handle
        {
            get { return m_handle; }
        }

        /// <summary>
        /// Expose the raw handle. This is a dangerous this to do.
        /// </summary>
        public IntPtr UnsafeHandle
        {
            get { return m_handle; }
        }

        /// <summary>
        /// Initialize handle to this process. This can be set during a CreateProcess debug event.
        /// This object then gets ownership and must close it.
        /// </summary>
        /// <param name="handle">handle to process</param>
        public void InitHandle(IntPtr handle)
        {
            m_handle = handle;
        }

        /// <summary>
        /// Called when handling ExitProcess debug event. This does not CloseHandle()
        /// </summary>
        public void ClearHandle()
        {
            // ContinueDebugEvent on ExitProcess debug event will release this handle.
            m_handle = IntPtr.Zero;
        }
        #endregion // Process handle

        /// <summary>
        /// Implement IMemoryReader.ReadMemory
        /// </summary>
        public void ReadMemory(IntPtr address, byte[] buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }

            int lenRead;
            UIntPtr len = new UIntPtr((uint)buffer.Length);
            bool fReadOk = NativeMethods.ReadProcessMemory(m_handle, address, buffer, len, out lenRead);

            if (!fReadOk || (lenRead != buffer.Length))
            {
                //throw new ReadMemoryFailureException(address, buffer.Length);                
            }
        }

        #region Loader Breakpoint
        /// <summary>
        /// Check if the event is the Loader Breakpoint, and if so, deal with it.
        /// </summary>
        /// <param name="nativeEvent">event</param>
        /// <remarks>Loader breakpoint is generally the first breakpoint event</remarks>
        public void HandleIfLoaderBreakpoint(NativeEvent nativeEvent)
        {
            // If it's already handled, nothing left to do
            if (m_fLoaderBreakpointReceived)
            {
                return;
            }

            // On x86, x64, we can just clear the exception.
            // This is even more complex on IA64, we have to actually skip it. IA64 is not yet implemented.

            // Loader Breakpoint is an exception event
            ExceptionNativeEvent e = nativeEvent as ExceptionNativeEvent;
            if (e == null)
            {
                return;
            }

            // and it's a breakpoint
            if (e.ExceptionCode != ExceptionCode.STATUS_BREAKPOINT)
            {
                return;
            }

            e.ContinueStatus = NativeMethods.ContinueStatus.DBG_CONTINUE;
            m_fLoaderBreakpointReceived = true;
        }
        bool m_fLoaderBreakpointReceived;

        /// <summary>
        /// Returns true if the loader breakpoint has been dispatched
        /// Else returns false.
        /// </summary>
        public bool IsInitialized
        {
            get { return m_fLoaderBreakpointReceived; }
        }

        #endregion // Loader Breakpoint

        #region Module support
        // Debug events for module loads contain file handles that we need to remember and close.
        Dictionary<IntPtr, NativeDbgModule> m_modules = new Dictionary<IntPtr, NativeDbgModule>();

        /// <summary>
        /// Lookup a module by base address
        /// </summary>
        /// <param name="baseAddress">base address for module to look for</param>
        /// <returns>module with matching base address. Returns null on invalid address</returns>
        /// <remarks>
        /// Some WOW64 cases will produce unload events for which there are no matching load events.
        /// </remarks>
        public NativeDbgModule LookupModule(IntPtr baseAddress)
        {
            NativeDbgModule module;
            if (m_modules.TryGetValue(baseAddress, out module))
            {
                return module;
            }
            return null;
        }

        /// <summary>
        /// Find a module containing the address
        /// </summary>
        /// <param name="address">any address in the process</param>
        /// <returns>NativeModule containing the address, or null if not in the native module list.</returns>
        public NativeDbgModule FindModuleForAddress(IntPtr address)
        {
            foreach (NativeDbgModule module in this.m_modules.Values)
            {
                long start = module.BaseAddress.ToInt64();
                int size = module.Size;
                long end = start + size;

                long test = address.ToInt64();
                if (test >= start && test < end)
                {
                    return module;
                }
            }
            return null;
        }

        internal void AddModule(NativeDbgModule module)
        {
            Debug.Assert(!m_modules.ContainsKey(module.BaseAddress));
            Debug.Assert(module.Process == this);
            m_modules[module.BaseAddress] = module;
        }
        internal void RemoveModule(IntPtr baseAddress)
        {
            m_modules.Remove(baseAddress);
        }
        #endregion Module support


        #region Context
        /// <summary>
        /// Retrieves the Thread Context of the thread that the event occured on.
        /// </summary>
        public INativeContext GetThreadContext(int threadId)
        {
            INativeContext context = NativeContextAllocator.Allocate();
            GetThreadContext(threadId, context);
            return context;
        }

        /// <summary>
        /// copy the current context into the existing context buffer. Useful to avoid allocating a new context.
        /// </summary>
        /// <param name="threadId">thread ID in the current process</param>
        /// <param name="context">already allocated context buffer</param>
        public void GetThreadContext(int threadId, INativeContext context)
        {
            IntPtr hThread = IntPtr.Zero;
            try
            {
                hThread = NativeMethods.OpenThread(ThreadAccess.THREAD_ALL_ACCESS, true, (uint)threadId);

                using (IContextDirectAccessor w = context.OpenForDirectAccess())
                { // context buffer is now locked
                    NativeMethods.GetThreadContext(hThread, w.RawBuffer);
                } // w is disposed, this unlocks the context buffer.
            }
            finally
            {
                if (hThread != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(hThread);
                }
            }
        }

        #endregion
    }
}