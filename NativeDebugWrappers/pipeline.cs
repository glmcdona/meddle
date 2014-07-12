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
    /// This encapsulates a set of processes being debugged with the native debugging pipeline,
    /// and the wait primitives to get native debug events from these processes.
    /// </summary>
    /// <remarks>
    /// This is single-threaded. The underlying OS APIs must all be called on the same thread.
    /// Multiple instances can exist on different threads.
    /// Only one pipeline object should exist on a given thread.
    /// </remarks>
    public sealed class NativePipeline : IDisposable
    {
        #region KillOnExit
        /// <summary>
        /// Do outstanding debuggees get automatically deleted when the debugger exits?
        /// </summary>
        /// <remarks>
        /// Default is 'True'. Only available in WinXp/Win2k03 and beyond.
        /// This corresponds to kernel32!DebugSetProcessKillOnExit()
        /// If somebody calls DebugSetProcessKillOnExit directly on this thread, then the values
        /// will be incorrect.
        /// </remarks>
        public bool KillOnExit
        {
            get
            {
                return m_KillOnExit;
            }
            set
            {
                m_KillOnExit = value;
                NativeMethods.DebugSetProcessKillOnExit(value);
            }
        }
        // Remember value of DebugSetProcessKillOnExit.
        // This defaults to true.
        bool m_KillOnExit = true;
        #endregion KillOnExit


        #region track list of processes
        // Mapping of pids to NativeDbgProcess objects.
        // This lets us hand back rich process objects instead of pids.
        Dictionary<int, NativeDbgProcess> m_processes = new Dictionary<int, NativeDbgProcess>();

        NativeDbgProcess CreateNew(int processId)
        {
            NativeDbgProcess process = new NativeDbgProcess(processId);
            m_processes[processId] = process;
            return process;
        }

        // Useful for picking up processes from debug events that this pipeline
        // didn't explicitly create (such as child process debugging)
        internal NativeDbgProcess GetOrCreateProcess(int processId)
        {
            NativeDbgProcess proc;
            if (m_processes.TryGetValue(processId, out proc))
            {
                return proc;
            }
            else
            {
                return CreateNew(processId);
            }
        }

        /// <summary>
        /// Get the process object for the given pid.
        /// </summary>
        /// <param name="processId">OS process id of process</param>
        /// <returns></returns>
        /// <exception>Throws if process is no longer deing debugger. This is the 
        /// case if you detached the process or after the ExitProcess debug event has been continued</exception>
        public NativeDbgProcess GetProcess(int processId)
        {
            NativeDbgProcess proc;
            if (m_processes.TryGetValue(processId, out proc))
            {
                return proc;
            }
            else
            {
                throw new InvalidOperationException("Process " + processId + " is not being debugged by this pipeline. The process may have exited or been detached from.");
            }
        }

        // Remove a process from the collection.
        internal void RemoveProcess(int pid)
        {
            GetProcess(pid).Dispose();
            m_processes.Remove(pid);
        }

        #endregion // track list of processes


        #region Connect

        /// <summary>
        /// Attach to the given process. Throws on error. 
        /// </summary>
        /// <param name="processId">process ID of target process to attach to</param>
        /// <returns>process object representing process being debugged</returns>
        public NativeDbgProcess Attach(int processId)
        {
            bool fAttached = NativeMethods.DebugActiveProcess((uint)processId);
            if (!fAttached)
            {
                int err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException("Failed to attach to process id " + processId + "error=" + err);
            }
            

            return CreateNew(processId);
        }

        /// <summary>
        /// Create a process under the debugger, and include debugging any
        /// child processes
        /// </summary>
        /// <param name="application"></param>
        /// <param name="commandArgs"></param>
        /// <returns></returns>
        public NativeDbgProcess CreateProcessChildDebug(string application, string commandArgs)
        {
            return CreateProcessDebugWorker(application, commandArgs,
                NativeMethods.CreateProcessFlags.DEBUG_PROCESS);
        }


        
        /// <summary>
        /// Creates a new process under this debugging pipeline.
        /// </summary>
        /// <param name="application">application to launch</param>
        /// <param name="commandArgs">arguments (not including the applicatin name) to pass to the debugee.</param>
        /// <returns>NativeDbgProcess instance for newly created process</returns>
        /// <seealso cref="Attach"/>
        /// <remarks>Pump the process for debug events by calling WaitForDebugEvent.
        /// Create a process under the debugger
        /// comandArgs are the arguments to application. Does not need to include arg[0] (the application name).</remarks>
        public NativeDbgProcess CreateProcessDebug(string application, string commandArgs)
        {
            return CreateProcessDebugWorker(application, commandArgs,
                NativeMethods.CreateProcessFlags.DEBUG_PROCESS |
                NativeMethods.CreateProcessFlags.DEBUG_ONLY_THIS_PROCESS);
        }

        NativeDbgProcess CreateProcessDebugWorker(string application, string commandArgs, Microsoft.Samples.Debugging.Native.NativeMethods.CreateProcessFlags flags)
        {
            if (application == null)
            {
                throw new ArgumentException("can't be null", "application");
            }

            // Compensate for Win32's behavior, where arg[0] is the application name.
            if (commandArgs != null)
            {
                commandArgs = application + " " + commandArgs;
            }

            // This is using definition imports from Mdbg core, where these are classes.
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION(); // class

            STARTUPINFO si = new STARTUPINFO(); // struct


            NativeMethods.CreateProcess(
                application,
                commandArgs,
                IntPtr.Zero, // process attributes
                IntPtr.Zero, // thread attributes
                false, // inherit handles,
                NativeMethods.CreateProcessFlags.CREATE_NEW_CONSOLE | flags,
                IntPtr.Zero, // env block
                null, // current dir
                si,
                pi);

            // We'll close these handle now. We'll get them again from the CreateProcess debug event.
            NativeMethods.CloseHandle(pi.hProcess);
            NativeMethods.CloseHandle(pi.hThread);

            return CreateNew(pi.dwProcessId);
        }

        /// <summary>
        /// Stop debugging the specified process (detach)
        /// </summary>
        /// <param name="process">process to detach from</param>
        /// <remarks>After detaching, the process is removed from the caches and can not be accessed. If detaching at a debug
        /// event, do not call Continue on the event. </remarks>
        public void Detach(NativeDbgProcess process)
        {
            if (process == null)
            {
                throw new ArgumentNullException("process");
            }


            int pid = process.Id;
            this.KillOnExit = false;
            bool fDetachOk = NativeMethods.DebugActiveProcessStop((uint)pid);
            if (!fDetachOk)
            {
                int err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException("Failed to detach to process " + pid + "error=" + err);
            }
            RemoveProcess(pid);
        }


        #endregion // Connect

        #region Stop/Go
        /// <summary>
        /// Waits for a debug event from any of the processes in the wait set.
        /// </summary>
        /// <param name="timeout">timeout in milliseconds to wait. If 0, checks for a debug event and returns immediately</param>
        /// <returns>Null if no event is available</returns>
        /// <remarks>Debug events should be continued by calling ContinueEvent. The debuggee is completely stopped when a
        /// debug event is dispatched and until it is continued.</remarks>
        public NativeEvent WaitForDebugEvent(int timeout)
        {
            bool fHasEvent;
            if (IntPtr.Size == sizeof(Int32))
            {
                DebugEvent32 event32 = new DebugEvent32();
                fHasEvent = NativeMethods.WaitForDebugEvent32(ref event32, timeout);
                if (fHasEvent)
                {
                    return NativeEvent.Build(this, ref event32.header, ref event32.union);
                }
            }
            else
            {
                DebugEvent64 event64 = new DebugEvent64();
                fHasEvent = NativeMethods.WaitForDebugEvent64(ref event64, timeout);
                if (fHasEvent)
                {
                    return NativeEvent.Build(this, ref event64.header, ref event64.union);
                }
            }

            // Not having an event could be a timeout, or it could be a real failure.
            // Empirically, timeout produces GetLastError()=121 (ERROR_SEM_TIMEOUT), but MSDN doesn't spec that, so 
            // we don't want to rely on it. So if we don't have an event, just return NULL and
            // don't try to probe any further.
            return null;
        }

        /// <summary>
        /// Wait forever for a debug event from a process. 
        /// </summary>
        /// <returns>event</returns>
        /// <exception cref="System.InvalidOperationException">throws on failure. Since this waits forever, not having a debug event means we must have hit some error </exception>
        /// <seealso cref="WaitForDebugEvent"/>
        /// <remarks>
        /// All pipeline functions must be called on the same thread.
        /// </remarks>
        public NativeEvent WaitForDebugEventInfinite()
        {
            // Ensure that we're debugging at least 1 process before we wait forever.
            if (m_processes.Count == 0)
            {
                throw new InvalidOperationException("Pipeline is not debugging any processes. Waiting for a debug event will hang.");
            }

            // Pass -1 to timeout to wait forever
            NativeEvent nativeEvent = WaitForDebugEvent(-1);
            if (nativeEvent == null)
            {
                throw new InvalidOperationException("WaitForDebugEvent failed for non-timeout reason");
            }
            return nativeEvent;
        }

        /// <summary>
        /// Continue a debug event previously gotten by WaitForDebugEvent
        /// </summary>
        /// <param name="nativeEvent"></param>
        /// <remarks>Can't continue a debug event if we just detached from the process</remarks>
        public void ContinueEvent(NativeEvent nativeEvent)
        {
            if (nativeEvent == null)
            {
                throw new ArgumentNullException("nativeEvent");
            }
            if (nativeEvent.ContinueStatus == NativeMethods.ContinueStatus.CONTINUED)
            {
                throw new ArgumentException("event was already continued", "nativeEvent");
            }
            if (nativeEvent.Pipeline != this)
            {
                throw new ArgumentException("event does not belong to this pipeline");
            }

            // Verify that the process for this event is still connected to our pipeline.
            // The lookup will throw if the process detached or was terminated.
            NativeDbgProcess proc = nativeEvent.Process;
            Debug.Assert(proc.Id == nativeEvent.ProcessId);


            nativeEvent.DoCleanupForContinue();

            bool fContinueOk = NativeMethods.ContinueDebugEvent((uint)nativeEvent.ProcessId, (uint)nativeEvent.ThreadId, nativeEvent.ContinueStatus);
            if (!fContinueOk)
            {
                int err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException("Continue failed on process " + nativeEvent.ProcessId + " error=" + err);
            }

            // Mark as continued so that we don't accidentally continue again.
            nativeEvent.ContinueStatus = NativeMethods.ContinueStatus.CONTINUED;
        }
        #endregion // Stop/Go

        #region Dispose

        /// <summary>
        /// Dispose unmanaged resources, which would include process handles. 
        /// </summary>
        public void Dispose()
        {
            // dispose managed resources            
            foreach (NativeDbgProcess proc in m_processes.Values)
            {
                proc.Dispose();
            }
            // No native resources to free, so we don't need a finalizer.

            GC.SuppressFinalize(true);
        }


        #endregion
    };

} // namespace Microsoft.Samples.Debugging.Native

