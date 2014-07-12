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
    /// Base class for native debug events
    /// </summary>
    /// <remarks>
    /// Base class for events.
    /// A single process will generate a lot of debug events, so we want to keep them pretty lightweight.
    /// At the OS level, an event is a DEBUG_EVENT structure, which is about 0x98 bytes
    /// The managed overhead here is:
    /// - a copy of the DEBUG_EVENT, fixed up for 32/64-bit alignment
    /// - a backpointer to the NativePipeline object. 
    /// - a MethodTable pointer (from being a managed object). We take advantage of this by having derived 
    ///    objects to expose debug event properties in a friendly way (especially properties requiring
    ///    non-trivial accessing, such as getting a message string out of the debuggee).
    /// - m_ContinueStatus
    /// This gives us a rich object model over the somewhat rough model native presents.
    ///
    /// Resouce management:
    /// - the event's ctor describes what can ve done when we first get the event
    /// - the event's DoCleanupForContinue() method describes what has to be done when the event is continued.
    /// Events keep a backpointer to the pipeline, which remembers the overall state. This is important because some
    /// state is introduced via an Enter event (eg, LoadDll) and must be remembered and cleaned up in the corresponding
    /// exit event (UnloadDll)
    /// </remarks>
    public class NativeEvent
    {
        // The key data for the native event is the header and union of data. 
        internal DebugEventHeader m_header;

        // Expose raw events because there's a lot of information here and we haven't yet wrapped it all.
        public DebugEventUnion m_union;

        // Builder, returns the proper derived event object
        internal static NativeEvent Build(
            NativePipeline pipeline,
            ref DebugEventHeader header,
            ref DebugEventUnion union
            )
        {
            NativeDbgProcess process = pipeline.GetOrCreateProcess((int)header.dwProcessId);
            switch (header.dwDebugEventCode)
            {
                case NativeDebugEventCode.CREATE_PROCESS_DEBUG_EVENT:                    
                    return new CreateProcessDebugEvent(pipeline, ref header, ref union);

                case NativeDebugEventCode.EXIT_PROCESS_DEBUG_EVENT:
                    return new ExitProcessDebugEvent(pipeline, ref header, ref union);

                case NativeDebugEventCode.EXCEPTION_DEBUG_EVENT:
                    return new ExceptionNativeEvent(pipeline, ref header, ref union);

                case NativeDebugEventCode.LOAD_DLL_DEBUG_EVENT:
                    return new LoadDllNativeEvent(pipeline, ref header, ref union);

                case NativeDebugEventCode.UNLOAD_DLL_DEBUG_EVENT:
                    return new UnloadDllNativeEvent(pipeline, ref header, ref union);

                case NativeDebugEventCode.OUTPUT_DEBUG_STRING_EVENT:
                    return new OutputDebugStringNativeEvent(pipeline, ref header, ref union);

                case NativeDebugEventCode.CREATE_THREAD_DEBUG_EVENT:
                    return new CreateThreadNativeEvent(pipeline, ref header, ref union);

                case NativeDebugEventCode.EXIT_THREAD_DEBUG_EVENT:
                    return new ExitThreadNativeEvent(pipeline, ref header, ref union);

                default:
                    return new NativeEvent(pipeline, ref header, ref union);

            }
        }

        // We'd like this to be protected too
        internal NativeEvent(
            NativePipeline pipeline,
            ref DebugEventHeader header,
            ref DebugEventUnion union
            )
        {
            m_pipeline = pipeline;

            // Copy over
            m_header = header;
            m_union = union;
        }

        // This backpointer to the pipeline lets us access rich information.
        NativePipeline m_pipeline;

        /// <summary>
        /// Get the NativePipeline that this event came from.
        /// </summary>
        public NativePipeline Pipeline
        {
            get { return m_pipeline; }
        }


        /// <summary>
        /// Get the event code identifying the type of event.
        /// </summary>
        /// <remarks>This can also be obtained from the derived class.</remarks>
        public NativeDebugEventCode EventCode
        {
            get { return m_header.dwDebugEventCode; }
        }

        /// <summary>
        /// OS Thread ID of the thread that produced this debug event.
        /// </summary>
        /// <remarks>For new threads, this is the id of the new thread, and not
        /// the id of the thread that called CreateThread.</remarks>
        public int ThreadId
        {
            get { return (int)m_header.dwThreadId; }
        }

        /// <summary>
        /// Process ID of the event 
        /// </summary>
        public int ProcessId
        {
            get { return (int)m_header.dwProcessId; }
        }

        /// <summary>
        /// Process helper object for this event. 
        /// </summary>
        /// <exception>Throws if process is no longer available</exception>
        /// <remarks>A process is removed from the pipeline after continuing from the exit process event or
        /// after calling Detach </remarks>
        public NativeDbgProcess Process
        {
            get
            {
                return m_pipeline.GetProcess(ProcessId);
            }
        }

        public override string ToString()
        {
            return String.Format("Event Type:tid={0}, code={1}", ThreadId, EventCode);
        }

        // Only has meaning for exception events.
        // If this is 0, then the event has been continued.
        NativeMethods.ContinueStatus m_ContinueStatus = NativeMethods.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED;
        internal NativeMethods.ContinueStatus ContinueStatus
        {
            get { return m_ContinueStatus; }
            set { m_ContinueStatus = value; }
        }

        /// <summary>
        /// Do any event cleanup that has to be done when the event is continued
        /// This should be called by the pipeline when the event is continued.
        /// </summary>
        /// <remarks>According to:
        /// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/debug/base/waitfordebugevent.asp
        /// When we continue, we should:
        /// - for a LOAD_DLL_DEBUG_EVENT, call CloseHandle on u.LoadDll.hFile member of the DEBUG_EVENT structure.
        /// - for CREATE_PROCESS_DEBUG_EVENT, CloseHandle on u.CreateProcess.hFile
        /// - for OUTPUT_DEBUG_STRING_EVENT, Clear the exception (gh)       
        ///
        /// The OS will close the handles to the hProcess and hThread objects when calling ContinueDebugEvent.
        /// </remarks>
        public virtual void DoCleanupForContinue()
        {
            // Default implementation is to do nothing.
        }

        #region Get/Set context
        /// <summary>
        /// Retrieves the Thread Context of the thread that the event occured on.
        /// </summary>
        public INativeContext GetCurrentContext()
        {       
            INativeContext context = NativeContextAllocator.Allocate();
            GetCurrentContext(context);
            return context;
        }

        /// <summary>
        /// copy the current context into the existing context buffer. Useful to avoid allocating a new context.
        /// </summary>
        /// <param name="context">already allocated context buffer</param>
        public void GetCurrentContext(INativeContext context)
        {
            Process.GetThreadContext(this.ThreadId, context);
        }

        /// <summary>
        /// Writes back the Thread Context of the thread that the CreateThreadNativeEvent was generated on
        /// </summary>
        /// <remarks>Setting a thread's context is very dangerous operation and must be used properly.</remarks>
        public void WriteContext(INativeContext context)
        {
            IntPtr hThread = IntPtr.Zero;
            try
            {
                hThread = NativeMethods.OpenThread(ThreadAccess.THREAD_ALL_ACCESS, true, (uint)this.ThreadId);
                using (IContextDirectAccessor w = context.OpenForDirectAccess())
                { // context buffer is now locked
                    NativeMethods.SetThreadContext(hThread, w.RawBuffer);
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
        #endregion Get/Set context
    }

    /// <summary>
    /// Derived class for the CREATE_PROCESS_DEBUG_EVENT debug event.
    /// </summary>
    public class CreateProcessDebugEvent : NativeEvent
    {
        internal CreateProcessDebugEvent(
            NativePipeline pipeline,
            ref DebugEventHeader header,
            ref DebugEventUnion union
        )
            : base(pipeline, ref header, ref union)
        {
            Process.InitHandle(union.CreateProcess.hProcess);

            // Module name of main program is unavailable.
            Process.AddModule(new NativeDbgModule(Process, "<main program>", union.CreateProcess.lpBaseOfImage, union.CreateProcess.hFile));
        }
    }

    /// <summary>
    /// Derived class for EXIT_PROCESS_DEBUG_EVENT. 
    /// </summary>
    /// <remarks>
    /// This matches the <see cref="CreateProcessDebugEvent"/> event. 
    /// You can also wait on the process's object handle to tell if the process exited.
    /// </remarks>
    public class ExitProcessDebugEvent : NativeEvent
    {
        internal ExitProcessDebugEvent(
            NativePipeline pipeline,
            ref DebugEventHeader header,
            ref DebugEventUnion union
        )
            : base(pipeline, ref header, ref union)
        {
        }

        // Called when this event is about to be continued
        public override void DoCleanupForContinue()
        {
            // The OS will clear the handle, so notify Process not to double-close it.
            Process.ClearHandle();

            // Remove the process object (this will dispose it). It will also clear any remaining modules handles.
            this.Pipeline.RemoveProcess(ProcessId);
        }
    }

    /// <summary>
    /// Debug event for OUTPUT_DEBUG_STRING_EVENT, representing a log message from kernel32!OutputDebugString
    /// </summary>
    public class OutputDebugStringNativeEvent : NativeEvent
    {
        internal OutputDebugStringNativeEvent(
            NativePipeline pipeline,
            ref DebugEventHeader header,
            ref DebugEventUnion union
        )
            : base(pipeline, ref header, ref union)
        {
            // On some platforms (Win2K), OutputDebugStrings are really exceptions that need to be cleared.
            this.ContinueStatus = NativeMethods.ContinueStatus.DBG_CONTINUE;
        }

        // Read Target to get the string.
        // No newline is appended. 
        string m_cachedMessage;

        /// <summary>
        /// Cache and read the log message from the target.
        /// </summary>
        /// <returns></returns>
        public string ReadMessage()
        {
            if (m_cachedMessage == null)
            {
                m_cachedMessage = m_union.OutputDebugString.ReadMessageFromTarget(this.Process);
            }
            return m_cachedMessage;
        }

        public override string ToString()
        {
            return String.Format("OutputDebugString:tid={0}, message={1}", ThreadId, ReadMessage());
        }
    }


    /// <summary>
    /// Base class for Dll load and unload events
    /// </summary>
    public abstract class DllBaseNativeEvent : NativeEvent
    {
        internal DllBaseNativeEvent(
            NativePipeline pipeline,
            ref DebugEventHeader header,
            ref DebugEventUnion union
        )
            : base(pipeline, ref header, ref union)
        {
        }

        /// <summary>
        /// Get the native module associated with this event.        
        /// </summary>
        public NativeDbgModule Module
        {
            get
            {
                return Process.LookupModule(BaseAddress);
            }
        }

        /// <summary>
        /// Get the base address of the module. This is a unique identifier.
        /// </summary>
        abstract public IntPtr BaseAddress
        {
            get;
        }
    }

    /// <summary>
    /// Debug event for LOAD_DLL_DEBUG_EVENT.
    /// </summary>
    public class LoadDllNativeEvent : DllBaseNativeEvent
    {
        internal LoadDllNativeEvent(
            NativePipeline pipeline,
            ref DebugEventHeader header,
            ref DebugEventUnion union
        )
            : base(pipeline, ref header, ref union)
        {
            Process.AddModule(new NativeDbgModule(Process, ReadImageName(), BaseAddressWorker, union.LoadDll.hFile));
        }

        /// <summary>
        /// Non-virtual accessor, so it's safe to use in the ctor. 
        /// </summary>
        protected IntPtr BaseAddressWorker
        {
            get { return m_union.LoadDll.lpBaseOfDll; }
        }

        /// <summary>
        /// Base address of the dll. This can be used to uniquely identify the dll within a process and match load and unload events.
        /// </summary>
        public override IntPtr BaseAddress
        {
            get { return BaseAddressWorker; }
        }


        string m_cachedImageName;

        /// <summary>
        /// Get the name of the dll if available.
        /// </summary>
        /// <returns>full string name of dll if available</returns>
        /// <remarks>This must read from the target. The value is cached. </remarks>
        public string ReadImageName()
        {
            if (m_cachedImageName == null)
            {
                m_cachedImageName = m_union.LoadDll.ReadImageNameFromTarget(this.Process);

                // this serves two purposes. 
                // - it gives us a more descriptive name than just null.
                // - it conveniently sets m_cachedImageName to a non-null value so that we don't keep
                // trying to read the name in the failure case.
                if (m_cachedImageName == null)
                {
                    m_cachedImageName = "(unknown)";
                }
            }
            return m_cachedImageName;
        }



        public override string ToString()
        {
            string name = ReadImageName();
            return String.Format("DLL Load:Address 0x{0}, {1}", BaseAddress.ToString("x"), name);
        }

    }

    /// <summary>
    /// Debug event for UNLOAD_DLL_DEBUG_EVENT.
    /// </summary>
    public class UnloadDllNativeEvent : DllBaseNativeEvent
    {
        internal UnloadDllNativeEvent(
            NativePipeline pipeline,
            ref DebugEventHeader header,
            ref DebugEventUnion union
        )
            : base(pipeline, ref header, ref union)
        {
        }

        /// <summary>
        /// BaseAddress of module. Matches BaseAddress from the LoadDllNativeEvent. 
        /// </summary>
        public override IntPtr BaseAddress
        {
            get { return m_union.UnloadDll.lpBaseOfDll; }
        }

        public override string ToString()
        {
            NativeDbgModule module = Module;
            string name = (module == null) ? "unknown" : Module.Name;
            return String.Format("DLL unload:Address 0x{0},{1}", BaseAddress.ToString("x"), name);
        }


        public override void DoCleanupForContinue()
        {
            // For native dlls, need to free the module handle. 
            // If there's no matching Load dll event, then module will be null and we can't do anything.
            NativeDbgModule module = this.Module;
            if (module != null)
            {
                module.CloseHandle();
                Process.RemoveModule(module.BaseAddress);
            }
        }
    }


    /// <summary>
    /// Debug event for native thread create.
    /// </summary>
    public class CreateThreadNativeEvent : NativeEvent
    {
        internal CreateThreadNativeEvent(
            NativePipeline pipeline,
            ref DebugEventHeader header,
            ref DebugEventUnion union
            )
            : base(pipeline, ref header, ref union)
        {
            // OS will close the thread handle when the ExitThread event is processed.
        }

    }

    /// <summary>
    /// Debug event for native thread exit.
    /// </summary>
    public class ExitThreadNativeEvent : NativeEvent
    {
        internal ExitThreadNativeEvent(
            NativePipeline pipeline,
            ref DebugEventHeader header,
            ref DebugEventUnion union
            )
            : base(pipeline, ref header, ref union)
        {
        }

        /// <summary>
        /// Get the exit code of the thread.
        /// </summary>
        public int ExitCode
        {
            get { return unchecked((int)m_union.ExitThread.dwExitCode); }
        }

    }

    /// <summary>
    /// Represent an exception debug event
    /// </summary>
    public class ExceptionNativeEvent : NativeEvent
    {
        internal ExceptionNativeEvent(
            NativePipeline pipeline,
            ref DebugEventHeader header,
            ref DebugEventUnion union
            )
            : base(pipeline, ref header, ref union)
        {
        }

        /// <summary>
        /// Get the exception code identifying the type of exception.
        /// </summary>
        public ExceptionCode ExceptionCode
        {
            get { return (ExceptionCode)m_union.Exception.ExceptionRecord.ExceptionCode; }
        }

        /// <summary>
        /// Is the exception first-chance or unhandled?
        /// </summary>
        public bool FirstChance
        {
            get { return m_union.Exception.dwFirstChance != 0; }
        }

        /// <summary>
        /// The address of the exception.
        /// For hardware exceptions, this is the address of the instruction that generated the fault.
        /// For software exceptions, this is the address in the OS that raised the exception
        /// (typically in kernel32!RaiseException)
        /// </summary>
        public IntPtr Address
        {
            get { return m_union.Exception.ExceptionRecord.ExceptionAddress; }
        }

        /// <summary>
        /// Clears the exception (continue as "gh"). This is an invasive operation that may change
        /// the debuggee's behavior.
        /// </summary>
        public void ClearException()
        {
            ContinueStatus = NativeMethods.ContinueStatus.DBG_CONTINUE;
        }

        public override string ToString()
        {
            // If we recognize the exception code, we want to print out the pretty value
            // {0} - if recognized, prints name, else prints in Decimal.
            // {0:x} - always prints in hex

            string val = String.Format("Exception Event:Tid={3}, 0x{0:x}, {1}, address=0x{2}",
                ExceptionCode,
                (FirstChance ? "first chance" : "unhandled"),
                Address.ToString("x"),
                ThreadId
                );

            return val;
        }
    }

} // namespace Microsoft.Samples.Debugging.Native