//---------------------------------------------------------------------
//  This file is part of the CLR Managed Debugger (mdbg) Sample.
// 
//  Copyright (C) Microsoft Corporation.  All rights reserved.
//
// Part of managed wrappers for native debugging APIs.
// NativeImports.cs: raw definitions of native methods and structures 
//  for native debugging API.
//  Also includes some useful utility methods.
//---------------------------------------------------------------------


using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Runtime.Serialization;

using Microsoft.Samples.Debugging.Native;
using Microsoft.Samples.Debugging.Native.Private;

// Native structures used privately for the implementation of the pipeline.
namespace Microsoft.Samples.Debugging.Native.Private
{
    // Passed to CreateProcess
    [StructLayout(LayoutKind.Sequential)]
    public class STARTUPINFO
    {
        public STARTUPINFO()
        {
            // Initialize size field.
            this.cb = Marshal.SizeOf(this);

            // initialize safe handles 
            this.hStdInput = new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(0), false);
            this.hStdOutput = new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(0), false);
            this.hStdError = new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(0), false);
        }
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public Microsoft.Win32.SafeHandles.SafeFileHandle hStdInput;
        public Microsoft.Win32.SafeHandles.SafeFileHandle hStdOutput;
        public Microsoft.Win32.SafeHandles.SafeFileHandle hStdError;
    }

    // Passed to CreateProces
    [StructLayout(LayoutKind.Sequential)]
    public class PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
}

namespace Microsoft.Samples.Debugging.Native
{
    #region Interfaces

    /// <summary>
    /// Thrown when failing to read memory from a target.
    /// </summary>
    [Serializable()]
    public class ReadMemoryFailureException : InvalidOperationException
    {
        /// <summary>
        /// Initialize a new exception
        /// </summary>
        /// <param name="address">address where read failed</param>
        /// <param name="countBytes">size of read attempted</param>
        public ReadMemoryFailureException(IntPtr address, int countBytes)
            : base(MessageHelper(address, countBytes))
        {
        }

        public ReadMemoryFailureException(IntPtr address, int countBytes, Exception innerException)
            : base(MessageHelper(address, countBytes), innerException)
        {
        }

        // Internal helper to get the message string for the ctor.
        static string MessageHelper(IntPtr address, int countBytes)
        {
            return String.Format("Failed to read memory at 0x" + address.ToString("x") + " of " + countBytes + " bytes.");
        }

        #region Standard Ctors
        /// <summary>
        /// Initializes a new instance of the ReadMemoryFailureException.
        /// </summary>
        public ReadMemoryFailureException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the ReadMemoryFailureException with the specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public ReadMemoryFailureException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the ReadMemoryFailureException with the specified error message and inner Exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public ReadMemoryFailureException(string message, Exception innerException) 
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the ReadMemoryFailureException class with serialized data.
        /// </summary>
        /// <param name="info">The SerializationInfo that holds the serialized object data about the exception being thrown.</param>
        /// <param name="context">The StreamingContext that contains contextual information about the source or destination.</param>
        protected ReadMemoryFailureException(SerializationInfo info, StreamingContext context)
            : base(info,context)
        {
        }
        #endregion
    }

    
    /// <summary>
    /// Interface to provide access to target
    /// </summary>
    public interface IMemoryReader
    {
        /// <summary>
        /// Read memory from the target process. Either reads all memory or throws.
        /// </summary>
        /// <param name="address">target address to read memory from</param>
        /// <param name="buffer">buffer to fill with memory</param>
        /// <exception cref="ReadMemoryFailureException">Throws if can't read all the memory</exception>
        void ReadMemory(IntPtr address, byte[] buffer);
    }
    #endregion


    #region Native Structures

    /// <summary>
    /// Native debug event Codes that are returned through NativeStop event
    /// </summary>
    public enum NativeDebugEventCode
    {
        None = 0,
        EXCEPTION_DEBUG_EVENT      = 1,
        CREATE_THREAD_DEBUG_EVENT  = 2,
        CREATE_PROCESS_DEBUG_EVENT = 3,
        EXIT_THREAD_DEBUG_EVENT    = 4,
        EXIT_PROCESS_DEBUG_EVENT   = 5,
        LOAD_DLL_DEBUG_EVENT       = 6,
        UNLOAD_DLL_DEBUG_EVENT     = 7,
        OUTPUT_DEBUG_STRING_EVENT  = 8,
        RIP_EVENT                  = 9,
    }

    // Debug header for debug events.
    [StructLayout(LayoutKind.Sequential)]
    public struct DebugEventHeader
    {
        public NativeDebugEventCode dwDebugEventCode;
        public UInt32 dwProcessId;
        public UInt32 dwThreadId;
    };

    public enum ThreadAccess : int
    {
        None = 0,
        THREAD_ALL_ACCESS = (0x1F03FF),
        THREAD_DIRECT_IMPERSONATION = (0x0200),
        THREAD_GET_CONTEXT = (0x0008),
        THREAD_IMPERSONATE = (0x0100),
        THREAD_QUERY_INFORMATION = (0x0040),
        THREAD_QUERY_LIMITED_INFORMATION = (0x0800),
        THREAD_SET_CONTEXT = (0x0010),
        THREAD_SET_INFORMATION = (0x0020),
        THREAD_SET_LIMITED_INFORMATION = (0x0400),
        THREAD_SET_THREAD_TOKEN = (0x0080),
        THREAD_SUSPEND_RESUME = (0x0002),
        THREAD_TERMINATE = (0x0001),

    }

    #region Exception events
    /// <summary>
    /// Common Exception codes
    /// </summary>
    /// <remarks>Users can define their own exception codes, so the code could be any value. 
    /// The OS reserves bit 28 and may clear that for its own purposes</remarks>
    public enum ExceptionCode : uint
    {
        None = 0x0, // included for completeness sake
        STATUS_BREAKPOINT = 0x80000003,
        STATUS_SINGLESTEP = 0x80000004,
        EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094,
        EXCEPTION_STACK_OVERFLOW = 0xC00000FD,
        EXCEPTION_NONCONTINUABLE_EXCEPTION = 0xC0000025,
        EXCEPTION_ACCESS_VIOLATION = 0xc0000005,

        STATUS_WX86_BREAKPOINT = 0x4000001F,
        STATUS_WX86_UNSIMULATE = 0x4000001C,
        STATUS_WX86_CONTINUE = 0x4000001D,
        STATUS_WX86_SINGLE_STEP = 0x4000001E,
        STATUS_WX86_EXCEPTION_CONTINUE = 0x40000020,
        STATUS_WX86_EXCEPTION_LASTCHANCE = 0x40000021,
        STATUS_WX86_EXCEPTION_CHAIN = 0x40000022,
    }

    /// <summary>
    /// Flags for <see cref="EXCEPTION_RECORD"/>
    /// </summary>
    [Flags]
    public enum ExceptionRecordFlags : uint
    {
        /// <summary>
        /// No flags. 
        /// </summary>
        None = 0x0,

        /// <summary>
        /// Exception can not be continued. Debugging services can still override this to continue the exception, but recommended to warn the user in this case.
        /// </summary>
        EXCEPTION_NONCONTINUABLE = 0x1,
    }

    /// <summary>
    /// Information about an exception
    /// </summary>    
    /// <remarks>This will default to the correct caller's platform</remarks>
    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_RECORD
    {
        public ExceptionCode ExceptionCode;
        public ExceptionRecordFlags ExceptionFlags;

        /// <summary>
        /// Based off ExceptionFlags, is the exception Non-continuable?
        /// </summary>
        public bool IsNotContinuable
        {
            get
            {
                return (ExceptionFlags & ExceptionRecordFlags.EXCEPTION_NONCONTINUABLE) != 0;
            }
        }

        public IntPtr ExceptionRecord;

        /// <summary>
        /// Address in the debuggee that the exception occured at.
        /// </summary>
        public IntPtr ExceptionAddress;
        
        /// <summary>
        /// Number of parameters used in ExceptionInformation array.
        /// </summary>
        public UInt32 NumberParameters;

        const int EXCEPTION_MAXIMUM_PARAMETERS = 15;
        // We'd like to marshal this as a ByValArray, but that's not supported yet.
        // We get an alignment error  / TypeLoadException for DebugEventUnion
        //[MarshalAs(UnmanagedType.ByValArray, SizeConst = EXCEPTION_MAXIMUM_PARAMETERS)]
        //public IntPtr [] ExceptionInformation;  

        // Instead, mashal manually.
        public IntPtr ExceptionInformation0;
        public IntPtr ExceptionInformation1;
        public IntPtr ExceptionInformation2;
        public IntPtr ExceptionInformation3;
        public IntPtr ExceptionInformation4;
        public IntPtr ExceptionInformation5;
        public IntPtr ExceptionInformation6;
        public IntPtr ExceptionInformation7;
        public IntPtr ExceptionInformation8;
        public IntPtr ExceptionInformation9;
        public IntPtr ExceptionInformation10;
        public IntPtr ExceptionInformation11;
        public IntPtr ExceptionInformation12;
        public IntPtr ExceptionInformation13;
        public IntPtr ExceptionInformation14;
    } // end of class EXCEPTION_RECORD

    /// <summary>
    /// Information about an exception debug event.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_DEBUG_INFO
    {
        public EXCEPTION_RECORD ExceptionRecord;
        public UInt32 dwFirstChance;
    } // end of class EXCEPTION_DEBUG_INFO

    #endregion // Exception events

    // MODULEINFO declared in psapi.h
    [StructLayout(LayoutKind.Sequential)]
    public struct ModuleInfo
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;  
        public IntPtr EntryPoint;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CREATE_PROCESS_DEBUG_INFO
    {
        public IntPtr hFile;
        public IntPtr hProcess;
        public IntPtr hThread;
        public IntPtr lpBaseOfImage;
        public UInt32 dwDebugInfoFileOffset;
        public UInt32 nDebugInfoSize;
        public IntPtr lpThreadLocalBase;
        public IntPtr lpStartAddress;
        public IntPtr lpImageName;
        public UInt16 fUnicode;
    } // end of class CREATE_PROCESS_DEBUG_INFO

    [StructLayout(LayoutKind.Sequential)]
    public struct CREATE_THREAD_DEBUG_INFO
    {
        public IntPtr hThread;
        public IntPtr lpThreadLocalBase;
        public IntPtr lpStartAddress;
    } // end of class CREATE_THREAD_DEBUG_INFO

    [StructLayout(LayoutKind.Sequential)]
    public struct EXIT_THREAD_DEBUG_INFO
    {
        public UInt32 dwExitCode;
    } // end of class EXIT_THREAD_DEBUG_INFO

    [StructLayout(LayoutKind.Sequential)]
    public struct EXIT_PROCESS_DEBUG_INFO
    {
        public UInt32 dwExitCode;
    } // end of class EXIT_PROCESS_DEBUG_INFO

    [StructLayout(LayoutKind.Sequential)]
    public struct LOAD_DLL_DEBUG_INFO
    {
        public IntPtr hFile;
        public IntPtr lpBaseOfDll;
        public UInt32 dwDebugInfoFileOffset;
        public UInt32 nDebugInfoSize;
        public IntPtr lpImageName;
        public UInt16 fUnicode;


        // Helper to read an IntPtr from the target
        IntPtr ReadIntPtrFromTarget(IMemoryReader reader, IntPtr ptr)
        {
            // This is not cross-platform: it assumes host and target are the same size.
            byte[] buffer = new byte[IntPtr.Size];
            reader.ReadMemory(ptr, buffer);

            System.UInt64 val = 0;
            // Note: this is dependent on endienness.
            for (int i = buffer.Length - 1; i >=0 ; i--)
            {
                val <<= 8;
                val += buffer[i];
            }
            IntPtr newptr = new IntPtr(unchecked((long)val));

            return newptr;
        }


        /// <summary>
        /// Read the image name from the target.
        /// </summary>
        /// <param name="reader">access to target's memory</param>
        /// <returns>String for full path to image. Null if name not available</returns>
        /// <remarks>MSDN says this will never be provided for during Attach scenarios; nor for the first 1 or 2 dlls.</remarks>
        public string ReadImageNameFromTarget(IMemoryReader reader)
        {
            string moduleName;
            bool bUnicode = (fUnicode != 0);

            if (lpImageName == IntPtr.Zero)
            {
                return null;
            }
            else
            {
                try
                {
                    IntPtr newptr = ReadIntPtrFromTarget(reader, lpImageName);

                    if (newptr == IntPtr.Zero)
                    {
                        return null;
                    }
                    else
                    {
                        int charSize = (bUnicode) ? 2 : 1;
                        byte[] buffer = new byte[charSize];

                        System.Text.StringBuilder sb = new System.Text.StringBuilder();

                        while (true)
                        {
                            // Read 1 character at a time. This is extremely inefficient,
                            // but we don't know the whole length of the string and it ensures we don't
                            // read off a page.
                            reader.ReadMemory(newptr, buffer);

                            int b;
                            if (bUnicode)
                            {
                                b = (int)buffer[0] + ((int)buffer[1] << 8);
                            }
                            else
                            {
                                b = (int)buffer[0];
                            }

                            if (b == 0) // string is null-terminated
                            {
                                break;
                            }
                            sb.Append((char)b);
                            newptr = new IntPtr(newptr.ToInt64() + charSize); // move to next character
                        }

                        moduleName = sb.ToString();
                    }
                }
                catch (InvalidOperationException) // ignore failures to read
                {
                    return null;
                }
            }

            return moduleName;
        }


    } // end of class LOAD_DLL_DEBUG_INFO

    [StructLayout(LayoutKind.Sequential)]
    public struct UNLOAD_DLL_DEBUG_INFO
    {
        public IntPtr lpBaseOfDll;
    } // end of class UNLOAD_DLL_DEBUG_INFO

    [StructLayout(LayoutKind.Sequential)]
    public struct OUTPUT_DEBUG_STRING_INFO
    {
        public IntPtr lpDebugStringData;
        public UInt16 fUnicode;
        public UInt16 nDebugStringLength;

        // 
        /// <summary>
        /// Read the log message from the target. 
        /// </summary>
        /// <param name="reader">interface to access debuggee memory</param>
        /// <returns>string containing message or null if not available</returns>
        public string ReadMessageFromTarget(IMemoryReader reader)
        {
            try
            {
                bool isUnicode = (fUnicode != 0);

                int cbCharSize = (isUnicode) ? 2 : 1;
                byte[] buffer = new byte[nDebugStringLength * cbCharSize];
                reader.ReadMemory(lpDebugStringData, buffer);

                System.Text.StringBuilder sb = new System.Text.StringBuilder();
                for (int i = 0; i < buffer.Length; i += cbCharSize)
                {
                    int val;
                    if (isUnicode)
                    {
                        val = (int)buffer[i] + ((int)buffer[i + 1] << 8);
                    }
                    else
                    {
                        val = buffer[i];
                    }
                    sb.Append((char)val);
                }
                return sb.ToString();
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }

    } // end of class OUTPUT_DEBUG_STRING_INFO

    [StructLayout(LayoutKind.Explicit)]
    public struct DebugEventUnion
    {
        [FieldOffset(0)]
        public CREATE_PROCESS_DEBUG_INFO CreateProcess;

        [FieldOffset(0)]
        public EXCEPTION_DEBUG_INFO Exception;

        [FieldOffset(0)]
        public CREATE_THREAD_DEBUG_INFO CreateThread;

        [FieldOffset(0)]
        public EXIT_THREAD_DEBUG_INFO ExitThread;

        [FieldOffset(0)]
        public EXIT_PROCESS_DEBUG_INFO ExitProcess;

        [FieldOffset(0)]
        public LOAD_DLL_DEBUG_INFO LoadDll;

        [FieldOffset(0)]
        public UNLOAD_DLL_DEBUG_INFO UnloadDll;

        [FieldOffset(0)]
        public OUTPUT_DEBUG_STRING_INFO OutputDebugString;
    }

    // 32-bit and 64-bit have sufficiently different alignment that we need 
    // two different debug event structures.

    /// <summary>
    /// Matches DEBUG_EVENT layout on 32-bit architecture
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct DebugEvent32  
    {
        [FieldOffset(0)]
        public DebugEventHeader header;

        [FieldOffset(12)]
        public DebugEventUnion union;
    }

    /// <summary>
    /// Matches DEBUG_EVENT layout on 64-bit architecture
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct DebugEvent64
    {
        [FieldOffset(0)]
        public DebugEventHeader header;

        [FieldOffset(16)]
        public DebugEventUnion union;
    }

    #endregion Native Structures

    // These extend the Mdbg native definitions.
    public class NativeMethods
    {
        private const string Kernel32LibraryName = "kernel32.dll";
        private const string PsapiLibraryName = "psapi.dll";

        //
        // These should be sharable with other pinvokes
        //
        [DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
        public static extern int WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport(Kernel32LibraryName)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport(Kernel32LibraryName)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, 
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, 
            uint dwThreadId);

        [DllImport(Kernel32LibraryName)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        // Filesize can be used as a approximation of module size in memory.
        // In memory size will be larger because of alignment issues.
        [DllImport(Kernel32LibraryName)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetFileSizeEx(IntPtr hFile, out System.Int64 lpFileSize);

        // Get the module's size.
        // This can not be called during the actual dll-load debug event. 
        // (The debug event is sent before the information is initialized)
        [DllImport(PsapiLibraryName, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule,out ModuleInfo lpmodinfo, uint countBytes);


        // Read memory from live, local process.
        [DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
          byte[] lpBuffer, UIntPtr nSize, out int lpNumberOfBytesRead);



        // Requires Windows XP / Win2k03
        [DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DebugSetProcessKillOnExit(
            [MarshalAs(UnmanagedType.Bool)]
            bool KillOnExit
        );

        // Requires WinXp/Win2k03
        [DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DebugBreakProcess(IntPtr hProcess);


        #region Attach / Detach APIS
        // constants used in CreateProcess functions
        public enum CreateProcessFlags
        {
            CREATE_NEW_CONSOLE = 0x00000010,

            // This will include child processes.
            DEBUG_PROCESS = 1,

            // This will be just the target process.
            DEBUG_ONLY_THIS_PROCESS = 2,
        }

        [DllImport(Kernel32LibraryName, CharSet = CharSet.Unicode, SetLastError = true, PreserveSig = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)]
            bool bInheritHandles,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            STARTUPINFO lpStartupInfo,// class
            PROCESS_INFORMATION lpProcessInformation // class
        );


        // Attach to a process
        [DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DebugActiveProcess(uint dwProcessId);

        // Detach from a process
        // Requires WinXp/Win2k03
        [DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DebugActiveProcessStop(uint dwProcessId);

        [DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        #endregion // Attach / Detach APIS


        #region Stop-Go APIs
        // We have two separate versions of kernel32!WaitForDebugEvent to cope with different structure
        // layout on each platform.
        [DllImport(Kernel32LibraryName, EntryPoint = "WaitForDebugEvent", SetLastError = true, PreserveSig = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WaitForDebugEvent32(ref DebugEvent32 pDebugEvent, int dwMilliseconds);

        [DllImport(Kernel32LibraryName, EntryPoint = "WaitForDebugEvent", SetLastError = true, PreserveSig = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WaitForDebugEvent64(ref DebugEvent64 pDebugEvent, int dwMilliseconds);

        /// <summary>
        /// Values to pass to ContinueDebugEvent for ContinueStatus
        /// </summary>
        public enum ContinueStatus : uint
        {
            /// <summary>
            /// This is our own "empty" value
            /// </summary>
            CONTINUED = 0,

            /// <summary>
            /// Debugger consumes exceptions. Debuggee will never see the exception. Like "gh" in Windbg.
            /// </summary>
            DBG_CONTINUE = 0x00010002,

            /// <summary>
            /// Debugger does not interfere with exception processing, this passes the exception onto the debuggee.
            /// Like "gn" in Windbg.
            /// </summary>
            DBG_EXCEPTION_NOT_HANDLED = 0x80010001,
        }

        [DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, ContinueStatus dwContinueStatus);

        #endregion // Stop-Go
    }

}