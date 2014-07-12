//---------------------------------------------------------------------
//  This file is part of the CLR Managed Debugger (mdbg) Sample.
// 
//  Copyright (C) Microsoft Corporation.  All rights reserved.
//
// Part of managed wrappers for native debugging APIs.
// Context.cs: defines INativeContext interfaces.
//---------------------------------------------------------------------


using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Runtime.Serialization;

using Microsoft.Samples.Debugging.Native;
using Microsoft.Samples.Debugging.Native.Private;



namespace Microsoft.Samples.Debugging.Native
{




    /// <summary>
    /// Serves as global hook to register a platform-specific allocator for a Context. 
    /// This provides extensions an easy way to get a CONTEXT for the current platform.
    /// </summary>
    [CLSCompliant(true)]
    public static class NativeContextAllocator
    {
        /// <summary>
        /// Allocate a context for the current platform
        /// </summary>
        /// <returns>Newly allocated platform specific context, determined by SetDefaultAllocator</returns>
        /// <exception cref="InvalidOperationException">Throws if no default allocator is set </exception>
        static public INativeContext Allocate()
        {
            if (s_fpAllocator == null)
            {
                throw new InvalidOperationException("No default allocator set.");
            }
            return s_fpAllocator();
        }

        /// <summary>
        /// Set the allocator used by Alloc
        /// </summary>
        /// <param name="fp">delegate to function that will allocate the context</param>
        static public void SetDefaultAllocator(AllocatorFunction fp)
        {
            s_fpAllocator = fp;
        }

        static AllocatorFunction s_fpAllocator;

        /// <summary>
        /// Prototype for native context allocator function.
        /// </summary>
        /// <returns>new instance of a native context</returns>
        public delegate INativeContext AllocatorFunction();
    }

    /// <summary>
    /// Exposes raw contents of the Context in IContext. This locks the buffer. Dispose this object to unlock the buffer
    /// </summary>
    /// <remarks>The implementation behind the interface has a variety of ways to ensure the memory is safe to write to.
    /// The buffer may be in the native heap; or it may be to a pinned object in the managed heap
    /// This is primarily intended for writing to the context (by passing the buffer out to a pinvoke),
    /// but can also be a way to read the raw bytes.</remarks>
    [CLSCompliant(true)]
    public interface IContextDirectAccessor : IDisposable
    {
        /// <summary>
        /// The size of the buffer. This should be the same as INativeContext.Size.
        /// </summary>
        int Size { get; }

        /// <summary>
        /// A pointer to the raw buffer. The memory is pinned until this object is disposed. Check the context Flags 
        /// to know which raw bytes are valid to be read. 
        /// </summary>
        IntPtr RawBuffer { get; }
    }

    /// <summary>
    /// Interface to a context. This provides platform agnostic wrapper to a platform specific OS Context.
    /// </summary>
    [CLSCompliant(true)]
    public interface INativeContext :
        IEquatable<INativeContext>,
        IDisposable
    {
        #region Writing
        /// <summary>
        /// Used to lock the buffer and get a raw pointer to it. 
        /// This is the only way to change the entire context at once. 
        /// This is useful for pinvoking to native functions.
        /// </summary>
        /// <returns>context writer object</returns>
        /// <remarks>
        /// Expected usage would be (in C# syntax):
        /// <example>
        ///    IContext c = NativeContextAllocator.Alloc();
        ///    using(IContextWriter w = c.OpenForDirectAccess) { // context buffer is now locked
        ///       SomeNativeFunctionToGetThreadContext(w.RawBuffer, w.Size);
        ///    } // w is disposed, this unlocks the context buffer.
        /// </example>
        /// </remarks>
        IContextDirectAccessor OpenForDirectAccess();
        #endregion

        #region Geometry and writing
        /// <summary>
        /// Get Size in bytes. Size could change depending on the flags.
        /// </summary>
        int Size { get; }

        /// <summary>
        /// Get the flags associated with the context. 
        /// </summary>
        /// <remarks>Flags are platform specific and generally indicate which parts of the context are valid.
        /// Flags will affect which registers are available (EnumerateRegisters), potentially the Size of the context,
        /// and how contexts are compared.
        /// Expanding the active flags means newly included registers have an uninitialized value.
        /// A context could be completely constructed late-bound by setting the Flags and then calling
        /// SetRegisterByName on each regsister
        /// 
        /// This property must roundtrip.
        /// 
        /// When setting the flags to a new value, the object may enforce certain contstraints(for example,
        /// it may ensure that certain mandatory flags stay present). To see if a the set occured exactly,
        /// reget the flags after setting them and compare with expected results.
        /// </remarks>
        int Flags { get; set; }


        #endregion

        #region Standard operations
        /// <summary>
        /// Get the instruction pointer (eip on x86)
        /// </summary>
        IntPtr InstructionPointer { get; }

        /// <summary>
        /// Get the stack pointer (esp on x86)
        /// </summary>
        IntPtr StackPointer { get; }

        /// <summary>
        /// Enable or disable the single-step flag in the context. 
        /// </summary>
        /// <param name="enable">true to enable single-stepping, false to disable it</param>
        /// <exception cref="System.InvalidOperationException">Throws if the architecture doesn't support single-stepping.</exception>
        void SetSingleStepFlag(bool enable);

        /// <summary>
        /// Is the single step flag enabled?
        /// </summary>
        bool IsSingleStepFlagEnabled { get; }

        /// <summary>
        /// Create a new deep copy of this context. 
        /// The copies are independent and can be modified without interfering with each other.
        /// </summary>
        /// <returns>copy of this context</returns>
        /// <remarks>Contexts can be large, so copying excessively would be expensive.</remarks>
        /// <example> 
        /// INativeContext c1 = ...
        /// INativeContext c2 = c1.Clone();
        ///   
        /// Assert(c1 != c2); // true, Clone gives different instances
        /// Assert(c1.Equals(c2)); // true
        /// Assert(c2.Equals(c1)); // true
        /// </example>
        INativeContext Clone();

        // <summary>
        // Implement IEquatable<T> to do value comparison of two contexts. 
        // </summary>
        // <param name="other">non-null context to compare too</param>
        // <returns>true if equal, else false</returns>
        // <remarks>Comparison can't just do a bitwise comparison of the buffer. It needs to be aware of the <see cref="Flags"/> 
        // property for each context, because if a portion of the context is missing, it could be random garbage. 
        // Comparison does not modify either context object.</remarks>

        // bool IEquatable<T>.Equals(object other)  // inheritted from IEquatable<T>

        #endregion Standard operations



        #region Self Describing
        /// <summary>
        /// Get a simple string description of the CPU the context is for. A implementation may also provide a ToString()
        /// override to give more detail (eg, which flags are active)
        /// </summary>
        string Cpu { get; }


        /// <summary>
        /// Enumerate registers names (and their types) for late-bound access. Available registers depend on the flags.
        /// </summary>
        /// <returns>an enumeration of (name,type) pairs</returns>
        /// <remarks>An implementation does not need to include all registers on the context.
        /// The returned strings can be used with other by-name functions like <see cref="FindRegisterByName"/>
        /// and <see cref="SetRegisterByName"/>.</remarks>
        System.Collections.Generic.IEnumerable<String> EnumerateRegisters();

        /// <summary>
        /// Get a register by name
        /// </summary>
        /// <param name="name">Name of the registers. Lookup is case insensitive</param>
        /// <returns>value of register. Registers can be arbitrary types (uint32, double, long, etc), so this
        /// returns an object. Throws if name is not currently valid</returns>
        object FindRegisterByName(string name);

        /// <summary>
        /// Sets a register by name.
        /// </summary>
        /// <param name="name">Case-insensitive name of register to set. </param>
        /// <param name="value">value of register to set. Type of value must be convertable to type of the register</param>
        /// <exception cref="System.InvalidOperationException">Throws if no matching name or if register is not valid for the given Flags.</exception>
        void SetRegisterByName(string name, object value);

        #endregion Self Describing


    } // IContext



}

