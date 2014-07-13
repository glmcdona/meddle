using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MeddleFramework;

namespace Meddle
{
    public class FuzzBlock
    {
        public string Name; // Location, eg "device.data.name + 0x18"
        public Int64 Hash;
        protected int _size;

        public virtual bool SetValue(UInt64 value, ref Context context)
        {
            throw new Exception("Not implemented.");
            return false;
        }

        public virtual UInt64 GetValue(ref Context context)
        {
            throw new Exception("Not implemented.");
            return 0;
        }

        public virtual string GetLocation()
        {
            throw new Exception("Not implemented.");
        }

        public virtual string GetName()
        {
            return Name;
        }

        public virtual int GetSize()
        {
            return _size;
        }

        public static bool IsValidBlockSize(int size)
        {
            switch (size)
            {
                case 1:
                    return true;

                case 2:
                    return true;

                case 4:
                    return true;

                case 8:
                    return true;

                default:
                    return false;
            }
        }
        
        public static List<FuzzBlock> GetFuzzBlockDescriptions(Process process, Int64 address, int size, int chunkSize, string name)
        {
            HashSet<FuzzBlock> blocks = new HashSet<FuzzBlock>();

            // Add this data argument as a fuzz
            for (int i = 0; i < size; i += chunkSize)
            {
                FuzzBlockAddress block;
                if (i + chunkSize > size)
                {
                    // Partial chunk, lower the start address until it fits and decrease size if required
                    if (size < chunkSize)
                    {
                        // Break it down into multiple smaller blocks
                        int n = i;
                        while (n < size)
                        {
                            // Make one chunk that is as big as allowed.
                            int newChunkSize = size - n;
                            while (newChunkSize > 0 && !FuzzBlock.IsValidBlockSize(newChunkSize))
                                newChunkSize--;

                            if (newChunkSize <= 0)
                                continue;

                            // Add a new block of this size
                            block = new FuzzBlockAddress(process.ProcessDotNet, address + n, name + " + 0x" + i.ToString("X"), newChunkSize);
                            if (!blocks.Contains(block))
                                blocks.Add(block);

                            n += newChunkSize;
                        }

                        return blocks.ToList();
                    }
                    else
                    {
                        // Shift down until it fits. This means two fuzz blocks will overlap, but that is alright.
                        Int64 newAddress = address + size - chunkSize;
                        block = new FuzzBlockAddress(process.ProcessDotNet, newAddress, name + " + 0x" + i.ToString("X"), chunkSize);
                    }

                }
                else
                {
                    // Full chunk
                    block = new FuzzBlockAddress(process.ProcessDotNet, address + i, name + " + 0x" + i.ToString("X"), chunkSize);
                }
                
                if (!blocks.Contains(block))
                    blocks.Add(block);
            }

            return blocks.ToList();
        }

        
    }

    public class FuzzBlockAddress : FuzzBlock
    {
        private IntPtr _address;
        private System.Diagnostics.Process _process;

        public FuzzBlockAddress(System.Diagnostics.Process process, long address, string name, int size)
        {
            _process = process;
            this._address = (IntPtr)address;
            this.Name = name;
            this.Hash = (Int64)this._address;
            _size = size;
        }

        public override string GetLocation()
        {
            return _address.ToString("X");
        }

        public override UInt64 GetValue(ref Context context)
        {
            switch (_size)
            {
                case 1:
                    return MemoryFunctions.ReadMemoryByte(_process, _address);

                case 2:
                    return MemoryFunctions.ReadMemoryUShort(_process, _address);

                case 4:
                    return MemoryFunctions.ReadMemoryDword(_process, _address);

                case 8:
                    return MemoryFunctions.ReadMemoryQword(_process, _address);

                default:
                    throw new Exception("ERROR: Unable to read fuzzblock value. Block sizes of only 1, 2, 4, or 8 are supported.");
            }
        }

        public override bool SetValue(UInt64 value, ref Context context)
        {
            switch (_size)
            {
                case 1:
                    return MemoryFunctions.WriteMemory(_process, _address, (byte)value);

                case 2:
                    return MemoryFunctions.WriteMemory(_process, _address, (UInt16)value);

                case 4:
                    return MemoryFunctions.WriteMemory(_process, _address, (UInt32)value);

                case 8:
                    return MemoryFunctions.WriteMemory(_process, _address, (UInt64)value);

                default:
                    throw new Exception("ERROR: Unable to set fuzzblock value. Block sizes of only 1, 2, 4, or 8 are supported.");
            }
        }
    }

    public class FuzzBlockRegister : FuzzBlock
    {
        private string _register;
        private System.Diagnostics.Process _process;
        
        public FuzzBlockRegister(System.Diagnostics.Process process, string register, string name, int size)
        {
            _process = process;
            this._register = register;
            this.Name = name;
            this.Hash = ((Int64)name.GetHashCode()) | 0x1000000000000000;
            _size = size;
        }

        public override string GetLocation()
        {
            return _register;
        }

        public override UInt64 GetValue(ref Context context)
        {
            return (UInt64)context.GetMember(_register);
        }

        public override bool SetValue(UInt64 value, ref Context context)
        {
            context.SetMember(_register, (object)value);
            return true;
        }
    }

    public class FuzzBlockComparer : IEqualityComparer<FuzzBlock>
    {
        public bool Equals(FuzzBlock one, FuzzBlock two)
        {
            // Adjust according to requirements
            return one.Hash == two.Hash;
        }

        public int GetHashCode(FuzzBlock item)
        {
            return (int)item.Hash;
        }
    }
}
