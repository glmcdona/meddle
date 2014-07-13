using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Text;
using IronPython.Runtime;
using MeddleFramework;

namespace Meddle
{
    public class Argument : DynamicObject
    {
        public long Address;
        public int Size;
        public bool Fuzz;
        public string Name; // eg in pStruct.hand, the prefix is "pStruct." and the name is "hand".
        public string NamePrefix;
        public Arguments PointerTarget;
        public byte[] Data;
        public int depth;
        protected Process process;
        protected PythonBoss _pyBoss;
        protected Arguments _parent;
        protected object _argumentType;
        protected object _typeArgs;

        public Argument()
        {
        }

        public Argument(PythonBoss pyBoss, long address, PythonDictionary spec, Process process, int depth, Arguments parent, string namePrefix)
        {
            Address = address;
            this.process = process;
            _pyBoss = pyBoss;
            _parent = parent;
            NamePrefix = namePrefix;


            // Parse the spec for this argument
            // stackspec: [{"name": "socket",
            //		      "size": 4,
            //		      "type": None,
            //		      "fuzz": NOFUZZ,
            //            "type_args": None},]
            
            Fuzz = (bool)spec.get("fuzz");
            Name = (string)spec.get("name");
            _argumentType = (object)spec.get("type");
            if ( spec.ContainsKey("type_args") )
            {
                _typeArgs = spec.get("type_args");
            }
            

            // Validate required fields
            if (Name == null)
                throw new Exception("ERROR: Argument specification must include 'name' attribute. Failed when parsing name prefix '" + namePrefix + "'.");
            else if (Fuzz == null)
                throw new Exception("ERROR: Argument specification must include 'fuzz' attribute. Failed when parsing type '" + namePrefix + Name + "'.");
            else if (spec.get("size") == null)
                throw new Exception("ERROR: Argument specification must include 'size' attribute. Failed when parsing type '" + namePrefix + Name + "'.");
            

            if (spec.get("size") is string)
            {
                object sizeArgument = null;
                if (parent.TryGetMemberSearchUp((string)spec.get("size"), out sizeArgument))
                    Size = ((Argument)sizeArgument).ToInt();
                else
                    throw new Exception("ERROR: Unable to load size for type '" + Name + "' from parent member named '" + (string)spec.get("size") + "'. Please make sure this field exists in the parent.");
            }
            else if (spec.get("size") is int)
            {
                Size = (int)spec.get("size");
            }
            else
            {
                throw new Exception("ERROR: Unable to load size for type '" + Name + "'. The size must be of type 'int' or type 'string'. Size is type: '" + spec.get("size").ToString() + "'" );
            }

            // Read the data
            Data = MemoryFunctions.ReadMemory(process.ProcessDotNet, address, (uint)Size);

            PointerTarget = null;
        }

        public void ParseChildren()
        {
            // Load the pointer target
            PointerTarget = null;
            if (_argumentType != null)
            {
                long targetAddress = 0;
                if (Size == 4 || Size == 8)
                    targetAddress = (long)MemoryFunctions.ByteArrayToUlong(Data, 0);
                else
                    throw new Exception("Argument type definition problem. A pointer to another type must be a size of 4 or 8. Argument name: " + Name + ". The unsupported size being specified is: " + Size.ToString());

                // Load the spec for the the target type
                List pointerSpec = _pyBoss.PyScope.Engine.Operations.Invoke(_argumentType, new object[] { _parent, targetAddress, "", _typeArgs });

                PointerTarget = new Arguments(_pyBoss, targetAddress,
                                              pointerSpec, process, depth + 1, this, NamePrefix + Name + ".");
            }
        }

        public virtual string GetLocation()
        {
            return "0x" + Address.ToString("X");
        }

        public void Reparse(byte[] data, long offset)
        {
            // Copy the data
            Array.ConstrainedCopy(data, (int)offset, Data, 0, (int)Size);
            if (PointerTarget != null)
            {
                if (Size == 4)
                    PointerTarget.Reparse(MemoryFunctions.ByteArrayToUint(Data, 0));
                else if (Size == 8)
                    PointerTarget.Reparse((long)MemoryFunctions.ByteArrayToUlong(Data, 0));
            }
        }

        // If you try to get a value of a property  
        // not defined in the class, this method is called. 
        public override bool TryGetMember(GetMemberBinder binder, out object result)
        {
            // Pass the request on to the pointed to Arguments struct
            if (PointerTarget != null)
            {
                return PointerTarget.TryGetMember(binder, out result);
            }
            result = null;
            return false;
        }

        public virtual Process GetProcess()
        {
            return this.process;
        }

        public virtual List<FuzzBlock> GetFuzzBlockDescriptions()
        {
            HashSet<FuzzBlock> blocks = new HashSet<FuzzBlock>();
            this.GetFuzzBlockDescriptions(ref blocks, (this.process.IsWin64 ? 8 : 4));

            return blocks.ToList<FuzzBlock>();
        }

        public virtual void GetFuzzBlockDescriptions(ref HashSet<FuzzBlock> blocks, int chunkSize)
        {
            if (this.Fuzz)
            {
                // Add this data argument as a fuzz
                blocks.UnionWith( FuzzBlock.GetFuzzBlockDescriptions(process, Address, Size, chunkSize, NamePrefix + Name) );
            }

            if (this.PointerTarget != null)
            {
                // Forward this to the pointed to arguments description
                PointerTarget.GetFuzzBlockDescriptions(ref blocks, chunkSize);
            }
        }

        public bool TryGetMemberSearchUp(string name, out object result)
        {
            if (_parent == null)
            {
                result = null;
                return false;
            }

            return _parent.TryGetMemberSearchUp(name, out result); ;
        }

        public Argument GetMemberSearchUp(string name)
        {
            if (_parent == null)
            {
                return null;
            }

            return _parent.GetMemberSearchUp(name); ;
        }

        public int ToInt()
        {
            // Return the data an int
            return (int)MemoryFunctions.ByteArrayToUint(Data, 0);
        }

        public long ToLong()
        {
            // Return the data a long
            return (long)MemoryFunctions.ByteArrayToUlong(Data, 0);
        }

        public long ToPtr()
        {
            // Return the data a IntPtr
            if (process.IsWin64)
                return this.ToLong();
            else
                return (long)this.ToInt();
        }

        public byte[] ToBytes()
        {
            // Return the data a byte array
            return Data;
        }

        public string ReadString()
        {
            return process.ReadString(this.ToLong());
        }

        public override string ToString()
        {
            if (PointerTarget != null)
            {
                // Pass the request on to the pointed to Arguments struct
                return string.Format("{4}{0} at {3}:\n{1}\n{2}", Name, MemoryFunctions.Hexlify(Data, 16, true), PointerTarget.ToString(), this.GetLocation(), NamePrefix);
            }
            return string.Format("{3}{0} at {2}:\n{1}", Name, MemoryFunctions.Hexlify(Data, 16, true), this.GetLocation(), NamePrefix);
        }

        public string ToBase64()
        {
            return MemoryFunctions.ToBase64(Data);
        }

        public string ToAscii()
        {
            return MemoryFunctions.ToAscii(Data);
        }

        public string ToHex()
        {
            return MemoryFunctions.ToHex(Data);
        }

        public string ToString(string overrideName)
        {
            if (PointerTarget != null)
            {
                // Pass the request on to the pointed to Arguments struct
                return string.Format("{4}{0} at {3}:\n{1}\n{2}", overrideName, MemoryFunctions.Hexlify(Data, 16, true), PointerTarget.ToString(), this.GetLocation(), "");
            }
            return string.Format("{3}{0} at {2}:\n{1}", overrideName, MemoryFunctions.Hexlify(Data, 16, true), this.GetLocation(), "");
        }
    }

    public class Arguments : DynamicObject
    {
        protected Process _process;
        protected PythonBoss _pyBoss;

        protected List<Argument> _args;
        protected List<long> _arg_offsets;
        protected long _size;
        protected long _address;
        protected int _depth;
        protected Argument _parent;

        protected String NamePrefix;

        private IDictionary<string, object> _parsedFields = new Dictionary<string, object>(5);

        public Arguments()
        {
        }

        public Arguments(PythonBoss pyBoss, long address, List specs, Process process, int depth, Argument parent, string namePrefix)
        {
            NamePrefix = namePrefix;
            _process = process;
            _address = address;
            _pyBoss = pyBoss;
            _depth = depth;
            _parent = parent;
            _args = new List<Argument>(specs.Count);
            _arg_offsets = new List<long>(specs.Count);

            // Handle the case of infinite recursion
            if (depth > 1000)
                throw new Exception("Error when processing argument types: An infinite loop has been detected, this is caused by a type somehow including a pointer to itself. Name: " + namePrefix);

            ParseCurrentLevel(specs);
            ParseNextLevel();
        }

        protected void ParseCurrentLevel(List specs)
        {
            // Use the stack spec to build the structure
            long offset = 0;
            foreach (PythonDictionary spec in specs)
            {
                // Add this argument
                Argument newArg = new Argument(_pyBoss, _address + offset, spec, _process, _depth, this, NamePrefix);
                _args.Add(newArg);
                _arg_offsets.Add(offset);
                offset += newArg.Size;

                // Add it as dynamic member variable to the current arguments struct so that
                // it can be accessed naturally from python.
                this.SetMember(newArg.Name, newArg);
            }
            _size = offset;
        }

        protected void ParseNextLevel()
        {
            foreach (Argument arg in _args)
            {
                arg.ParseChildren();
            }
        }

        public string ToString()
        {
            string result = "";
            foreach (Argument arg in _args)
            {
                result = result + arg.ToString() + "\n";
            }
            return result;
        }

        // If you try to get a value of a property  
        // not defined in the class, this method is called. 
        public override bool TryGetMember(GetMemberBinder binder, out object result)
        {
            // Converting the property name to lowercase 
            // so that property names become case-insensitive. 
            string name = binder.Name.ToLower();

            // If the property name is found in a dictionary, 
            // set the result parameter to the property value and return true. 
            // Otherwise, return false. 
            return _parsedFields.TryGetValue(name, out result);
        }

        public bool TryGetMember(string name, out object result)
        {
            // If the property name is found in a dictionary, 
            // set the result parameter to the property value and return true. 
            // Otherwise, return false. 
            return _parsedFields.TryGetValue(name, out result);
        }

        public bool TryGetMemberSearchUp(string name, out object result)
        {
            if (_parsedFields.TryGetValue(name.ToLower(), out result))
            {
                return true;
            }
            if (_parent == null)
                return false;

            return _parent.TryGetMemberSearchUp(name.ToLower(), out result);
        }

        public Argument GetMemberSearchUp(string name)
        {
            // Try to find the name in this arguments set of arguments
            object result;
            if (_parsedFields.TryGetValue(name.ToLower(), out result))
                return (Argument) result;

            if (_parent == null)
                return null; // not found and can't go up

            return _parent.GetMemberSearchUp(name);
        }

        // If you try to set a value of a property that is 
        // not defined in the class, this method is called. 
        public override bool TrySetMember(SetMemberBinder binder, object value)
        {
            // Converting the property name to lowercase 
            // so that property names become case-insensitive.
            _parsedFields[binder.Name.ToLower()] = value;

            // You can always add a value to a dictionary, 
            // so this method always returns true. 
            return true;
        }

        protected bool SetMember(string name, object value)
        {
            // Converting the property name to lowercase 
            // so that property names become case-insensitive.
            _parsedFields[name.ToLower()] = value;

            // You can always add a value to a dictionary, 
            // so this method always returns true. 
            return true;
        }

        public void Reparse(long address)
        {
            // Parse these arguments from a new address while assuming the basic structure hasn't changed. If
            // the structure has the possibility of changing, a new Arguments() class should be created instead.
            _address = address;

            // Read in all arguments in this block
            byte[] data = MemoryFunctions.ReadMemory(_process.ProcessDotNet, address, (uint)_size);
            for (int i = 0; i < _args.Count; i++)
            {
                _args[i].Reparse(data, _arg_offsets[i]);
            }
        }

        public void GetFuzzBlockDescriptions(ref HashSet<FuzzBlock> blocks, int chunkSize)
        {
            // Return a list of [addresses], for the blocks of size unitSize that should be fuzzed.
            foreach (Argument arg in _args)
            {
                arg.GetFuzzBlockDescriptions(ref blocks, chunkSize);
            }
        }

        public List<FuzzBlock> GetFuzzBlockDescriptions()
        {
            HashSet<FuzzBlock> blocks = new HashSet<FuzzBlock>();
            foreach (Argument arg in _args)
            {
                arg.GetFuzzBlockDescriptions(ref blocks, (_process.IsWin64 ? 8 : 4));
            }
            return blocks.ToList<FuzzBlock>();
        }
    }
}
