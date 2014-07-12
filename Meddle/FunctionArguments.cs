using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IronPython.Runtime;
using System.Dynamic;
using MeddleFramework;

namespace Meddle
{
    public class RegisterArgument : Argument
    {
        private string Register;

        public RegisterArgument(PythonBoss pyBoss, Context context, PythonDictionary spec, Process process, Arguments parent, string namePrefix)
        {
            NamePrefix = namePrefix;
            this.process = process;

            // Parse the spec for this argument
            // regspec: [{"name": "socket",
		    //		      "register": "rcx",
		    //		      "type": None,
		    //		      "fuzz": NOFUZZ},]

            Register = ((string) spec.get("register")).ToLower();
            Fuzz = (bool)spec.get("fuzz");
            Name = (string)spec.get("name");
            _argumentType = (object)spec.get("type");

            if (spec.ContainsKey("size_override"))
                _childSizeOverride = (object)spec.get("size_override");
            else
                _childSizeOverride = null;

            // Validate required fields
            if (Name == null)
                throw new Exception("ERROR: Argument specification must include 'name' attribute. Failed when parsing name prefix '" + namePrefix + "'.");
            else if (Fuzz == null)
                throw new Exception("ERROR: Argument specification must include 'fuzz' attribute. Failed when parsing type '" + namePrefix + Name + "'.");
            
            this.process = process;
            _pyBoss = pyBoss;
            _parent = parent;

            // Read the data
            var tmpData = context.GetMember(Register);
            if (tmpData is UInt32)
                Data = BitConverter.GetBytes((UInt32)tmpData);
            else if (tmpData is UInt64)
                Data = BitConverter.GetBytes((UInt64)tmpData);
            else
                throw new Exception("Register argument type definition problem. The register must be of type 'int' or 'long'. The is likely an engine bug. Argument name: " + Name + ". The unsupported register type is: " + tmpData.ToString());
            Size = Data.Length;

            PointerTarget = null;
        }

        public override string GetLocation()
        {
            return Register;
        }
        
        public override void GetFuzzBlockDescriptions(ref HashSet<FuzzBlock> blocks, int chunkSize)
        {
            if (this.Fuzz)
            {
                // Add this data argument as a fuzz
                var block = new FuzzBlockRegister(process.ProcessDotNet, Register, NamePrefix + Name + " + REGISTER " + Register, chunkSize);
                if (!blocks.Contains(block))
                    blocks.Add(block);
            }

            if (this.PointerTarget != null)
            {
                // Forward this to the pointed to arguments description
                PointerTarget.GetFuzzBlockDescriptions(ref blocks, chunkSize);
            }
        }
    }

    public class FunctionArguments : Arguments
    {
        public FunctionArguments(PythonBoss pyBoss, Context context, List stackSpec, List registerSpec, Process process)
        {
            _process = process;
            _address = (long)context.GetSP();
            _pyBoss = pyBoss;
            _depth = 0;
            _args = new List<Argument>(stackSpec.Count + registerSpec.Count);
            _arg_offsets = new List<long>(stackSpec.Count);
            _parent = null;

            ParseCurrentRegisterLevel(registerSpec, context);
            ParseCurrentLevel(stackSpec);
            ParseNextLevel();
        }

        protected void ParseCurrentRegisterLevel(List registerSpec, Context context)
        {
            // Use the stack spec to build the structure
            foreach (PythonDictionary spec in registerSpec )
            {
                // Add this register argument
                Argument newArg = new RegisterArgument(_pyBoss, context, spec, _process, this, NamePrefix);
                _args.Insert(0, newArg);

                // Add it as dynamic member variable to the current arguments struct so that
                // it can be accessed naturally from python.
                this.SetMember(newArg.Name, newArg);
            }
        }
    }
}
