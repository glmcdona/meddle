using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Text.RegularExpressions;
using MeddleFramework;

namespace Meddle
{
    public struct OpcodeAssembler {
        public readonly byte[] Opcode;
        public readonly bool Plusr;
        public readonly byte ModRegRM;

        public OpcodeAssembler(byte[] opcode, bool plusr, byte modRegRM)
        {
            Opcode = opcode;
            Plusr = plusr;
            ModRegRM = modRegRM;
        }

        public byte[] Assemble(out bool fullyAssembled, Shellcode shellcode)
        {
            fullyAssembled = true;
            return Opcode;
        }

        public byte[] Assemble(Operand op1, out bool fullyAssembled, Shellcode shellcode)
        {
            byte[] res_opcode = Opcode;
            byte[] res_ModRegRM = new byte[0];
            byte[] res_end = new byte[0];
            fullyAssembled = true;

            if (op1.Imm)
            {
                UInt64 imm = op1.GetValue(out fullyAssembled, shellcode);
                if (shellcode.IsWin64)
                {
                    res_end = res_end.Concat(MemoryFunctions.ToByteArray(imm)).ToArray();
                }
                else
                {
                    res_end = res_end.Concat(MemoryFunctions.ToByteArray((UInt32)imm)).ToArray();
                }
            }
            else if (op1.Reg && Plusr)
            {
                // Add register code to the last byte of the opcode and return
                res_opcode[res_opcode.Length - 1] = (byte)(res_opcode[res_opcode.Length - 1] + (byte)AssemblyDefines.Registers[op1.GetRegisterName()]);
            }
            else
            {
                fullyAssembled = false;
                throw new Exception("Opcode Assembler Error: Failed to assemble instruction with opcode " + MemoryFunctions.ByteArrayToString(Opcode));
            }

            return res_opcode.Concat(res_ModRegRM).Concat(res_end).ToArray();
        }

        public byte[] Assemble(Operand op1, Operand op2, out bool fullyAssembled, Shellcode shellcode)
        {
            // Double-operand assembler
            byte[] res_opcode = Opcode;
            byte[] res_ModRegRM = new byte[0];
            byte[] res_end = new byte[0];
            fullyAssembled = true;

            if (op1.Imm)
            {
                UInt64 imm = op1.GetValue(out fullyAssembled, shellcode);
                if (shellcode.IsWin64)
                {
                    res_end = res_end.Concat(MemoryFunctions.ToByteArray(imm)).ToArray();
                }
                else
                {
                    res_end = res_end.Concat(MemoryFunctions.ToByteArray((UInt32)imm)).ToArray();
                }
            }
            else if (op1.Reg && Plusr)
            {
                // Add register code to the last byte of the opcode and return
                res_opcode[res_opcode.Length - 1] = (byte)(res_opcode[res_opcode.Length - 1] + (byte)AssemblyDefines.Registers[op1.GetRegisterName()]);
            }
            else if (op1.Reg && ModRegRM == byte.MaxValue)
            {
                // Add register code to the start of the res_reg stream in ModRegRM format
                if (res_ModRegRM.Length == 0)
                {
                    byte mod = 0x3;
                    byte reg1 = (byte)AssemblyDefines.Registers[op1.GetRegisterName()];
                    res_ModRegRM = new byte[1] { (byte)((byte)(mod << 7) + (byte)(reg1 << 3)) };
                }
            }
            else
            {
                fullyAssembled = false;
                throw new Exception("Opcode Assembler Error: Failed to assemble instruction during processing of first operand with opcode " + MemoryFunctions.ByteArrayToString(Opcode));
            }

            if (op2.Imm)
            {
                bool partFullyAssembled = true;
                UInt64 imm = op2.GetValue(out partFullyAssembled, shellcode);
                if (!partFullyAssembled)
                    fullyAssembled = false;

                if (shellcode.IsWin64)
                {
                    res_end = res_end.Concat(MemoryFunctions.ToByteArray(imm)).ToArray();
                }
                else
                {
                    res_end = res_end.Concat(MemoryFunctions.ToByteArray((UInt32)imm)).ToArray();
                }
            }
            else if (op2.Reg && Plusr)
            {
                // Add register code to the last byte of the opcode and return
                res_opcode[res_opcode.Length - 1] = (byte)(res_opcode[res_opcode.Length - 1] + (byte)AssemblyDefines.Registers[op1.GetRegisterName()]);
            }
            else if (op1.Reg && ModRegRM == byte.MaxValue)
            {
                // Add register code to the start of the res_reg stream in ModRegRM format
                if (res_ModRegRM.Length == 1)
                {
                    res_ModRegRM[0] |= (byte)AssemblyDefines.Registers[op1.GetRegisterName()];
                }
            }
            else
            {
                fullyAssembled = false;
                throw new Exception("Opcode Assembler Error: Failed to assemble instruction during processing of second operand with opcode " + MemoryFunctions.ByteArrayToString(Opcode));
            }

            return res_opcode.Concat(res_ModRegRM).Concat(res_end).ToArray();
        }
    }

    public struct OpcodeDescriptor {
        public readonly string Mnem;
        public readonly bool HasOperand1;
        public readonly bool Deref1;
        public readonly bool Imm1;

        public readonly bool HasOperand2;
        public readonly bool Deref2;
        public readonly bool Imm2;

        public OpcodeDescriptor(string mnem) {
            Mnem = mnem;
            
            HasOperand1 = false;
            Deref1 = false;
            Imm1 = false;

            HasOperand2 = false;
            Deref2 = false;
            Imm2 = false;
        }

        public OpcodeDescriptor(string mnem, Operand op1)
        {
            Mnem = mnem;

            HasOperand1 = true;
            Deref1 = op1.Deref;
            Imm1 = op1.Imm;

            HasOperand2 = false;
            Deref2 = false;
            Imm2 = false;
        }

        public OpcodeDescriptor(string mnem, bool deref1, bool imm1)
        {
            Mnem = mnem;

            HasOperand1 = true;
            Deref1 = deref1;
            Imm1 = imm1;

            HasOperand2 = false;
            Deref2 = false;
            Imm2 = false;
        }

        public OpcodeDescriptor(string mnem, bool deref1, bool imm1, bool deref2, bool imm2)
        {
            Mnem = mnem;

            HasOperand1 = true;
            Deref1 = deref1;
            Imm1 = imm1;

            HasOperand2 = true;
            Deref2 = deref2;
            Imm2 = imm2;
        }

        public OpcodeDescriptor(string mnem, Operand op1, Operand op2)
        {
            Mnem = mnem;

            HasOperand1 = true;
            Deref1 = op1.Deref;
            Imm1 = op1.Imm;

            HasOperand2 = true;
            Deref2 = op2.Deref;
            Imm2 = op2.Imm;
        }
        
        public override bool Equals(object obj)
        {
            // Compare only included operands
            OpcodeDescriptor other = (OpcodeDescriptor) obj;

            if( !HasOperand1 )
            {
                return other.Mnem == Mnem;
            }else if( !HasOperand2 )
            {
                return other.Mnem == Mnem && other.Deref1 == Deref1 && other.Imm1 == Imm1;
            }else{
                return other.Mnem == Mnem && other.Deref1 == Deref1 && other.Imm1 == Imm1 && other.Deref2 == Deref2 && other.Imm2 == Imm2;
            }
        }

        public override int GetHashCode()
        {
            if( !HasOperand1 )
            {
                return Mnem.GetHashCode();
            }else if( !HasOperand2 )
            {
                return Mnem.GetHashCode() ^ Deref1.GetHashCode() ^ Imm1.GetHashCode();
            }else{
                return Mnem.GetHashCode() ^ Deref1.GetHashCode() ^ Imm1.GetHashCode() ^ Deref2.GetHashCode() ^ Imm2.GetHashCode();
            }
        }
    }

    public static class AssemblyDefines
    {
        public static readonly Dictionary<string, int> Registers
                        = new Dictionary<string, int>
                    {
                        { "eax", 0 },
                        { "rax", 0 },
                        { "ecx", 1 },
                        { "rcx", 1 },
                        { "edx", 2 },
                        { "rdx", 2 },
                        { "ebx", 3 },
                        { "rbx", 3 },
                        { "esp", 5 },
                        { "rsp", 5 },
                        { "ebp", 5 },
                        { "rbp", 5 },
                        { "esi", 6 },
                        { "rsi", 6 },
                        { "edi", 7 },
                        { "rdi", 7 },
                    };

        public static readonly Dictionary<OpcodeDescriptor, OpcodeAssembler> OpcodeAssemblers = new Dictionary<OpcodeDescriptor, OpcodeAssembler>
                    {
                                           /* (mnem,deref1,imm1,deref2,imm2)                        (opcode,plusr,r)              */
                        { new OpcodeDescriptor("mov", false, false, false, false),   new OpcodeAssembler( new byte[] {0x89}, false, byte.MaxValue) }, // mov reg,reg
                        { new OpcodeDescriptor("pushad"),   new OpcodeAssembler( new byte[] {0x60}, false, 0) },
                        { new OpcodeDescriptor("popad"),    new OpcodeAssembler( new byte[] {0x61}, false, 0) }
                    };
        
    }

    public class Operand
    {
        public bool Reg;
        public bool Imm;
        public bool Deref;

        private UInt64 _value;
        private string _valueName;
        private string _registerName;

        public Operand(string operand)
        {
            Reg = false;
            Imm = false;
            Deref = false;
            _valueName = null;

            if (operand.Contains('[') && operand.Contains(']'))
            {
                // Deref whatever it is
                Deref = true;
                operand = operand.Replace("[", "").Replace("]", "");
            }

            if (AssemblyDefines.Registers.ContainsKey(operand))
            {
                Reg = true;
                _registerName = operand;
            }
            else
            {
                // Imm, can be directly or indirectly specified
                if (operand.Contains('#'))
                {
                    _valueName = operand.Replace("#", "");
                }
                else
                {
                    // Just an imm
                    _value = UInt64.Parse(operand, System.Globalization.NumberStyles.AllowHexSpecifier);
                }
            }
        }

        public string GetRegisterName()
        {
            return _registerName;
        }

        public UInt64 GetValue(out bool realValue, Shellcode shellcode)
        {
            if (Imm && _valueName != null)
            {
                // Return dummy value if variable not resolved
                UInt64 value = 0;
                realValue = shellcode.GetVariable(_valueName, out value);
                return value;
            }
            realValue = true;
            return _value;
        }
    }

    public class Instruction
    {
        // Description of instruction
        public int Size;
        public byte[] Data;
        public UInt64 Offset;
        public bool FullyAssembled;

        // Description of variable
        public bool HasVariable;
        public bool VariableIsOffset;
        public string VariableName;

        public Instruction(Shellcode parent, Process process, string instruction, UInt64 offset)
        {
            Assemble( parent, process, instruction, offset);
        }

        public bool Assemble(Shellcode parent, Process process, string instruction, UInt64 offset)
        {
            // Parse this instruction if there is one
            Offset = offset;
            Size = 0;
            Data = null;
            HasVariable = false;
            VariableIsOffset = false;
            FullyAssembled = false;
            VariableName = "";

            string[] fields = instruction.Split(new char[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries);

            if (fields.Length == 1 && fields.Contains(":"))
            {
                // This is a label. Add it as a variable.
                parent.SetVariable(fields[0].Replace(":", ""), offset);
                FullyAssembled = true;
            }
            else
            {
                // Load the opcode and operands
                string opcode = fields[0];
                List<Operand> operands = new List<Operand>(fields.Length - 1);
                for (int i = 1; i < fields.Length; i++)
                    operands.Add(new Operand(fields[i]));

                // Assemble the instruction now
                byte[] bytes;
                if (operands.Count < 1)
                {
                    OpcodeAssembler builder = AssemblyDefines.OpcodeAssemblers[new OpcodeDescriptor(opcode)];
                    bytes = builder.Assemble(out FullyAssembled, parent);
                }
                else if (operands.Count < 2)
                {
                    OpcodeAssembler builder = AssemblyDefines.OpcodeAssemblers[new OpcodeDescriptor(opcode, operands[0])];
                    bytes = builder.Assemble(operands[0], out FullyAssembled, parent);
                }
                else
                {
                    OpcodeAssembler builder = AssemblyDefines.OpcodeAssemblers[new OpcodeDescriptor(opcode, operands[0], operands[1])];
                    bytes = builder.Assemble(operands[0], operands[1], out FullyAssembled, parent);
                }

                Data = bytes;
                this.Size = bytes.Length;
            }

            return FullyAssembled;
        }
    }

    public class Shellcode
    {
        private Dictionary<string, object> _variables;
        private Process _process;
        private string[] _code;
        public bool IsWin64;
        private List<Instruction> _instructions;

        public Shellcode(XDocument description, Process process)
        {
            _process = process;
            _code = null;
            IsWin64 = process.IsWin64;
            
            // Load the xml description
            parse(description);
        }

        public void Assemble()
        {
            if (_code == null)
                return;

            // Assemble the code for the target
            // Simplifications:
            //  - Cannot access 64-bit and 32-bit registers separately. rax is eax and eax is rax.
            UInt64 offset = 0;
            _instructions = new List<Instruction>(_code.Length);
            foreach( string line in _code )
            {
                // Assemble this instruction
                Instruction tmpInstr = new Instruction(this, _process, line, offset);
                if (tmpInstr.Size > 0)
                {
                    // Had a real instruction
                    offset += (UInt64) tmpInstr.Size;
                    _instructions.Add(tmpInstr);
                }
            }

            // Assemble a second time now that we know all variables and labels
            // TODO: continue here
        }

        private void parse(XDocument description)
        {
            try
            {
                // Parse and resolve the defined variables
                foreach (XElement element in description.Descendants("Variable"))
                {
                    string name = element.Attribute("Name").ToString();
                    object value = 0;
                    if (element.HasElements)
                    {
                        value = parseValue(element.Elements().First());
                    }


                    SetVariable(name, value);
                }

                // Parse the code
                var blockComments = @"/\*(.*?)\*/";
                var lineComments = @"//(.*?)\r?\n";
                var strings = @"""((\\[^\n]|[^""\n])*)""";
                var verbatimStrings = @"@(""[^""]*"")+";

                string code = description.Descendants("Code").FirstOrDefault().Value.ToString();
                code = Regex.Replace(code,
                                                    blockComments + "|" + lineComments + "|" + strings + "|" + verbatimStrings,
                                                    me =>
                                                    {
                                                        if (me.Value.StartsWith("/*") || me.Value.StartsWith("//"))
                                                            return me.Value.StartsWith("//") ? Environment.NewLine : "";
                                                        // Keep the literal strings
                                                        return me.Value;
                                                    },
                                                    RegexOptions.Singleline);

                _code = code.Split( new char[]{ '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                        "HOOK PARSING ERROR: An unknown error occured while processing a hook xml description.\n" + "\n\nError Reason: " + ex.Message.ToString() + "\n");
            }
        }

        private object parseValue(XElement item)
        {
            try
            {
                switch (item.Name.ToString().ToLowerInvariant())
                {
                    case "api":
                        // Resolve an api import
                        ulong address = MemoryFunctions.loadAddress(item.Element("Library").Value.ToString(), item.Element("Procedure").Value.ToString(), _process.ProcessDotNet);
                        return (_process.IsWin64 ? (UInt64)address : (UInt32)address);


                    case "intptr":
                        string data = item.Value.ToString();
                        return (_process.IsWin64 ? UInt64.Parse(data, System.Globalization.NumberStyles.AllowHexSpecifier) : UInt32.Parse(data, System.Globalization.NumberStyles.AllowHexSpecifier));

                    default:
                        return null;

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                        "HOOK PARSING ERROR: An unknown error occured while processing a hook <Variable> element.\n" +
                        "\nLocation: " + item.Name.ToString() + "\n\nError Reason: " + ex.Message.ToString() + "\n");
                return null;
            }
        }


        public void SetVariable(string name, object value)
        {
            if (_variables.ContainsKey(name))
                _variables[name] = value;
            else
                _variables.Add(name, value);
        }

        public bool GetVariable(string name, out UInt64 value)
        {
            if (!_variables.ContainsKey(name))
            {
                value = 0;
                return false;
            }

            value = (UInt64)_variables[name];
            return true;
        }
    }

    public class BreakpointShellcode
    {


        private string _hook = @"<?xml version=""1.0""?>
            <Hook>
                <Code Name='Breakpoint'>
                    start:
                        pushad

                        // Build data packet to meddle
                        call #GetCurrentThread#
                        mov [lpInBuffer_0], eax
                        
                        call #GetCurrentProcessId#
                        mov [lpInBuffer_1], eax

                        // Call meddle
                        push 1000 // Wait 1 second at most
                        push #lpBytesRead#
                        push 0 // nOutBufferSize
                        push 0 // lpOutBuffer
                        push 8 // nInBuffserSize
                        push #lpInBuffer_0# // lpInBuffer
                        push pipe_name // lpNamedPipeName
                        call #CallNamedPipe#
                        popad
                        
                        // Restore the original code
                        
                        jmp #ReturnAddress#
                    
                    lpInBuffer_0: // hthread
                        dd 0
                    lpInBuffer_1: // pid
                        dd 0
                    lpBytesRead:
                        dd 0
                    pipe_name:
                        ascii 'meddle'
                </Code>
            
                <Variables>
                    <Variable Name='GetCurrentThread'>
                        <Api>
                            <Library>kernel32.dll</Library>
                            <Procedure>GetCurrentThread</Procedure>
                        </Api>
                    </Variable>
                    
                    <Variable Name='SuspendThread'>
                        <Api>
                            <Library>kernel32.dll</Library>
                            <Procedure>SuspendThread</Procedure>
                        </Api>
                    </Variable>
                    
                    <Variable Name='ReturnAddress'>
                        <IntPtr>0</IntPtr>
                    </Variable>
                </Variables>
            </Hook>";


    }

    

}
