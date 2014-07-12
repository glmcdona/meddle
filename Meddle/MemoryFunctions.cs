using System;
using System.Collections.Generic;
using System.Globalization;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MeddleFramework
{
    public class addressRegion : IComparable
    {
        public Int64 address = 0;
        public int length = 0;

        public addressRegion(Int64 address, int length)
        {
            this.address = address;
            this.length = length;
        }

        public addressRegion(IntPtr address, int length)
        {
            this.address = (Int64)address;
            this.length = length;
        }

        int IComparable.CompareTo(object b)
        {
            return address.CompareTo(((addressRegion)b).address);
        }


    }

    public static class MemoryFunctions
    {
        // Quick way of checking if a character value is displayable ascii
                                                            /*          0     1     2     3        4     5     6     7        8     9     A     B        C     D     E     F     */
        public static bool[] isDisplayableAscii =/* 0x00 */new bool[]{false,false,false,false,   false,false,false,false,   false,false ,true,false,   false,true ,false,false,
	                                             /* 0x10 */  false,false,false,false,   false,false,false,false,   false,false,false,false,   false,false,false,false,
	                                             /* 0x20 */  true ,true ,true ,true ,   true ,true ,true ,true ,   true ,true ,true ,true ,   true ,true ,true ,true ,
	                                             /* 0x30 */  true ,true ,true ,true ,   true ,true ,true ,true ,   true ,true ,true ,true ,   true ,true ,true ,true ,
	                                             /* 0x40 */  true ,true ,true ,true ,   true ,true ,true ,true ,   true ,true ,true ,true ,   true ,true ,true ,true ,
	                                             /* 0x50 */  true ,true ,true ,true ,   true ,true ,true ,true ,   true ,true ,true ,true ,   true ,true ,true ,true ,
	                                             /* 0x60 */  true ,true ,true ,true ,   true ,true ,true ,true ,   true ,true ,true ,true ,   true ,true ,true ,true ,
	                                             /* 0x70 */  true ,true ,true ,true ,   true ,true ,true ,true ,   true ,true ,true ,true ,   true ,true ,true ,false,
	                                             /* 0x80 */  false,false,false,false,   false,false,false,false,   false,false,false,false,   false,false,false,false,
	                                             /* 0x90 */  false,false,false,false,   false,false,false,false,   false,false,false,false,   false,false,false,false,
	                                             /* 0xA0 */  false,false,false,false,   false,false,false,false,   false,false,false,false,   false,false,false,false,
	                                             /* 0xB0 */  false,false,false,false,   false,false,false,false,   false,false,false,false,   false,false,false,false,
	                                             /* 0xC0 */  false,false,false,false,   false,false,false,false,   false,false,false,false,   false,false,false,false,
	                                             /* 0xD0 */  false,false,false,false,   false,false,false,false,   false,false,false,false,   false,false,false,false,
	                                             /* 0xE0 */  false,false,false,false,   false,false,false,false,   false,false,false,false,   false,false,false,false,
	                                             /* 0xF0 */  false,false,false,false,   false,false,false,false,   false,false,false,false,   false,false,false,false};

        public static void getDebugPrivileges()
        {
            try
            {
                System.Diagnostics.Process.EnterDebugMode();
            }
            catch
            {

            }

            /*
            IntPtr hToken;
            LUID luidSEDebugNameValue;
            TOKEN_PRIVILEGES tkpPrivileges;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            {
                Console.WriteLine("OpenProcessToken() failed, error = {0} . SeDebugPrivilege is not available", Marshal.GetLastWin32Error());
                return;
            }
            else
            {
                Console.WriteLine("OpenProcessToken() successfully");
            }
            if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out luidSEDebugNameValue))
            {
                Console.WriteLine("LookupPrivilegeValue() failed, error = {0} .SeDebugPrivilege is not available", Marshal.GetLastWin32Error());
                CloseHandle(hToken);
                return;
            }
            else
            {
                Console.WriteLine("LookupPrivilegeValue() successfully");
            }
            tkpPrivileges.PrivilegeCount = 1;
            tkpPrivileges.Luid = luidSEDebugNameValue;
            tkpPrivileges.Attributes = SE_PRIVILEGE_ENABLED;
            if (!AdjustTokenPrivileges(hToken, false, ref tkpPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
            {
                Console.WriteLine("LookupPrivilegeValue() failed, error = {0} .SeDebugPrivilege is not available", Marshal.GetLastWin32Error());
            }
            else
            {
                Console.WriteLine("SeDebugPrivilege is now available");
            }
            CloseHandle(hToken);
            Console.ReadLine();
             * */
        }

        public static string reverseString(string input)
        {
            // Reverses the input string
            string result = "";
            for (int i = 0; i < input.Length; i += 2)
                result = String.Concat(input[i], input[i + 1], result);
            return result;
        }

        /// <summary>
        /// Converts the number an 8-character hex representation, with byte-wise reversing.
        /// </summary>
        /// <param name="number"></param>
        /// <returns></returns>
        public static string intToDwordString(uint number)
        {
            // Convert it to an 4-byte string
            string result = number.ToString("X");
            while (result.Length < 8)
                result = "0" + result;

            // Reverse the string
            return reverseString(result);
        }

        /// <summary>
        /// Converts a uint to a signed float.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static float intToFloat(uint input)
        {
            // This is untested, I am not sure if I did this perfectly!
            int sign = (input & 0x80000000) == 1 ? -1 : 1;
            int exponent = ((int)(input & 0x7F800000)) >> 23;
            return (float)sign * (1.0f + ((float)(input & 0x007fffff)) / ((float)(2 ^ 23))) * (float)(2 ^ (exponent - 127));
        }

        public static UInt64 loadAddress(string dllName, string procedureName, Process process)
        {
            // Find the dll in the destination process
            ProcessModule dll = null;
            foreach (ProcessModule module in process.Modules)
            {
                try
                {
                    if (module.ModuleName.ToLower().Equals(dllName.ToLower()) || module.ModuleName.ToLower().Equals(dllName.ToLower() + ".dll"))
                    {
                        dll = module;
                        break;
                    }
                }
                catch { }
            }
            if (dll == null)
            {
                Console.WriteLine("Failed to find dll named " + dllName + " while searching for procedure " + procedureName + ".");
                return 0;
            }

            // Import the dll into our application and find the function offset from the base address of the module
            int hwnd = LoadLibrary(dllName);
            UInt64 myProcedureAddress = (UInt64)GetProcAddress(hwnd, procedureName);

            // Find the dll base address in our process
            UInt64 myDllBase = 0;
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                try
                {
                    if (module.ModuleName.ToLower().Equals(dllName.ToLower()) || module.ModuleName.ToLower().Equals(dllName.ToLower() + ".dll"))
                    {
                        myDllBase = (UInt64)module.BaseAddress;
                        break;
                    }
                }
                catch { }
            }
            if (myDllBase == 0)
            {
                Console.WriteLine("Failed to find dll named " + dllName + " while searching myself to obtain base address. Procedure " + procedureName + ".");
                FreeLibrary((IntPtr)hwnd);
                return 0;
            }

            // Calculate the address
            UInt64 offsetProcedure = myProcedureAddress - myDllBase;
            UInt64 procedureAddressTarget = offsetProcedure + (UInt64)dll.BaseAddress;

            // Remove the new copy of kernel32.dll
            FreeLibrary((IntPtr)hwnd);

            return procedureAddressTarget;
        }


        /*public static byte[] getMin5Bytes(Process process, uint addressStart)
        {
            // This function returns NULL if in the first 5 bytes it starts a call or jump statement.
            // This is to protect it from screwing up the code.

            // Create our disassembler
            xdis.Class1 disassembler = new xdis.Class1();

            // Read in the memory
            byte[] buffer = new byte[50];
            IntPtr numRead = (IntPtr)0;
            ReadProcessMemory(process.Handle, (IntPtr)(addressStart), buffer, 50, ref numRead);

            unsafe
            {
                // Set the disassembler source data
                IntPtr tmpPtr = Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0);
                disassembler.setData((byte*)tmpPtr, (uint)buffer.Length, (uint)(addressStart));
                uint address = 0;
                uint* pAddress = &address;

                // Create our string and hex pointers
                sbyte* ascii = (sbyte*)Marshal.UnsafeAddrOfPinnedArrayElement(new sbyte[255], 0);
                sbyte* hex = (sbyte*)Marshal.UnsafeAddrOfPinnedArrayElement(new sbyte[255], 0);

                // Read in the instructions until we have over 5 bytes of data
                uint offsetStart = 0;
                uint count = 0;
                uint lastAddress = addressStart;
                byte[] data = new byte[50];
                while (disassembler.getNextInstruction(pAddress, &ascii, &hex) != 0 && count < 5)
                {
                    // Record this location if it is a nop instruction
                    if ((ascii[0] == 'c' && ascii[1] == 'a' && ascii[2] == 'l' && ascii[3] == 'l' && ascii[4] == ' ') ||
                        (ascii[0] == 'j' && ascii[1] == 'm' && ascii[2] == 'p' && ascii[3] == ' '))
                        return null;

                    // Increment our total count
                    count += address - lastAddress;
                    lastAddress = address;
                }

                // Read in our result
                byte[] result = oMemoryFunctions.readMemory(process, addressStart, count);

                // Return
                return result;
            }
        }*/





        public static ProcessModule getModuleFromAddress(Process process, ulong addressLoc)
        {
            // This function figures out which module the specified address lies in
            ulong resultBase = 0;
            ProcessModule resultModule = null;

            foreach (ProcessModule module in process.Modules)
            {
                if ((ulong)(module.BaseAddress) > resultBase && (ulong)(module.BaseAddress) <= addressLoc)
                {
                    resultBase = (ulong)(module.BaseAddress);
                    resultModule = module;
                }
            }
            return resultModule;
        }

        public static byte[] readMemory(Process process, Int64 address, UInt32 length)
        {
            return readMemory(process, (IntPtr)address, length);
        }

        public static byte readMemoryByte(Process process, UInt64 address)
        {
            return readMemoryByte(process, (IntPtr)address);
        }

        public static ushort readMemoryUShort(Process process, UInt64 address)
        {
            return readMemoryUShort(process, (IntPtr)address);
        }

        public static UInt32 readMemoryDword(Process process, UInt64 address)
        {
            return readMemoryDword(process, (IntPtr)address);
        }

        public enum STRING_TYPE
        {
            auto,
            ascii,
            unicode
        }

        public static string ToHex(byte[] data)
        {
            // Hex string representation of byte array
            string result = "";

            for (int i = 0; i < data.Length; i++)
            {
                result += data[i].ToString("X");
            }

            return result.TrimEnd();
        }

        public static string ToAscii(byte[] data)
        {
            // Builds a string of the ascii representation of a byte array
            string result = "";

            for (int i = 0; i < data.Length; i++)
            {
                if (isDisplayableAscii[data[i]] && data[i] != '\r' && data[i] != '\n')
                    result += (char)data[i];
                else
                    result += ".";
            }

            return result;
        }

        public static string ToBase64(byte[] data)
        {
            // Return the base64 encoding
            return System.Convert.ToBase64String(data);
        }

        public static string Hexlify(byte[] data, int width, bool printAscii)
        {
            // Hexifys data, eg:
            // 1a 2f 29 1a 2f 29 1a 2f   1a 2f 29 1a 2f 29 1a 2f   abcdabcdeabcdabcd
            // 1a 2f 29 1a 2f 29 1a 2f   1a 2f 29 1a 2f 29 1a 2f   abcdabcdeabcdabcd
            // 1a 2f 29 1a 2f 29 1a 2f   1a 2f 29 1a 2f 29 1a 2f   abcdabcdeabcdabcd

            string result = "";
            List<byte> currentRow = new List<byte>(width);
            int column = 0;
            int asciiColumn = width * 3 + (width / 8) * 2 + 2;
            for (int i = 0; i < data.Length; i++)
            {
                result += data[i].ToString("X2") + " ";
                currentRow.Add(data[i]);
                column += 3;

                if (i % width == width - 1 || i == data.Length - 1)
                {
                    // Print the ascii and add line break
                    if (printAscii)
                    {
                        while (column < asciiColumn)
                        {
                            result += "  ";
                            column += 2;
                        }

                        for (int j = 0; j < currentRow.Count; j++)
                        {
                            if (j % 8 == 0)
                                result += "  ";
                            if (isDisplayableAscii[currentRow[j]] && currentRow[j] != '\r' && currentRow[j] != '\n')
                                result += (char)currentRow[j];
                            else
                                result += ".";
                        }
                    }
                    result += "\n";
                    currentRow.Clear();
                    column = 0;
                }
                else if (i % width == 7)
                {
                    result += "  ";
                    column += 2;
                }
            }

            return result;

        }

        public static string Hexlify(List<byte> data, int width, bool printAscii)
        {
            // Hexifys data, eg:
            // 1a 2f 29 1a 2f 29 1a 2f   1a 2f 29 1a 2f 29 1a 2f   abcdabcdeabcdabcd
            // 1a 2f 29 1a 2f 29 1a 2f   1a 2f 29 1a 2f 29 1a 2f   abcdabcdeabcdabcd
            // 1a 2f 29 1a 2f 29 1a 2f   1a 2f 29 1a 2f 29 1a 2f   abcdabcdeabcdabcd

            string result = "";
            List<byte> currentRow = new List<byte>(width);
            int column = 0;
            int asciiColumn = width * 3 + (width / 8) * 2 + 2;
            for (int i = 0; i < data.Count; i++)
            {
                result += data[i].ToString("X2") + " ";
                currentRow.Add(data[i]);
                column += 3;

                if (i % width == width - 1 || i == data.Count - 1)
                {
                    // Print the ascii and add line break
                    if (printAscii)
                    {
                        while (column < asciiColumn)
                        {
                            result += "  ";
                            column += 2;
                        }

                        for (int j = 0; j < currentRow.Count; j++)
                        {
                            if (j % 8 == 0)
                                result += "  ";
                            if (isDisplayableAscii[currentRow[j]] && currentRow[j] != '\r' && currentRow[j] != '\n')
                                result += (char)currentRow[j];
                            else
                                result += ".";
                        }
                    }
                    result += "\n";
                    currentRow.Clear();
                    column = 0;
                }
                else if (i % width == 7)
                {
                    result += "  ";
                    column += 2;
                }
            }

            return result;

        }

        public static string ReadString(Process process, UInt64 address, STRING_TYPE type)
        {
            // Reads a string from the specified address.
            string result = "";
            bool moreString = true;
            int chunkSize = 0x100;
            while (moreString)
            {
                byte[] data = readMemory(process, (long)address, (uint)chunkSize);
                if (data.Length == 0)
                    return result;
                int i = 0;
                while (i < chunkSize && i < data.Length && moreString)
                {
                    if (isDisplayableAscii[data[i]])
                        result = result + ((char)data[i]);
                    else
                        moreString = false;

                    if (type == STRING_TYPE.auto && i + 1 < data.Length)
                        type = (data[i + 1] == 0 ? STRING_TYPE.unicode : STRING_TYPE.ascii);
                    else if (type == STRING_TYPE.auto)
                        type = STRING_TYPE.ascii;

                    if (type == STRING_TYPE.ascii)
                        i++;
                    else
                        i += 2;
                }
                address += (ulong)i;
            }
            return result;
        }


        public static List<UInt64> MemoryFindAll(Process processDotNet, IntPtr moduleBase, UInt32 size, object[] pattern)
        {
            List<UInt64> result = new List<ulong>();

            // Read in the module memory
            byte[] data = readMemory(processDotNet, moduleBase, size);

            // Find the matches
            for (int i = 0; i < data.Length - pattern.Length; i++)
            {
                bool matched = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if ((pattern[j] is int || pattern[j] is long || pattern[j] is byte) && (byte)(int)pattern[j] != data[i + j])
                    {
                        matched = false;
                        break;
                    }
                }
                if (matched)
                    result.Add(((UInt64)i + (UInt64)moduleBase));
            }

            return result;
        }

        public static byte[] readMemory(Process process, IntPtr address, UInt32 length)
        {
            // Copy the bytes from this heap
            byte[] buffer = new byte[length];
            int numRead = 0;
            bool result = ReadProcessMemory(process.Handle, address, buffer, (int)length, out numRead);

            if (!result && GetLastError() != 299) // ERROR_PARTIAL_COPY
            {
                //Console.WriteLine("GetLastError = " + GetLastError().ToString()); //998
                return new byte[0];
            }

            // Check that all the data was read correctly
            //if ((UInt32)numRead != length)
            //    Console.WriteLine("Failed to read memory from address " + address.ToString("X") + ". Read " + numRead.ToString() + " of " + length.ToString() + ".")
            if ((UInt32)numRead != length)
            {
                byte[] newBuffer = new byte[numRead];
                if (newBuffer.Length > 0)
                {
                    Array.ConstrainedCopy(buffer, 0, newBuffer, 0, newBuffer.Length);
                }
                return newBuffer;
            }



            return buffer;
        }


        public static byte readMemoryByte(Process process, IntPtr address)
        {
            // Copy the bytes from this heap
            byte[] buffer = new byte[1];
            int numRead = 0;
            ReadProcessMemory(process.Handle, (IntPtr)address, buffer, 1, out numRead);

            // Check that all the data was read correctly
            if ((int)numRead != 1)
                Console.WriteLine("Failed to read BYTE from address " + address.ToString("X") + ". Read " + numRead.ToString() + " of 4.");

            return (byte)RawDataToObject(ref buffer, typeof(byte));
        }


        public static ushort readMemoryUShort(Process process, IntPtr address)
        {
            // Copy the bytes from this heap
            byte[] buffer = new byte[2];
            int numRead = 0;
            ReadProcessMemory(process.Handle, (IntPtr)address, buffer, 2, out numRead);

            // Check that all the data was read correctly
            if ((int)numRead != 2)
                throw new Exception("Failed to read SHORT from address " + address.ToString("X") + ". Read " + numRead.ToString() + " of 2.");

            return (ushort)RawDataToObject(ref buffer, typeof(ushort));
        }



        public static UInt32 readMemoryDword(Process process, IntPtr address)
        {
            // Copy the bytes from this heap
            byte[] buffer = new byte[4];
            int numRead = 0;
            ReadProcessMemory(process.Handle, (IntPtr)address, buffer, 4, out numRead);

            // Check that all the data was read correctly
            if ((UInt32)numRead != 4)
            {
                // Retry once incase we caused a page guard stack growth
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                long blockSize = (long)VirtualQueryEx(process.Handle, (IntPtr)address, ref mbi, (IntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                throw new Exception("Failed to read DWORD from address " + address.ToString("X") + ". Read " + numRead.ToString() + " of 4. GetLastError() = " + GetLastError().ToString() + "\n" + mbi.Protect.ToString() + "\n" + mbi.State.ToString());
            }

            return (UInt32)RawDataToObject(ref buffer, typeof(UInt32));
        }

        public static UInt64 readMemoryQword(Process process, IntPtr address)
        {
            // Copy the bytes from this heap
            byte[] buffer = new byte[8];
            int numRead = 0;
            ReadProcessMemory(process.Handle, address, buffer, 8, out numRead);

            // Check that all the data was read correctly
            if ((UInt32)numRead != 8)
                throw new Exception("Failed to read QWORD from address " + address.ToString("X") + ". Read " + numRead.ToString() + " of 8. GetLastError() = " + GetLastError().ToString());

            return (UInt64)RawDataToObject(ref buffer, typeof(UInt64));
        }

        public static string readMemoryString(Process process, UInt64 address, int maxLength)
        {
            // Copy the bytes from this heap
            byte[] buffer = new byte[maxLength];
            int numRead = 0;
            ReadProcessMemory(process.Handle, (IntPtr)address, buffer, maxLength, out numRead);

            // Check that all the data was read correctly
            if ((UInt32)numRead != maxLength)
                Console.WriteLine("Failed to read string from address " + address.ToString("X") + ". Read " + numRead.ToString() + " of " + maxLength.ToString() + ".");

            // Find the first null in the data
            int length = 0;
            string result = "";
            while (length < maxLength && buffer[length] != 0)
            {
                result += (char)buffer[length];
                length++;
            }

            return result;
        }

        public static bool WriteMemory(Process process, Int64 address, byte data)
        {
            return WriteMemory(process, (IntPtr)address, data);
        }

        public static bool WriteMemory(Process process, UInt64 address, byte[] data)
        {
            return WriteMemory(process, (IntPtr)address, data);
        }

        public static bool WriteMemory(Process process, IntPtr address, byte[] data)
        {
            // Write the array
            IntPtr numWritten = (IntPtr)0;
            return WriteProcessMemory(process.Handle, (IntPtr)address, data, (uint)data.Length, out numWritten) && (UInt32)numWritten == data.Length;
        }

        public static bool WriteMemory(Process process, IntPtr address, Int64 data)
        {
            return WriteMemory(process, address, (UInt64)data);
        }

        public static bool WriteMemory(Process process, IntPtr address, UInt64 data)
        {
            // Copy the bytes from this heap
            byte[] buffer = new byte[8];
            IntPtr numWritten = (IntPtr)1;
            buffer[0] = (byte)(data & 0x000000ff);
            buffer[1] = (byte)((data & 0x0000ff00) >> 8);
            buffer[2] = (byte)((data & 0x00ff0000) >> 16);
            buffer[3] = (byte)((data & 0xff000000) >> 24);
            buffer[4] = (byte)((data & 0x000000ff00000000) >> 32);
            buffer[5] = (byte)((data & 0x0000ff0000000000) >> 40);
            buffer[6] = (byte)((data & 0x00ff000000000000) >> 48);
            buffer[7] = (byte)((data & 0xff00000000000000) >> 56);
            return WriteProcessMemory(process.Handle, (IntPtr)address, buffer, (uint)8, out numWritten) && (UInt32)numWritten == 8;
        }

        public static bool WriteMemory(Process process, IntPtr address, UInt32 data)
        {
            // Copy the bytes from this heap
            byte[] buffer = new byte[4];
            IntPtr numWritten = (IntPtr)1;
            buffer[0] = (byte)(data & 0x000000ff);
            buffer[1] = (byte)((data & 0x0000ff00) >> 8);
            buffer[2] = (byte)((data & 0x00ff0000) >> 16);
            buffer[3] = (byte)((data & 0xff000000) >> 24);
            return WriteProcessMemory(process.Handle, (IntPtr)address, buffer, (uint)4, out numWritten) && (UInt32)numWritten == 4;
        }

        public static bool WriteMemory(Process process, IntPtr address, byte data)
        {
            // Copy the bytes from this heap
            byte[] buffer = new byte[1];
            buffer[0] = data;
            IntPtr numWritten = (IntPtr)0;
            
            bool success = WriteProcessMemory(process.Handle, (IntPtr)address, buffer, (uint)1, out numWritten);

            if( !success )
            {
                int lastError = Marshal.GetLastWin32Error();
                if (lastError == 0x3E6 /*ERROR_NOACCESS*/ )
                {
                    // Add write permissions and try again
                    SetMemoryProtection(process, address, 1, MEMORY_PROTECT.PAGE_EXECUTE_READWRITE);

                    // Try again
                    success = WriteProcessMemory(process.Handle, address, buffer, (uint)1, out numWritten);
                }
            }

            return success && (UInt32)numWritten == 1;
        }


        /// <summary>
        /// Sets the memory protection. ie. read, write, execute
        /// </summary>
        /// <param name="process"></param>
        /// <param name="address"></param>
        /// <param name="length"></param>
        /// <param name="protection">The protection code: </param>
        public static bool SetMemoryProtection(Process process, IntPtr address, uint length, MEMORY_PROTECT protection)
        {
            uint oldProtection = 0;
            bool result = VirtualProtectEx(process.Handle, (IntPtr)address, (UIntPtr)length, (uint)protection, out oldProtection);
            return result;
        }

        public static void clearMemory(Process process, uint address, uint length)
        {
            byte[] blankData = new byte[length];
            WriteMemory(process, (ulong)address, blankData);
        }

        public static void writeString(Process process, UInt64 address, String data)
        {
            char[] bufferChar = data.ToCharArray();
            byte[] buffer = new byte[bufferChar.Length + 1];
            for (int i = 0; i < bufferChar.Length; i++)
                buffer[i] = (byte)bufferChar[i];
            buffer[buffer.Length - 1] = 0;

            IntPtr numWritten = (IntPtr)0;
            WriteProcessMemory(process.Handle, (IntPtr)address, buffer, (uint)4, out numWritten);

            // Check that all the data was read correctly
            if ((UInt32)numWritten != buffer.Length)
                Console.WriteLine("Failed to write string to address " + address.ToString("X") + ". Wrote " + numWritten.ToString() + " of " + buffer.Length.ToString() + ". Attempting to write string of '" + data + "'.");
        }

        /// <summary>
        /// Converts the specified dword into an array of bytes
        /// </summary>
        /// <param name="dword"></param>
        /// <returns></returns>
        public static byte[] ToByteArray(UInt32 dword)
        {
            byte[] result = new byte[4];
            result[0] = (byte)(dword & 0x000000ff);
            result[1] = (byte)((dword & 0x0000ff00) >> 8);
            result[2] = (byte)((dword & 0x00ff0000) >> 16);
            result[3] = (byte)((dword & 0xff000000) >> 24);
            return result;
        }
        public static byte[] ToByteArray(UInt64 dword)
        {
            byte[] result = new byte[8];
            result[0] = (byte)(dword & 0x000000ff);
            result[1] = (byte)((dword & 0x0000ff00) >> 8);
            result[2] = (byte)((dword & 0x00ff0000) >> 16);
            result[3] = (byte)((dword & 0xff000000) >> 24);
            result[4] = (byte)((dword & 0xff00000000) >> 32);
            result[5] = (byte)((dword & 0xff0000000000) >> 40);
            result[6] = (byte)((dword & 0xff000000000000) >> 48);
            result[7] = (byte)((dword & 0xff00000000000000) >> 56);
            return result;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            string hex = BitConverter.ToString(ba);
            return hex.Replace("-", "");
        }

        /// <summary>
        /// Converts takes the first 4 bytes from the array into a uint
        /// </summary>
        /// <param name="dword"></param>
        /// <returns></returns>
        public static uint byteArrayToUint(byte[] data, int index)
        {
            int i = 0;
            uint result = 0;
            while (i < 4 && i + index < data.Length)
            {
                result = result + ((uint)data[i + index] << (i * 8));
                i++;
            }
            return result;
        }
        public static uint byteArrayToUint(List<byte> data, int index)
        {
            int i = 0;
            uint result = 0;
            while (i < 4 && i + index < data.Count)
            {
                result = result + ((uint)data[i + index] << (i * 8));
                i++;
            }
            return result;
        }

        public static ulong byteArrayToUlong(byte[] data, int index)
        {
            int i = 0;
            ulong result = 0;
            while (i < 8 && i + index < data.Length)
            {
                result = result + ((ulong)data[i + index] << (i * 8));
                i++;
            }
            return result;
        }

        /// <summary>
        /// Converts takes the first 2 bytes from the array into a ushort
        /// </summary>
        /// <param name="dword"></param>
        /// <returns></returns>
        public static ushort byteArrayToUshort(byte[] data, int index)
        {
            if (data.Length - index >= 2)
                return (ushort)(data[0 + index] + (data[1 + index] << 8));
            else
                return 0;
        }
        public static ushort byteArrayToUshort(List<byte> data, int index)
        {
            if (data.Count - index >= 2)
                return (ushort)(data[0 + index] + (data[1 + index] << 8));
            else
                return 0;
        }

        /// <summary>
        /// This will return the heap containing the specified address.
        /// </summary>
        /// <param name="process"></param>
        /// <returns></returns>
        public static HEAP_INFO lookupAddressInMap(List<HEAP_INFO> map, uint address)
        {
            // Loop through the heaps
            foreach (HEAP_INFO heap in map)
            {
                // Check if our address falls into this heap
                if (address <= heap.heapAddress + heap.heapLength - 1)
                {
                    return heap;
                }
            }

            // Return an invalid heap
            return new HEAP_INFO(0, 0, "", "", null, 0, 0);
        }


        public static bool isValidReadPointer(List<addressRegion> heaps, Int64 address)
        {
            int index = heaps.BinarySearch(new addressRegion(address, 0));
            if (index < 0)
                index = ~index - 1;
            if (index >= 0 && index < heaps.Count)
            {
                if (heaps[index].address + ((Int64)heaps[index].length) >= address)
                    return true;
            }
            return false;
        }

        public static List<addressRegion> getValidReadHeaps(Process process)
        {
            List<addressRegion> result = new List<addressRegion>(200);

            // Search the process for heaps
            long address = 0;
            long addressLast = long.MaxValue;
            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
            while (address != addressLast)
            {
                // Load this heap information
                long blockSize = (long)VirtualQueryEx(process.Handle, (IntPtr)address, ref mbi, (IntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                addressLast = address;
                address = (long)mbi.BaseAddress + (long)mbi.RegionSize + 1;

                // Check if this has READ privilege and does not have a GUARD
                if ((mbi.Protect & (MEMORY_PROTECT.PAGE_GUARD | MEMORY_PROTECT.PAGE_NOACCESS | MEMORY_PROTECT.PAGE_EXECUTE)) == 0 &&
                    mbi.State == StateEnum.MEM_COMMIT)
                {
                    // This is a valid read heap
                    result.Add(new addressRegion((IntPtr)mbi.BaseAddress, (int)mbi.RegionSize));
                }
            }

            return result;
        }

        public static List<addressRegion> getValidReadHeaps(List<HEAP_INFO> map)
        {
            // Create the table
            List<addressRegion> result = new List<addressRegion>(map.Count);

            for (int i = 0; i < map.Count; i++)
            {
                // Check if this has READ privilege and does not have a GUARD
                if ((map[i].protect & (MEMORY_PROTECT.PAGE_GUARD | MEMORY_PROTECT.PAGE_NOACCESS | MEMORY_PROTECT.PAGE_EXECUTE)) == 0 &&
                    map[i].state == StateEnum.MEM_COMMIT)
                {
                    // This is a valid read heap
                    result.Add(new addressRegion((IntPtr)map[i].heapAddress, (int)map[i].heapLength));
                }
            }

            return result;
        }

        public static bool IsWin64(Process process)
        {
            // Parse the PE header of the target process
            return HeaderReader.IsWin64(process);
            
            
            if ((Environment.OSVersion.Version.Major > 5)
                || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1)))
            {
                IntPtr processHandle;
                bool retVal;

                try
                {
                    processHandle = Process.GetProcessById(process.Id).Handle;
                }
                catch
                {
                    return false; // access is denied to the process
                }
                bool result = IsWow64Process(processHandle, out retVal);
                return result && retVal;
            }

            return false; // not on 64-bit Windows
        }

        /// <summary>
        /// Generates an access lookup table of the process for valid read addresses.
        /// This is used by the code injection to determine if a pointer can be dereferenced.
        /// </summary>
        /// <param name="process"></param>
        /// <returns></returns>
        public static byte[] generateValidReadPointerTableFromMap(List<HEAP_INFO> map)
        {
            // Create the table
            byte[] lookupTable = new byte[0x80000];
            int currentHeapIndex = 0;

            for (uint i = 0; i < 0x80000; i++)
            {
                if (currentHeapIndex < map.Count && i * 0x1000 > map[currentHeapIndex].heapAddress + map[currentHeapIndex].heapLength - 1)
                {
                    // We are now in the next heap
                    currentHeapIndex++;
                }

                if (currentHeapIndex < map.Count)
                {
                    // Check if this has READ privilege and does not have a GUARD
                    lookupTable[i] = (map[currentHeapIndex].heapProtection.ToLower().Contains("read") &&
                                      !map[currentHeapIndex].heapProtection.ToLower().Contains("guard"))
                                         ? (byte)1
                                         : (byte)0;
                }
                else
                    lookupTable[i] = 0;
            }

            return lookupTable;
        }

        /// <summary>
        /// Given a process, this function generates a memory map of the entire process.
        /// </summary>
        /// <param name="process"></param>
        /// <returns></returns>
        public static List<HEAP_INFO> generateMemoryMap(Process process)
        {
            try
            {
                // Initialize the return structure
                List<HEAP_INFO> result = new List<HEAP_INFO>();

                // Search the process for heaps
                long address = 0;
                long addressLast = long.MaxValue;
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                while (address != addressLast)
                {
                    // Load this heap information
                    long blockSize = (long)VirtualQueryEx(process.Handle, (IntPtr)address, ref mbi, (IntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));

                    if (blockSize == 0)
                    {
                        int error = GetLastError();
                        error++;
                    }

                    // Try to associate a module with this memory block
                    ProcessModule associatedModule = null;
                    foreach (ProcessModule module in process.Modules)
                    {
                        if (((ulong)module.BaseAddress >= (ulong)mbi.BaseAddress) && ((ulong)module.BaseAddress < (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize))
                        {
                            associatedModule = module;
                            break;
                        }
                        else if (associatedModule == null && (ulong)module.BaseAddress < (ulong)mbi.BaseAddress)
                        {
                            associatedModule = module;
                        }
                        else if (associatedModule == null)
                        {

                        }
                        else if (((ulong)module.BaseAddress <= (ulong)mbi.BaseAddress) && ((ulong)module.BaseAddress > (ulong)associatedModule.BaseAddress))
                        {
                            associatedModule = module;
                        }
                    }

                    addressLast = address;
                    address = (long)mbi.BaseAddress + (long)mbi.RegionSize + 1;

                    // Decide if this heap is a PE header or not
                    string peHeader = "";
                    if (((mbi.Protect & MEMORY_PROTECT.PAGE_GUARD) == 0) && (mbi.State == StateEnum.MEM_COMMIT))
                    {
                        peHeader = (HeaderReader.isPeHeader(process, (ulong)mbi.BaseAddress, mbi.Protect) ? "PE HEADER" : "");
                    }

                    // Add this heap information
                    result.Add(new HEAP_INFO((ulong)mbi.BaseAddress, (ulong)mbi.RegionSize, mbi.Protect.ToString(), peHeader, associatedModule, mbi.State, mbi.Protect));
                }
                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return new List<HEAP_INFO>();
            }
        }

        /// <summary>
        /// This converts a hex number string to a fixed length, ie 1A0 to 000001A0.
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public static string makeFixedLengthHexString(string hex, int length)
        {
            while (hex.Length < length)
                hex = "0" + hex;
            return hex;
        }

        public static string toHex(byte[] hex)
        {
            // Convert the array into hex readable text
            string result = "";
            for (int index = 0; index < hex.Length; index++)
            {
                if (hex[index].ToString("X").Length == 1)
                    result = result + "0" + hex[index].ToString("X") + " ";
                else
                    result = result + hex[index].ToString("X") + " ";
            }
            result.TrimEnd(new char[] { ' ' });
            return result;
        }

        public static byte[] hexStringToByteArray(string text)
        {
            string tmpText = text.Replace(" ", "").ToLower();
            if ((tmpText.Length % 2) != 0 || tmpText.Length == 0)
                return null;

            // Parse the hex string
            byte[] result = new byte[tmpText.Length / 2];
            for (int i = 0; i < tmpText.Length - 1; i += 2)
            {
                if (!byte.TryParse(tmpText.Substring(i, 2), NumberStyles.HexNumber, null, out result[i / 2]))
                    return null;
            }
            return result;
        }

        public static byte[] textToByteArray_ascii(string text)
        {
            // Parse the hex string
            byte[] result = new byte[text.Length];
            for (int i = 0; i < text.Length; i += 1)
            {
                result[i] = (byte)text[i];
            }
            return result;
        }

        public static byte[] textToByteArray_unicode(string text)
        {
            // Parse the unicode ascii string
            byte[] result = new byte[text.Length * 2];
            for (int i = 0; i < text.Length * 2; i += 1)
            {
                if (i % 2 == 0)
                    result[i] = (byte)text[i / 2];
                else
                    result[i] = 0;
            }
            return result;
        }

        public static bool byteArrayInByByteArray(byte[] largerArray, uint lengthLargerArray, byte[] contains)
        {
            if (largerArray == null || contains == null) return false;
            if (largerArray.Length < lengthLargerArray) lengthLargerArray = (uint)largerArray.Length;

            // Searches the larger array for the byte array
            int n = 0;
            for (int i = 0; i < lengthLargerArray - contains.Length; i++)
            {
                // Check to see if this spot is a match
                n = 0;
                while (largerArray[i + n] == contains[n])
                {
                    if (n++ >= contains.Length - 1)
                        // We found our match
                        return true;
                }
            }
            return false;
        }

        public static string toHex(byte[] hex, uint length)
        {
            if (length > hex.Length) length = (uint)hex.Length;
            // Convert the array into hex readable text
            string result = "";
            for (int index = 0; index < length; index++)
            {
                if (hex[index].ToString("X").Length == 1)
                    result = result + "0" + hex[index].ToString("X") + " ";
                else
                    result = result + hex[index].ToString("X") + " ";
            }
            result.TrimEnd(new char[] { ' ' });
            return result;
        }

        public static string toAscii(byte[] hex)
        {
            // Convert the array into ascii readable text
            string result = "";
            for (int index = 0; index < hex.Length; index++)
            {
                if (hex[index] >= 32)
                    result += new string((char)hex[index], 1);
                else
                    result += "?";
            }
            result.TrimEnd(new char[] { ' ' });
            return result;
        }

        public static string toAscii(byte[] hex, uint length)
        {
            if (length > hex.Length) length = (uint)hex.Length;
            // Convert the array into ascii readable text
            string result = "";
            for (int index = 0; index < length; index++)
            {
                if (hex[index] >= 32)
                    result += new string((char)hex[index], 1);
                else
                    result += "?";
            }
            result.TrimEnd(new char[] { ' ' });
            return result;
        }

        /// <summary>
        /// Creates a remote thread in the process starting at the specified address
        /// </summary>
        /// <param name="process"></param>
        /// <param name="address"></param>
        /// <returns></returns>
        public static IntPtr createThread(Process process, ulong address)
        {
            uint threadIdentifier;
            IntPtr result = CreateRemoteThread(process.Handle, (IntPtr)null, 10000, (IntPtr)address, (IntPtr)null, 0, out threadIdentifier);
            if (result == (IntPtr)null)
                Console.WriteLine("Failed to create remote thread at address 0x" + address.ToString("X"));
            return result;
        }

        public static uint[] ByteArrayToUintArray(ref byte[] data)
        {
            uint[] result = new uint[data.Length / 4];
            for (int i = 0; i < data.Length; i += 4)
            {
                // Copy this element
                result[i / 4] = BitConverter.ToUInt32(data, i);
            }
            return result;
        }

        /// <summary>
        /// Check if all of the values in hex are valid hex characters. Spaces should be removed before calling this function.
        /// </summary>
        /// <param name="hex">Hex characters to check</param>
        /// <returns>True if they are all valid hex characters.</returns>
        public static bool isValidHex(string hex)
        {
            // Must be even number of characters
            if ((hex.Length % 2) != 0)
                return false;

            // Check all the characters
            for (int i = 0; i < hex.Length; i++)
            {
                if (!((hex[i] <= 57 && hex[i] >= 48)
                    || (hex[i] <= 102 && hex[i] >= 97)
                    || (hex[i] <= 70 && hex[i] >= 65)))
                    return false;
            }
            return true;
        }

        // This function from http://www.matthew-long.com/2005/10/18/memory-pinning/
        public static object RawDataToObject(ref byte[] rawData, Type overlayType)
        {
            object result = null;

            GCHandle pinnedRawData = GCHandle.Alloc(rawData,
                GCHandleType.Pinned);
            try
            {

                // Get the address of the data array
                IntPtr pinnedRawDataPtr =
                    pinnedRawData.AddrOfPinnedObject();

                // overlay the data type on top of the raw data
                result = Marshal.PtrToStructure(
                    pinnedRawDataPtr,
                    overlayType);
            }
            finally
            {
                // must explicitly release
                pinnedRawData.Free();
            }

            return result;
        }



        /*public static FUNCTION_INFORMATION[] RawDataToFunctionInformationArray(ref byte[] rawData)
        {
            FUNCTION_INFORMATION[] result = null;

            GCHandle pinnedRawData = GCHandle.Alloc(rawData,
                GCHandleType.Pinned);
            try
            {

                // Get the address of the data array
                IntPtr pinnedRawDataPtr =
                    pinnedRawData.AddrOfPinnedObject();
                unsafe
                {
                    FUNCTION_INFORMATION* resultPtr = (FUNCTION_INFORMATION*)pinnedRawDataPtr;
                    
                    // Create our result array
                    result = new FUNCTION_INFORMATION[rawData.Length / FUNCTION_INFORMATION.SIZE];
                    for (int i = 0; i < result.Length; i++)
                        result[i] = resultPtr[i];
                }
            }
            finally
            {
                // must explicitly release
                pinnedRawData.Free();
            }

            return result;
        }*/

        [DllImport("kernel32")]
        public static extern IntPtr CreateRemoteThread(
          IntPtr hProcess,
          IntPtr lpThreadAttributes,
          uint dwStackSize,
          IntPtr lpStartAddress, // raw Pointer into remote process
          IntPtr lpParameter,
          uint dwCreationFlags,
          out uint lpThreadId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] buffer, int size, out int lpNumberOfBytesRead);

        [DllImport("kernel32", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out IntPtr lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
           UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("Kernel32.dll")]
        static extern void GetSystemInfo(ref SYSTEM_INFO systemInfo);
        // void GetSystemInfo( LPSYSTEM_INFO lpSystemInfo );

        [DllImport("Kernel32.dll")]
        static extern Int32 VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, ref MEMORY_BASIC_INFORMATION buffer, IntPtr dwLength);

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress,
           int dwSize, int dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, Int32 dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern Int32 CloseHandle(IntPtr hObject);

        [DllImport("Advapi32.dll")]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, Int32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public extern static int GetProcAddress(int hwnd, string procedureName);

        [DllImport("kernel32")]
        public extern static int LoadLibrary(string librayName);

        [DllImport("kernel32.dll")]
        public static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetLastError();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle,
            UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
           [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState,
           UInt32 BufferLengthInBytes,
           ref TOKEN_PRIVILEGES PreviousState,
           IntPtr ReturnLengthInBytes);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);

        private static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        private static uint STANDARD_RIGHTS_READ = 0x00020000;
        private static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private static uint TOKEN_DUPLICATE = 0x0002;
        private static uint TOKEN_IMPERSONATE = 0x0004;
        private static uint TOKEN_QUERY = 0x0008;
        private static uint TOKEN_QUERY_SOURCE = 0x0010;
        private static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private static uint TOKEN_ADJUST_GROUPS = 0x0040;
        private static uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private static uint TOKEN_ADJUST_SESSIONID = 0x0100;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin
        }


    }

    public struct HEAP_INFO
    {
        public ulong heapAddress;
        public ulong heapLength;
        public string heapProtection;
        public string extra;
        public ProcessModule associatedModule;
        public StateEnum state;
        public MEMORY_PROTECT protect;

        public HEAP_INFO(ulong heapAddress, ulong heapLength, string heapProtection, string extra, ProcessModule associatedModule, StateEnum state, MEMORY_PROTECT protect)
        {
            this.heapAddress = heapAddress;
            this.heapLength = heapLength;
            this.heapProtection = heapProtection;
            this.extra = extra;
            this.associatedModule = associatedModule;
            this.state = state;
            this.protect = protect;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SYSTEM_INFO
    {
        public Int32 dwOemId;
        public Int32 dwPageSize;
        public UInt32 lpMinimumApplicationAddress;
        public UInt32 lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public Int32 dwNumberOfProcessors;
        public Int32 dwProcessorType;
        public Int32 dwAllocationGranularity;
        public Int16 wProcessorLevel;
        public Int16 wProcessorRevision;
    }

    [Flags]
    public enum MEMORY_STATE
    {
        COMMIT = 0x1000,
        FREE = 0x10000,
        RESERVE = 0x2000
    }

    [Flags]
    public enum MEMORY_TYPE
    {
        IMAGE = 0x1000000,
        MAPPED = 0x40000,
        PRIVATE = 0x20000
    }

    [Flags]
    public enum MEMORY_PROTECT
    {
        PAGE_UNKNOWN = 0x0,
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
        PAGE_EXECUTE_WRITECOPY = 0x80,
        PAGE_NOACCESS = 0x01,
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_WRITECOPY = 0x08,
        PAGE_GUARD = 0x100,
        PAGE_NOCACHE = 0x200,
        PAGE_WRITECOMBINE = 0x400
    }

    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public AllocationProtectEnum AllocationProtect;
        public IntPtr RegionSize;
        public StateEnum State;
        public MEMORY_PROTECT Protect;
        public TypeEnum Type;
    }

    public enum AllocationProtectEnum
    {
        PAGE_EXECUTE = 0x00000010,
        PAGE_EXECUTE_READ = 0x00000020,
        PAGE_EXECUTE_READWRITE = 0x00000040,
        PAGE_EXECUTE_WRITECOPY = 0x00000080,
        PAGE_NOACCESS = 0x00000001,
        PAGE_READONLY = 0x00000002,
        PAGE_READWRITE = 0x00000004,
        PAGE_WRITECOPY = 0x00000008,
        PAGE_GUARD = 0x00000100,
        PAGE_NOCACHE = 0x00000200,
        PAGE_WRITECOMBINE = 0x00000400
    }

    public enum StateEnum
    {
        MEM_COMMIT = 0x1000,
        MEM_FREE = 0x10000,
        MEM_RESERVE = 0x2000
    }

    public enum TypeEnum
    {
        MEM_IMAGE = 0x1000000,
        MEM_MAPPED = 0x40000,
        MEM_PRIVATE = 0x20000
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct LUID
    {
        public Int32 LowPart;
        public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TOKEN_PRIVILEGES
    {
        public Int32 PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public Int32 Attributes;
    }



}
