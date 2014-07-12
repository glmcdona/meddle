using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IronPython.Runtime;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

namespace Meddle
{
    public class CaptureLog
    {
        private Stream _stream;
        private BinaryWriter _bwriter;
        private Object _thisLock = new Object();

        public CaptureLog(string filename)
        {
            _stream = File.OpenWrite(filename);
            _bwriter = new BinaryWriter(_stream);
        }

        ~CaptureLog()
        {
            lock (_thisLock)
            {
                _stream.Close();
            }
        }

        public void Log(string eventName, Dictionary<string, object> fields, byte[] buffer)
        {
            // Create the new log entry
            LogEntry newEntry = new LogEntry(eventName, fields, buffer);

            lock (_thisLock)
            {
                // Serialize the new log entry to binary
                newEntry.Serialize(_bwriter);

                // Flush it to disk, since we may crash.
                _stream.FlushAsync();
            }
        }


    }

    public class LogEntry   
    {
        public string EventName { get; set; }
        public Dictionary<string,object> Fields { get; set; }
        public byte[] Buffer { get; set; }

        public LogEntry(string eventName, Dictionary<string, object> fields, byte[] buffer)
        {
            EventName = eventName;
            Buffer = buffer;
            Fields = fields;
        }

        //Deserialization constructor.
        public LogEntry(BinaryReader breader)
        {
            try
            {
                EventName = (string)breader.ReadString();

                int numFields = breader.ReadInt32();
                Fields = new Dictionary<string, object>(numFields);
                for (int i = 0; i < numFields; i++)
                {
                    // Read this entry
                    Fields.Add(breader.ReadString(), breader.ReadString());
                }

                int bufferSize = breader.ReadInt32();
                Buffer = breader.ReadBytes(bufferSize);
            }
            catch (Exception e)
            {
                throw new Exception("An unknown error occurred while deserializing capture file.");
            }
        }
        
        //Serialization function.
        public void Serialize(BinaryWriter bwriter)
        {
            // Write the event name
            bwriter.Write(EventName);

            // Write the fields
            bwriter.Write((Int32)Fields.Count);
            foreach (var kvp in Fields)
            {
                bwriter.Write(kvp.Key);
                bwriter.Write(kvp.Value.ToString());
            }

            // Write the buffer
            bwriter.Write((Int32)Buffer.Length);
            bwriter.Write(Buffer);
        }
    }
}
