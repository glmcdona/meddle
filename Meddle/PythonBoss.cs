using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using IronPython;
using IronPython.Hosting;
using IronPython.Runtime;
using IronPython.Runtime.Exceptions;
using Microsoft.CSharp.RuntimeBinder;
using Microsoft.Scripting;
using Microsoft.Scripting.Hosting;
using Microsoft.CSharp;
using System.IO;


namespace Meddle
{
  public class PythonBoss
  {
    private string _code;
    
    public ScriptEngine PyEngine = null;
    private ScriptRuntime _pyRuntime = null;
    public ScriptScope PyScope = null;
    public dynamic PyScopeDyn = null;
    private SimpleLogger _logger = new SimpleLogger();

    public PythonBoss(string scriptPath)
    {
      // Create the engine and scope
      _pyRuntime = Python.CreateRuntime();
      PyEngine = Python.CreateEngine();
      PyScope = PyEngine.CreateScope();
      PyScopeDyn = PyScope;
      PyScope.SetVariable("log", _logger);

      // Set the paths used by the engine
      string dir = Path.GetDirectoryName(scriptPath);
      ICollection<string> paths = PyEngine.GetSearchPaths();
      if (String.IsNullOrEmpty(dir))
        dir = Environment.CurrentDirectory;
      paths.Add("C:\\Program Files (x86)\\IronPython 2.7\\Lib");
      paths.Add(dir);
      PyEngine.SetSearchPaths(paths);

      _logger.AddInfo("Python Initialized");
    }
    

    /// <summary>
    /// Executes the added code and adds it to the full code buffer
    /// </summary>
    /// <param name="code"></param>
    public bool AddCode(string code, string location)
    {
      _code += code;

      // Execute the new code
      try
      {
        PyEngine.Execute(_code, PyScope);
      }
      catch (SyntaxErrorException e)
      {

        File.WriteAllText("python_error.py", code);
        Console.WriteLine(
          "PYTHON ERROR: A synatax error occured while processing a script. The script has been saved to 'python_error.py' for analysis.\nError Reason: " +
          e.Message.ToString() +
          "\nLine Number: " + e.Line + "\nLine: " + e.GetCodeLine() + "\nLocation: " + location + "\n");

        return false;
      }
      catch (ImportException e)
      {
        Console.WriteLine("PYTHON ERROR: A module import error occured when processing a script. \nError Reason: " +
                          e.Message.ToString() + "\nLocation: " + location + "\n");

        return false;
      }
      catch (Exception e)
      {
        File.WriteAllText("python_error.py", code);
        Console.WriteLine(
          "PYTHON ERROR: An unknown error occured while processing a script. The script has been saved to 'python_error.py' for analysis.\n" +
          "\nLocation: " + location + "\n\nError Reason: " + e.Message.ToString() + "\n");

        return false;
      }

      return true;
    }

    public void PrintError(Exception e, string location)
    {
      if (e is SyntaxErrorException)
      {
        Console.WriteLine(
          "PYTHON ERROR: A synatax error occured while processing a script. The script has been saved to 'python_error.py' for analysis.\nError Reason: " +
          e.Message.ToString() +
          "\nLine Number: " + ((SyntaxErrorException)e).Line + "\nLine: " + ((SyntaxErrorException)e).GetCodeLine() + "\nLocation: " + location + "\n");
      }
      else if (e is ImportException)
      {
        Console.WriteLine("PYTHON ERROR: A module import error occured when processing a script. \nError Reason: " +
                          ((ImportException)e).Message.ToString() + "\nLocation: " + location + "\n");
      }
      else if (e is ArgumentTypeException)
      {
        Console.WriteLine("PYTHON ERROR: An argument type error occured when processing a script. \nError Reason: " +
                          ((ArgumentTypeException)e).Message.ToString() + "\nLocation: " + location + "\n");
      }
      else
      {
        Console.WriteLine(
          "PYTHON ERROR: An unknown error occured while processing a script. The script has been saved to 'python_error.py' for analysis.\n" +
          "\nLocation: " + location + "\n\nError Reason: " + e.Message.ToString() + "\n");
      }
    }
  }

  internal class SimpleLogger
  {
    private Mutex _mutex = new Mutex(false);
    private UInt32 _entryCount = 0;
    public class Entry
    {
      public enum EntryType
      {
        Info,
        Warning,
        Error,
        Fault
      }

      private EntryType _entryType;
      private DateTime _timestamp;
      private String _msg;
      private UInt32 _index;

      private Entry()
      {
      }

      public Entry(EntryType entryType, String msg, UInt32 index)
      {
        _msg = msg;
        _timestamp = DateTime.Now;
        _entryType = entryType;
        _index = index;
      }

      public String msg { get { return _msg; } }
      public DateTime timestamp { get { return _timestamp; } }
      public EntryType entryType { get { return _entryType; } }
      public UInt32 index { get { return _index; } }

      public override string ToString()
      {
        return String.Format("[{0}][{1}][{2}][{3}]", _timestamp, _index, _entryType, _msg);
      }
    }

    private List<Entry> _entries = new List<Entry>();

    public void Reset()
    {
      try
      {
        _mutex.WaitOne();
        _entries = new List<Entry>();
      }
      finally
      {
        _mutex.ReleaseMutex();
      }
    }

    public Int32 Count
    {
      get
      {
        _mutex.WaitOne();
        Int32 result = _entries.Count; _mutex.ReleaseMutex(); return result;
      }
    }

    /// <summary>
    /// Gets the first entry in log and removes it from the log.
    /// Returns null if the log is empty.
    /// </summary>
    /// <returns></returns>
    public Entry GetFirst()
    {
      Entry result = null;
      try
      {
        _mutex.WaitOne();
        if (_entries.Count > 0)
        {
          result = _entries[0];
          _entries.RemoveAt(0);
        }

      }
      finally
      {
        _mutex.ReleaseMutex();
      }
      return result;
    }

    /// <summary>
    /// Retrives all the entries from the log.  The log will be 
    /// empty after the operation has been executed.
    /// </summary>
    /// <returns></returns>
    public List<Entry> GetAll()
    {
      List<Entry> result = null;
      try
      {
        _mutex.WaitOne();
        result = _entries;
        _entries = new List<Entry>();
      }
      finally
      {
        _mutex.ReleaseMutex();
      }
      return result;
    }

    public void AddInfo(String msg)
    {
      try
      {
        _mutex.WaitOne();
        _entries.Add(new Entry(Entry.EntryType.Info, msg, _entryCount++));
      }
      finally
      {
        _mutex.ReleaseMutex();
      }
    }

    public void AddWarning(String msg)
    {
      try
      {
        _mutex.WaitOne();
        _entries.Add(new Entry(Entry.EntryType.Warning, msg, _entryCount++));
      }
      finally
      {
        _mutex.ReleaseMutex();
      }
    }

    public void AddError(String msg)
    {
      try
      {
        _mutex.WaitOne();
        _entries.Add(new Entry(Entry.EntryType.Error, msg, _entryCount++));
      }
      finally
      {
        _mutex.ReleaseMutex();
      }
    }

    public void AddFault(String msg)
    {
      try
      {
        _mutex.WaitOne();
        _entries.Add(new Entry(Entry.EntryType.Fault, msg, _entryCount++));
      }
      finally
      {
        _mutex.ReleaseMutex();
      }
    }

    public void AddFault(Exception ex)
    {

      try
      {
        _mutex.WaitOne();
        String msg = ex.Message;
        if (ex.InnerException != null)
          msg += " (+INNER): " + ex.InnerException.Message;
        _entries.Add(new Entry(Entry.EntryType.Fault, msg, _entryCount++));
      }
      finally
      {
        _mutex.ReleaseMutex();
      }
    }
  }
}
