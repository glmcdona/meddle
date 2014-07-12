using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Xml.Linq;
using IronPython.Runtime;

namespace Meddle
{
    public class Target
    {
        private PythonBoss _pyBoss;
        private List<Breakpoint> _breakpoints;
        private Process _process;
        public dynamic PyTarget = null;
        private string _name;
        private object _targetClass;

        public Target(object targetClass, PythonBoss pyBoss, Process process)
        {
            _targetClass = targetClass;
            _process = process;
            _pyBoss = pyBoss;
            _breakpoints = new List<Breakpoint>(1);
            _name = Target.GetName(targetClass);
        }

        public bool Initialize()
        {
            // Create an instance of the class 'Target' __init__(self, Engine)
            try
            {
                this.PyTarget = _pyBoss.PyEngine.Operations.CreateInstance(_targetClass, _process, _process.PyProcess);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(string.Format("ERROR: Constructor of python class 'Target' {0} failed:", _name));
                Console.WriteLine(e.ToString());
            }
            return false;
        }

        public void ProcessBreakpointEvent(Breakpoint breakpoint, IntPtr hThread, ref Context context, string eventName)
        {
            // Ask the process manager handle the breakpoint event
            _process.HandleBreakpointEvent(this, breakpoint, hThread, context, eventName);
            
        }

        public void Invoke(string name, object args)
        {
            if (_pyBoss.PyEngine.Operations.ContainsMember(this.PyTarget, name))
            {
                _pyBoss.PyEngine.Operations.InvokeMember(this.PyTarget, name, new object[] { args });
            }
        }

        public string GetName()
        {
            return _name;
        }

        public static string GetName(object pythonTarget)
        {
            //IronPython.Runtime.Types.OldClass a;
            return pythonTarget.ToString();
        }

        public void HandleModuleLoaded(Microsoft.Samples.Debugging.Native.LoadDllNativeEvent loadDllNativeEvent)
        {
            // Call the process module_loaded() event
            try
            {
                this.PyTarget.module_loaded(loadDllNativeEvent.Module.Name, (Int64) loadDllNativeEvent.Module.BaseAddress);
            }
            catch (Exception e)
            {
                _pyBoss.PrintError(e, string.Format("'Target' handler for instance '{0}' failed during attempt to call 'module_loaded()':", _name));
            }
        }
    }
}
