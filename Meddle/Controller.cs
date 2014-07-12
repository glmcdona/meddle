using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IronPython.Runtime;
using System.Windows.Threading;
using System.Threading;

namespace Meddle
{
    public class Controller
    {
        private readonly PythonBoss _pyBoss;
        private string _scriptPath = "";
        public dynamic PyController = null;

        public bool Initialized = false;
        private bool _running = true;

        private HashSet<int> _lastProcesses = null;
        private Thread _dispatchLoadedProcesses = null;

        public bool Begin()
        {
            return false;
        }

        public void NewProcessMonitor()
        {
            while (this._running)
            {
                System.Diagnostics.Process[] processes = System.Diagnostics.Process.GetProcesses();

                if (_lastProcesses == null)
                {

                    _lastProcesses = new HashSet<int>();
                    foreach (System.Diagnostics.Process process in processes)
                        _lastProcesses.Add(process.Id);
                }

                // Check for differences
                foreach (System.Diagnostics.Process process in processes)
                {
                    if (!_lastProcesses.Contains(process.Id))
                    {
                        // New process
                        IntPtr handle = IntPtr.Zero;
                        try
                        {
                            handle = process.Handle;
                        }
                        catch
                        {

                        }
                        PyController.system_new_process(process.ProcessName, process.Id, handle);
                    }
                }

                _lastProcesses = new HashSet<int>();
                foreach (System.Diagnostics.Process process in processes)
                    _lastProcesses.Add(process.Id);

                System.Threading.Thread.Sleep(10);
            }
        }


        public Controller(string startScript, string scriptPath)
        {
            _scriptPath = scriptPath;

            // Now that we slightly verified the xml structure, lets initialize
            _pyBoss = new PythonBoss(scriptPath);

            if (!_pyBoss.AddCode("from " + startScript.Replace(".py", "") + " import *", startScript))
                return;

            try
            {
                // Create the controller
                var pyTypeController = _pyBoss.PyScope.GetVariable("Controller");
                PyController = _pyBoss.PyEngine.Operations.CreateInstance(pyTypeController, this);

                // Create the new process dispatcher check loop
                _dispatchLoadedProcesses = new Thread(NewProcessMonitor);
                _dispatchLoadedProcesses.Start();

                // Execute the controller main function
                try
                {
                    PyController.main();
                }
                catch (Exception e)
                {
                    Console.WriteLine("ERROR: Python class controller.main() not found or failed while executing.");
                    Console.WriteLine(e.ToString());
                    return;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR: Python class controller(...) not found or failed while executing constructor.");
                Console.WriteLine(e.ToString());
                return;
            }


            // Success, this controller is now loaded
            Initialized = true;
        }

        public bool AttachProcess(dynamic pyProcess)
        {
            try
            {
                // Add this process
                Process newProcess = new Process(_pyBoss, this, pyProcess);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR: An unknown error occured while processing Controller.AddProcess(). Plase check that the argument inputs were correct.");
                Console.WriteLine(e);
            }
            return false;
        }
    }


}
