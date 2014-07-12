using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using IronPython.Hosting;
using IronPython.Runtime;
using Microsoft.Scripting;
using Microsoft.Scripting.Hosting;
using System.IO;
using MeddleFramework;


namespace Meddle
{
  class Meddle
  {
    static void Main(string[] args)
    {
      // Parse the command line arguments
      string config = "";

      for(int i = 0; i < args.Length; i++)
      {
        if (args[i] == "-f")
        {
          // Do something
        }
        else
        {
          // Unassigned variable
          if (config == "")
            config = args[i];
          else
          {
            // Error
            Console.WriteLine("Error: Unable to process unassigned agument '" + args[i] + "'.");
            return;
          }
        }
      }

      // Request debug privelages
      MemoryFunctions.getDebugPrivileges();

      if (config != "" && System.IO.File.Exists(config))
      {
        // Create a process instance using the input config
        Controller controller = new Controller(config);

        if (controller.Initialized)
        {
          // Carry out the security test according to the config
          controller.Begin();
        }
      }
      else
      {
        if( config != "" )
          Console.WriteLine("Error: Invalid config path '" + config + "'.");
        else
          Console.WriteLine("Error: Please specify a config for the attack. Eg 'meddle.exe \"config_notepad_driver.xml\".");
      }

      Console.WriteLine("FINISHED. Press any key to quit.");
      Console.Read();
    }


  }
}
