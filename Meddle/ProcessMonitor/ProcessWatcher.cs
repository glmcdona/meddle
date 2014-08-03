/******************************** Module Header ****************************\
Module Name:  ProcessWatcher.cs
Project:      CSProcessWatcher
Copyright (c) Microsoft Corporation.

using WMI Query Language (WQL) to query process events.

This source is subject to the Microsoft Public License.
See http://www.microsoft.com/opensource/licenses.mspx#Ms-PL.
All other rights reserved.

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/

using System;
using System.Management;

namespace Meddle
{
    public delegate void ProcessEventHandler(WMI.Win32.Process proc);

    public class ProcessWatcher : ManagementEventWatcher
    {
        // Process Events
        public event ProcessEventHandler ProcessCreated;
        public event ProcessEventHandler ProcessDeleted;
        public event ProcessEventHandler ProcessModified;

        // WMI WQL process query string
        static readonly string processEventQuery = @"SELECT * FROM 
             __InstanceOperationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'";
                
        public ProcessWatcher()
        {
            this.Options.BlockSize = 1;
            Init();
        }

        private void Init()
        {
            this.Query.QueryLanguage = "WQL";
            this.Query.QueryString = processEventQuery;
            this.EventArrived += new EventArrivedEventHandler(watcher_EventArrived);
        }

        private void watcher_EventArrived(object sender, EventArrivedEventArgs e)
        {
            string eventType = e.NewEvent.ClassPath.ClassName;
            WMI.Win32.Process proc = new WMI.Win32.Process(e.NewEvent["TargetInstance"] as ManagementBaseObject);

            switch (eventType)
            {
                case "__InstanceCreationEvent":
                    if (ProcessCreated != null)
                    {
                        ProcessCreated(proc);
                    }
                    break;

                case "__InstanceDeletionEvent":
                    if (ProcessDeleted != null)
                    {
                        ProcessDeleted(proc);
                    }
                    break;

                case "__InstanceModificationEvent":
                    if (ProcessModified != null)
                    {
                        ProcessModified(proc);
                    }
                    break;
            }
        }
    }
}
