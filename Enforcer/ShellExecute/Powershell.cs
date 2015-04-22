/*
 *
 *  Copyright 2015 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */

using System;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using Fido_Main.Fido_Support.ErrorHandling;

namespace Fido_Main.Enforcer.ShellExecute
{
  class Powershell
  {
    //function to run Powershell commands
    public static void RunPowerShell(string psScript, string psParameters)
    {

      try
      {
        var runspaceConfiguration = RunspaceConfiguration.Create();
        var runspace = RunspaceFactory.CreateRunspace(runspaceConfiguration);
        runspace.Open();
        var pipeline = runspace.CreatePipeline();
        var myCommand = new Command(psScript);
        pipeline.Commands.Add(myCommand);
        if (!string.IsNullOrEmpty(psParameters))
        {
          var aryParameters = psParameters.Split(' ');
          for (var i = 0; i < aryParameters.Count(); i++)
          {
            myCommand.Parameters.Add(aryParameters[i].ToString(CultureInfo.InvariantCulture), aryParameters[i + 1].ToString(CultureInfo.InvariantCulture));
            i++;
          }
        }

        var scriptInvoker = new RunspaceInvoke(runspace);

        // Execute PowerShell script
        Collection<PSObject> results = pipeline.Invoke();
        runspace.Close();
        return;

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught running powershell:" + e);
      }
    }

  }
}
