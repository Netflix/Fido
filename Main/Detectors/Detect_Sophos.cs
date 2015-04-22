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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using Fido_Main.Director;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Properties;
using Microsoft.Win32;

namespace Fido_Main.Main.Detectors
{
  static class Sophos
  {
    //this function will attemp to pick up reading logs from the last entry
    //in the previous FIDO process iteration. First it will make a temp copy
    //of the log.
    public static void ReadLogs(string sSophosDefaultServer, string sSophosDefaultFile)
    {
      //todo: move pull of last event out of registry and to DB.
      var lSophosReturn = new List<string>();
      var sSophosDefaultLog = sSophosDefaultServer + sSophosDefaultFile;
      using (var registryKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Fido\Configs\Antivirus", true))
      {
        if (registryKey == null) return;
        var sSophosLastEvent = (string)registryKey.GetValue("lastevent");
        try
        {
          if (File.Exists(Application.StartupPath + @"\\temp\\" + sSophosDefaultFile + @".001"))
          {
            File.Delete(Application.StartupPath + @"\\temp\\" + sSophosDefaultFile + @".001");
          }

          if (string.IsNullOrEmpty(sSophosDefaultLog) && (File.Exists((@sSophosDefaultLog))))
          {
            File.Copy(@sSophosDefaultLog, Application.StartupPath + @"\\temp\\" + sSophosDefaultFile + @".001", true);
            lSophosReturn.AddRange(File.ReadAllLines(Application.StartupPath + @"\\temp\\" + sSophosDefaultFile + @".001"));
          }

          if (lSophosReturn.Count > 0)
          {
            lSophosReturn.Reverse();

            for (var i = 0; i < lSophosReturn.Count; i++)
            {
              var sSophosEntry = lSophosReturn[i].Split(';');
              if ((sSophosEntry.Length > 0) && (sSophosLastEvent.Trim() == sSophosEntry[1].Trim()) && (i > 0))
              {
                lSophosReturn.Reverse();
                lSophosReturn.RemoveRange(0, lSophosReturn.Count - i);
                ParseLogs(lSophosReturn);
              }
            }
          }
          var sNewLastEvent = lSophosReturn[0].Split(';');
          registryKey.SetValue("lastevent", sNewLastEvent[1]);
          registryKey.Close();
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Sophos readlogs area:" + e);
        }
      }
    }

    //This function will attempt to go through the log looking for computers which
    //the local client could not clean malicous malware.
    static void ParseLogs([NotNull] IEnumerable<string> sSophosAlerts)
    {
      if (sSophosAlerts == null) throw new ArgumentNullException("sSophosAlerts");
      var lSophosReturns = new List<string>();
      try
      {
        //loop through new entries from log
        foreach (var sSophosValues in from t in sSophosAlerts let sFilter = new[] { "INFO:", ";", "InsertedAt=", "EventTime=", "ActionTaken=", "UserName=", "Status=", "ThreatType=", "ThreatName=", "FullFilePath=", "ComputerName=", "ComputerIPAddress=" } select t.Split(sFilter, StringSplitOptions.RemoveEmptyEntries) into sSophosValues where (sSophosValues[18].Trim() == "Viruses/spyware") && ((sSophosValues[8].Trim() == "Partially Cleaned") || (sSophosValues[8].Trim() == "None")) && (sSophosValues[12].Trim() != "ScannerType=Web browser") && (sSophosValues[20].Trim() != "Shh/Updater-B") select sSophosValues)
        {
          //assign values to list
          for (var x = 0; x < sSophosValues.Length; x++)
          {
            switch (x)
            {
              case 2:
                lSophosReturns.Add(sSophosValues[2].Trim());
                break;
              case 5:
                lSophosReturns.Add(sSophosValues[5].Trim());
                break;
              case 8:
                lSophosReturns.Add(sSophosValues[8].Trim());
                break;
              case 10:
                lSophosReturns.Add(sSophosValues[10].Trim());
                break;
              case 15:
                lSophosReturns.Add(sSophosValues[15].Trim());
                break;
              case 18:
                lSophosReturns.Add(sSophosValues[18].Trim());
                break;
              case 20:
                lSophosReturns.Add(sSophosValues[20].Trim());
                break;
              case 22:
                lSophosReturns.Add(sSophosValues[22].Trim());
                break;
              case 24:
                lSophosReturns.Add(sSophosValues[24].Trim());
                break;
              case 27:
                lSophosReturns.Add(sSophosValues[27].Trim());
                break;
            }
          }
              
          //convert list to fidoreturnvalues
          var lFidoReturnValues = Sophos2FidoValues.SophoslFidoValues(lSophosReturns);
          lFidoReturnValues.CurrentDetector = "antivirus";
          TheDirector.Direct(lFidoReturnValues);
          lSophosReturns.Clear();
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Sophos parselogs area:" + e);
      }
    }
  }

  static class Sophos2FidoValues
  {
    //This function will attempt to assign alerts to the AntivirusReturnValues object
    //before returning it to the FidoReturnValues object.
    public static FidoReturnValues SophoslFidoValues(List<string> lHostInfo)
    {
      var lFidoReturnValues = new FidoReturnValues();
      var lSophosReturnValues = new AntivirusReturnValues();
      for (var x = 0; x < lHostInfo.Count; x++)
      {
        switch (x)
        {
          case 0:
            lSophosReturnValues.ReceivedTime = lHostInfo[0];
            break;
          case 1:
            lSophosReturnValues.EventTime = lHostInfo[1];
            lFidoReturnValues.TimeOccurred = lHostInfo[1];
            break;
          case 2:
            lSophosReturnValues.ActionTaken = lHostInfo[2];
            break;
          case 3:
            lSophosReturnValues.Username = lHostInfo[3];
            var sNewUserName = lHostInfo[3].Split('\\');
            if (sNewUserName.Length == 1)
            {
              lFidoReturnValues.Username = sNewUserName[0];
            }
            else if (sNewUserName.Length > 1)
            {
              lFidoReturnValues.Username = sNewUserName[1];
            }
            else
            {
              lFidoReturnValues.Username = string.Empty;
            }
            break;
          case 4:
            lSophosReturnValues.Status = lHostInfo[4];
            break;
          case 5:
            lSophosReturnValues.ThreatType = lHostInfo[5];
            break;
          case 6:
            lSophosReturnValues.ThreatName = lHostInfo[6];
            lFidoReturnValues.MalwareType = lHostInfo[6];
            break;
          case 7:
            lSophosReturnValues.FilePath = lHostInfo[7];
            break;
          case 8:
            lSophosReturnValues.HostName = lHostInfo[8];
            lFidoReturnValues.Hostname = lHostInfo[8];
            break;
          case 9:
            lFidoReturnValues.SrcIP = lHostInfo[9];
            break;
        }
      }

      lFidoReturnValues.Antivirus = lSophosReturnValues;

      return lFidoReturnValues;

    }

  }

}
