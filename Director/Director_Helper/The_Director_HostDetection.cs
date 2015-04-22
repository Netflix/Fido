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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using Fido_Main.Director.SysMgmt;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.FidoDB;
using Fido_Main.Fido_Support.Objects.Fido;
using Microsoft.Win32;

namespace Fido_Main.Director.Director_Helper
{
  static class The_Director_HostDetection
  {
    public static FidoReturnValues HostDetection(FidoReturnValues lFidoReturnValues, string sHostname, string sSrcIP)
    {

      Console.WriteLine(@"Attempting host detection for " + sSrcIP + @".");

      //attempt to directly communicate with the device
      //assume Windows first, then Mac second
      lFidoReturnValues.RemoteRegHostname = RemoteRegHost(sSrcIP);
      if (lFidoReturnValues.RemoteRegHostname == null || lFidoReturnValues.RemoteRegHostname == "Not able to connect")
      {
        lFidoReturnValues.SSHHostname = SshHost(sSrcIP);
        if (!String.IsNullOrEmpty(lFidoReturnValues.SSHHostname))
        {
          sHostname = lFidoReturnValues.SSHHostname;
        }
      }
      else
      {
        if (!String.IsNullOrEmpty(lFidoReturnValues.RemoteRegHostname))
        {
          sHostname = lFidoReturnValues.RemoteRegHostname;
          lFidoReturnValues.Hostname = sHostname;
        }
      }

      //if remote registry and ssh fail then NMAP the host
      if ((sHostname == null) && (sHostname == String.Empty))
      {
        Console.WriteLine(@"Cannot detect hostname, attempting to NMAP " + sSrcIP + @".");
        //todo: not currently doing anything wint nmap other
        //assigning it to a variable.
        lFidoReturnValues.NmapHostname = NmapHost(sSrcIP);
      }
      return lFidoReturnValues;
    }

    public static string NmapHost(string sIP)
    {
      try
      {
        var procNmap = new ProcessStartInfo();
        string procResult = null;
        procNmap.FileName = Application.StartupPath + "\\nmap\\nmap.exe";
        procNmap.Arguments = "-O " + sIP;
        procNmap.UseShellExecute = false;
        procNmap.RedirectStandardOutput = true;

        using (var process = Process.Start(procNmap))
        {
          if (process != null)
            using (var reader = process.StandardOutput)
            {
              procResult = reader.ReadToEnd();
              //Console.WriteLine(procResult);
            }
        }

        var filter = new[] { "\n", "\r" };
        string NmapHostname = null;
        string sNmapOs = null;

        if (procResult != null)
        {
          var aryResult = procResult.Split(filter, StringSplitOptions.RemoveEmptyEntries);
          if (aryResult.Count() >= 25)
          {
            NmapHostname = aryResult[1];
            sNmapOs = aryResult[21];
          }
        }
        var sPassReturn = NmapHostname + "^" + sNmapOs;

        return sPassReturn;

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught during NMAP scan:" + e);
      }
      return null;
    }

    public static string RemoteRegHost(string sSrcIP)
    {
      try
      {
        var environmentKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, sSrcIP).OpenSubKey(@"SYSTEM\ControlSet001\Control\ComputerName\ActiveComputerName");
        if (environmentKey != null)
        {
          var sHostname = environmentKey.GetValue("ComputerName").ToString();
          environmentKey.Close();
          return sHostname;
        }
      }
      catch 
      {
        return "Not able to connect";
      }
      return null;
    }

    public static string SshHost(string sSrcIP)
    {
      var pwdDesktop = "";
      var acctDesktop = "";
      var procPlink = new ProcessStartInfo();
      if (File.Exists(Application.StartupPath + "\\plink\\plink.exe"))
      {
        procPlink.FileName = Application.StartupPath + "\\plink\\plink.exe";
        //todo: need to put this in DB and encrypted
        procPlink.Arguments = "-batch -ssh -2 " + acctDesktop + " " + sSrcIP + " -pw " + pwdDesktop;
        procPlink.UseShellExecute = false;
        procPlink.RedirectStandardOutput = true;
        procPlink.RedirectStandardInput = true;
        procPlink.CreateNoWindow = false;
        procPlink.ErrorDialog = false;

        try
        {
          using (var process = Process.Start(procPlink))
          {
            if (process != null)
            {
              var reader = process.StandardOutput;
              var writer = process.StandardInput;
              var procResult = reader.ReadToEnd();
              var i = 0;

              while (!process.HasExited | i >= 6)
              {
                writer.WriteLine("y");
                writer.WriteLine(ConsoleKey.Enter);
                Thread.Sleep(5000);
                writer.WriteLine("n");
                writer.WriteLine(ConsoleKey.Enter);
                writer.Flush();
                writer.WriteLine("hostname");
                procResult = reader.ReadToEnd();
                //process.WaitForExit(10000);
                i++;
              }
              process.Close();
              return procResult;
            }
          }
        }
        catch
        {
          return null;
        }
      }

      return null;
    }

    public static FidoReturnValues SQLFidoReturnValues(FidoReturnValues lFidoReturnValues, string sSrcIP, string sHostname)
    {
      //go to our sysmgmt data sources in the XML to get SQL queries and strings
      var sSQLSource = SQL_Queries.GetSqlSources();
      var sLandeskSrcIP = String.Empty;

      foreach (var source in sSQLSource)
      {
        // ReSharper disable once RedundantAssignment
        var lQuery = new List<string>();
        var lHostInfo = new List<string>();
        string sNewSource = null;
        var sSplitSource = source.Split('-');
        sNewSource = sSplitSource.Length > 1 ? sSplitSource[0] : source;

        switch (sNewSource)
        {
          case "landesk":

            //this is a hack needed to reformat the srcip if Landesk is used
            //because landesk stores IPs in 000.000.000.000 format Where each
            //octet needs 3 numbers.
            if ((sNewSource.ToLower() == "landesk") && (!String.IsNullOrEmpty(sSrcIP)))
            {
              sLandeskSrcIP = SysmgmtLandesk.FormatIP(sSrcIP);
            }


            //if nmap or ssh is null
            if (String.IsNullOrEmpty(sHostname))
            {
              lQuery = SQL_Queries.GetSqlConfigs(source);
              lHostInfo.AddRange(SQL_Queries.RunMSsqlQuery(lQuery, sLandeskSrcIP, null));
            }
            else
            {
              lQuery = SQL_Queries.GetSqlConfigs(source);
              lHostInfo.AddRange(SQL_Queries.RunMSsqlQuery(lQuery, null, sHostname));
            }

            //if return has values assign to lFidoReturnValues
            if (lHostInfo[0] != "unknown")
            {
              lFidoReturnValues.Hostname = lHostInfo[0];
              if (lFidoReturnValues.Landesk == null)
              {
                lFidoReturnValues.Landesk = new LandeskReturnValues();
              }

              //format return from Landesk to Fido object
              lFidoReturnValues = Landesk2FidoValues.LandesklFidoValues(lFidoReturnValues, lHostInfo);

              //query Landesk to get more system information
              lFidoReturnValues = SysmgmtLandesk.GetHostOsInfo(lFidoReturnValues, lQuery[0]);

              //query to get total # of vulns for the machine
              lFidoReturnValues.Landesk.Patches = SysmgmtLandesk.GetVulns(lFidoReturnValues.Hostname, lQuery[0]);

              //query to get if Bit9 was installed\
              if (lFidoReturnValues.Bit9 == null)
              {
                lFidoReturnValues.Bit9 = new Bit9ReturnValues();
              }
              lFidoReturnValues.Bit9.IsBit9 = IsBit9Installed();
              lFidoReturnValues = SysmgmtLandesk.GetBit9Status(lFidoReturnValues, lQuery[0]);
              if (lFidoReturnValues.Landesk.Bit9Running == null)
              {
                lFidoReturnValues.Landesk.Bit9Running = String.Empty;
              }
              if (lFidoReturnValues.Landesk.Bit9Version == null)
              {
                lFidoReturnValues.Landesk.Bit9Version = String.Empty;
              }

            }

            continue;

          case "jamf":

            //if nmap or ssh is null use IP
            if (String.IsNullOrEmpty(sHostname))
            {
              lQuery = SQL_Queries.GetSqlConfigs(source);
              lHostInfo.AddRange(SQL_Queries.RunMysqlQuery(lQuery, sSrcIP, null));
            }
            //if hostname is not null use IP instead
            else
            {
              lQuery = SQL_Queries.GetSqlConfigs(source);
              lHostInfo.AddRange(SQL_Queries.RunMysqlQuery(lQuery, null, sHostname));
            }

            //if return has values assign to lFidoReturnValues
            if (lHostInfo[0] != "unknown")
            {
              if ((lFidoReturnValues.Landesk != null) && !String.IsNullOrEmpty(lFidoReturnValues.Landesk.Hostname))
              {
                var LandeskDateTime = Convert.ToDateTime(lFidoReturnValues.Landesk.LastUpdate);
                var JamfDateTime = FromEpochTime(lHostInfo[3]);

                if (LandeskDateTime.ToUniversalTime() > JamfDateTime)
                {
                  continue;
                }
              }
              lFidoReturnValues.Hostname = lHostInfo[1];
              lFidoReturnValues.Username = lHostInfo[11];
              if (lFidoReturnValues.Jamf == null)
              {
                lFidoReturnValues.Jamf = new JamfReturnValues();
              }

              lFidoReturnValues.Jamf = Jamf2FidoValues.Convert(lFidoReturnValues, lHostInfo);
            }

            continue;

          default:
            continue;
        }
      }
      return lFidoReturnValues;
    }

    private static DateTime? FromEpochTime(string unixTime)
    {
      return new DateTime(1970, 1, 1, 0, 0, 0).AddMilliseconds(Convert.ToDouble(unixTime));
    }

    //simple check to see if Bit9 is configured in Fido
    public static bool IsBit9Installed()
    {
      var sDetectors = Object_Fido_Configs.GetAsString("fido.application.detectors", null).Split(',');
      return sDetectors.Any(detector => detector.ToLower() == "bit9");
    }

    public static FidoReturnValues GetUserInfo(FidoReturnValues lFidoReturnValues)
    {
      var acctDesktop = "";
      if (!String.IsNullOrEmpty(lFidoReturnValues.Hostname) || !string.IsNullOrEmpty(lFidoReturnValues.Username))
      {
        lFidoReturnValues.IsHostKnown = true;

        Console.WriteLine(@"Attempting to retrieve detailed user information.");

        //query Active Directory to get detailed user/manager information
        var username = String.Empty;
        if (!String.IsNullOrEmpty(lFidoReturnValues.Username))
        {
          var usernameAry = lFidoReturnValues.Username.Split('\\');
          if (usernameAry.Count() > 1)
          {
            if ((usernameAry[1].ToLower() != acctDesktop))
            {
              username = lFidoReturnValues.Username.Contains("\\") ? usernameAry[1] : lFidoReturnValues.Username;
            }
          }
          else if (usernameAry.Count() == 1)
          {
            username = usernameAry[0];
          }
          var lUserReturn = SysMgmt_ActiveDirectory.Getuserinfo(username);
          if (!String.IsNullOrEmpty(username))
          {
            if (lFidoReturnValues.UserInfo == null)
            {
              lFidoReturnValues.UserInfo = new UserReturnValues();
            }
            lFidoReturnValues.UserInfo = lUserReturn;
          }
        }
        else
        {
          Console.WriteLine(@"Unable to get detailed user information.");
          lFidoReturnValues.Username = "Unknown username";
        }

        //format OS for Notification
        Console.WriteLine(@"Formatting OS information.");
        if ((lFidoReturnValues.Landesk != null) && (lFidoReturnValues.Landesk.OSName != null))
        {
          lFidoReturnValues.MachineType = NormalizeOSName(lFidoReturnValues.Landesk);
        }
        else if ((lFidoReturnValues.Jamf != null) && (lFidoReturnValues.Jamf.OSName != null))
        {
          lFidoReturnValues.MachineType = lFidoReturnValues.Jamf.OSName;
        }

      }
      return lFidoReturnValues;
    }

    private static string NormalizeOSName(LandeskReturnValues lLandeskReturnValues)
    {
      string machineType;
      if (lLandeskReturnValues.OSName.Contains("server"))
      {
        if ((!String.IsNullOrEmpty(lLandeskReturnValues.ChassisType)) && (lLandeskReturnValues.ChassisType != "unknown"))
        {
          machineType = "Windows Server " + lLandeskReturnValues.ChassisType;
        }
        else
        {
          machineType = "Windows Server";
        }
      }
      else
      {
        if ((!String.IsNullOrEmpty(lLandeskReturnValues.ChassisType)) && (lLandeskReturnValues.ChassisType != "unknown"))
        {
          machineType = "Windows " + lLandeskReturnValues.ChassisType;
        }
        else if (lLandeskReturnValues.Battery.ToLower() == "yes")
        {
          machineType = "Windows Laptop/Tablet";
        }
        else
        {
          machineType = "Windows Unknown";
        }
      }
      return machineType;
    }
  }

  class Compare
  {
    public FidoReturnValues FidoHostNames(FidoReturnValues lFidoInputHostnames)
    {
      //code to look at all returned hostname values
      //if remotereg/ssh come back with value then
      //they win... make sure they are equal to 
      //sysmgmt return and if not get new return from
      //sysmgmt server. if remotereg/ssh come back as 
      //empty, then sysmgmt wins.
      var lFidoParseHostnames = lFidoInputHostnames;

      try
      {

        return lFidoParseHostnames;
      }
      catch(Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught doing FidoHostNames:" + e);
      }
      return null;
    }
  }
}
