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
using System.Data.SqlClient;
using System.Globalization;
using System.Linq;
using System.Threading;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Director.SysMgmt
{
  class SysmgmtLandesk
  {
    public static FidoReturnValues GetBit9Status(FidoReturnValues lFidoReturnValues, string sConnectionString)
    {
      //todo: move this to the DB
      var sQuery = "SELECT DISTINCT A0.DISPLAYNAME, A1.NAME, A1.STATUS, A2.SUITENAME, A2.VERSION FROM Computer A0 (nolock) LEFT OUTER JOIN Services A1 (nolock) ON A0.Computer_Idn = A1.Computer_Idn LEFT OUTER JOIN AppSoftwareSuites A2 (nolock) ON A0.Computer_Idn = A2.Computer_Idn  WHERE (A1.NAME = N'Parity Agent' AND A2.SuiteName LIKE N'Parity Agent' AND A0.DEVICENAME = N'" + lFidoReturnValues.Hostname + "')";
      var lBit9Return = new List<string>();

      var sqlConnect = new SqlConnection(sConnectionString);
      sqlConnect.Open();

      try
      {
        var sqlCmd = new SqlCommand(sQuery, sqlConnect);
        var sqlReader = sqlCmd.ExecuteReader();

        Thread.Sleep(500);

        while (sqlReader.Read())
        {
          for (var i = 0; i < sqlReader.FieldCount; i++)
          {
            lBit9Return.Add(sqlReader.GetString(i) != string.Empty ? sqlReader.GetString(i) : string.Empty);
          }
        }
        sqlReader.Close();
      }
      catch(Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in getting Bit9 status from Landesk:" + e);
      }

      if (lBit9Return.Count > 0)
      {
        lFidoReturnValues.Landesk.Bit9Running = lBit9Return[2].ToString(CultureInfo.InvariantCulture);
        lFidoReturnValues.Landesk.Bit9Version = lBit9Return[4].ToString(CultureInfo.InvariantCulture);
        return lFidoReturnValues;
      }
      lFidoReturnValues.Landesk.Bit9Running = string.Empty;
      lFidoReturnValues.Landesk.Bit9Version = "Not Installed";
      return lFidoReturnValues;
    }

    public static List<Int32> GetVulns(string sHostname, string sConnectionString)
    {
      var lVuln = new List<Int32>();
      var sQueries = new List<string>();
      //todo: move this to the DB as const values.
      var sFinalQuery = "SELECT count(DISTINCT A1.Title) FROM Computer A0 (nolock) LEFT OUTER JOIN CVDetectedV A1 (nolock) ON A0.Computer_Idn = A1.Computer_Idn  WHERE (A0.DEVICENAME = N'" + sHostname + "' AND (A1.VULSEVERITY = N'Critical' OR A1.VULSEVERITY = N'High' OR A1.VULSEVERITY = N'Low' OR A1.VULSEVERITY = N'Medium') AND A1.VULTYPE = N'Vulnerability')";
      var sCriticalQuery = "SELECT count(DISTINCT A1.Title) FROM Computer A0 (nolock) LEFT OUTER JOIN CVDetectedV A1 (nolock) ON A0.Computer_Idn = A1.Computer_Idn  WHERE (A0.DEVICENAME = N'" + sHostname + "' AND A1.VULSEVERITY = N'Critical' AND A1.VULTYPE = N'Vulnerability')";
      var sHighQuery = "SELECT count(DISTINCT A1.Title) FROM Computer A0 (nolock) LEFT OUTER JOIN CVDetectedV A1 (nolock) ON A0.Computer_Idn = A1.Computer_Idn  WHERE (A0.DEVICENAME = N'" + sHostname + "' AND A1.VULSEVERITY = N'High' AND A1.VULTYPE = N'Vulnerability')";
      var sLowQuery = "SELECT count(DISTINCT A1.Title) FROM Computer A0 (nolock) LEFT OUTER JOIN CVDetectedV A1 (nolock) ON A0.Computer_Idn = A1.Computer_Idn  WHERE (A0.DEVICENAME = N'" + sHostname + "' AND (A1.VULSEVERITY = N'Low' OR A1.VULSEVERITY = N'Medium') AND A1.VULTYPE = N'Vulnerability')";
      
      sQueries.Add(sFinalQuery);
      sQueries.Add(sCriticalQuery);
      sQueries.Add(sHighQuery);
      sQueries.Add(sLowQuery);
      var sqlConnect = new SqlConnection(sConnectionString);
      sqlConnect.Open();

      try
      {
        foreach (var sqlReader in sQueries.Select(tmpQuery => new SqlCommand(tmpQuery, sqlConnect)).Select(sqlCmd => sqlCmd.ExecuteReader()))
        {
          Thread.Sleep(500);

          while (sqlReader.Read())
          {
            lVuln.Add(sqlReader.GetInt32(0) > 0 ? sqlReader.GetInt32(0) : 0);
          }
          sqlReader.Close();
        }
        sqlConnect.Close();
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in getting vulns from Landesk:" + e);
      }
      return lVuln;
    }

    public static FidoReturnValues GetHostOsInfo(FidoReturnValues lFidoReturnValues, string sConnectionString)
    {
      var lLandeskReturnValues = lFidoReturnValues.Landesk;
      var lHostInfoReturn = new List<string>();
      //todo: move this to the DB as a const value.
      var sQuery = "SELECT DISTINCT A1.OSTYPE, A0.TYPE, A2.HASBATTERY, A2.CHASSISTYPE, A1.VERSION, A3.CURRENTBUILD  FROM Computer A0 (nolock) LEFT OUTER JOIN Operating_System A1 (nolock) ON A0.Computer_Idn = A1.Computer_Idn LEFT OUTER JOIN CompSystem A2 (nolock) ON A0.Computer_Idn = A2.Computer_Idn LEFT OUTER JOIN OSNT A3 (nolock) ON A0.Computer_Idn = A3.Computer_Idn  WHERE (A0.DeviceName = N' + hostname + ')";
      //todo: move the below to a parametertized function to prevent SQL injection.
      sQuery = sQuery.Replace(" + hostname + ", lFidoReturnValues.Landesk.Hostname);
      var sqlConnect = new SqlConnection(sConnectionString);
      sqlConnect.Open();
      try
      {
        var sqlCmd = new SqlCommand(sQuery, sqlConnect);
        var sqlReader = sqlCmd.ExecuteReader();

        Thread.Sleep(500);

        if (sqlReader.HasRows)
        {
          while (sqlReader.Read())
          {
            var oHostOsInfo = new object[sqlReader.FieldCount];
            sqlReader.GetValues(oHostOsInfo);
            var q = oHostOsInfo.Count();
            for (var i = 0; i < q; i++)
            {
              lHostInfoReturn.Add(string.IsNullOrEmpty(oHostOsInfo[i].ToString()) ? oHostOsInfo[i].ToString() : "unknown");
            }
          }
        }
        sqlReader.Dispose();
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in getting vulns from Landesk:" + e);
      }
      finally
      {
        sqlConnect.Dispose();
      }
      lLandeskReturnValues = Landesk2FidoValues.LandeskOsValues(lLandeskReturnValues, lHostInfoReturn);
      lFidoReturnValues.Landesk = lLandeskReturnValues;
      return lFidoReturnValues;
    }

    //special function to format IP for Landesk DBs queries
    public static string FormatIP(string sIP)
    {
      var sIPary = sIP.Split('.');
      try
      {
        for (var i = 0; i < 4; i++)
        {
          var iOctet = sIPary[i].Length;
          switch (iOctet)
          {
            case 1:
              sIPary[i] = "00" + sIPary[i];
              break;
            case 2:
              sIPary[i] = "0" + sIPary[i];
              break;
          }
        }
        sIP = sIPary[0] + "." + sIPary[1] + "." + sIPary[2] + "." + sIPary[3];
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in getting vulns from Landesk:" + e);
      }
      return sIP;
    }
  }
  class Landesk2FidoValues
  {
    public static FidoReturnValues LandesklFidoValues(FidoReturnValues lFidoReturnValues, List<string> lHostInfo)
    {

      var lLandeskReturnValues = new LandeskReturnValues();
      for (var i = 0; i < lHostInfo.Count(); i++)
      {
        switch (i)
        {
          case 0:
            lLandeskReturnValues.Hostname = lHostInfo[0] ?? string.Empty;
            break;
          case 1:
            lLandeskReturnValues.Domain = lHostInfo[1] ?? string.Empty;
            break;
          case 2:
            lLandeskReturnValues.LastUpdate = lHostInfo[2] ?? string.Empty;
            break;
          case 3:
            lLandeskReturnValues.Product = lHostInfo[3] ?? string.Empty;
            break;
          case 4:
            lLandeskReturnValues.ProductVersion = lHostInfo[4] ?? string.Empty;
            break;
          case 5:
            lLandeskReturnValues.AgentRunning = lHostInfo[5] ?? string.Empty;
            break;
          case 6:
            lLandeskReturnValues.AutoProtectOn = lHostInfo[6] ?? string.Empty;
            break;
          case 7:
            lLandeskReturnValues.DefInstallDate = lHostInfo[7] ?? string.Empty;
            break;
          case 8:
            lLandeskReturnValues.EngineVersion = lHostInfo[8] ?? string.Empty;
            break;
          case 9:
            lLandeskReturnValues.OSName = lHostInfo[9] ?? string.Empty;
            break;
          case 10:
            lLandeskReturnValues.ComputerIDN = lHostInfo[10] ?? string.Empty;
            break;
          case 11:
            lLandeskReturnValues.Username = lHostInfo[11] ?? string.Empty;
            break;
        }
      }

      lFidoReturnValues.Landesk = lLandeskReturnValues;
      lFidoReturnValues.Hostname = lLandeskReturnValues.Hostname;
      lFidoReturnValues.Username = lLandeskReturnValues.Username;
      return lFidoReturnValues;
    }
    public static LandeskReturnValues LandeskOsValues(LandeskReturnValues lLandeskReturnValues, List<string> lHostInfo)
    {

      for (var i = 0; i < lHostInfo.Count(); i++)
      {
        switch (i)
        {
          case 0:
            lLandeskReturnValues.OSType = lHostInfo[0];
            break;
          case 1:
            lLandeskReturnValues.Type = lHostInfo[1];
            break;
          case 2:
            lLandeskReturnValues.Battery = lHostInfo[2];
            break;
          case 3:
            lLandeskReturnValues.ChassisType = lHostInfo[3];
            break;
          case 4:
            lLandeskReturnValues.OSVersion = lHostInfo[4];
            break;
          case 5:
            lLandeskReturnValues.OSBuild = lHostInfo[5];
            break;
        }
      }

      return lLandeskReturnValues;
    }
  }
}
