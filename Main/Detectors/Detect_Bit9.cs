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
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using Fido_Main.Director;
using Fido_Main.Director.Threat_Feeds;
using Fido_Main.Fido_Support.Crypto;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using VirusTotalNET.Objects;

namespace Fido_Main.Main.Detectors
{
  internal static class Detect_Bit9
  {
    //This is the detector call for bit9. Its purpose is to get
    //the most recent hashes (last 60 secs (or so)) and parse them
    //over to our security feeds. If the security feeds find
    //relevant information get hostname/ip and call TheDirector.
    public static void GetEvents()
    {
      var lFidoReturnValues = new FidoReturnValues();
      try
      {
        Console.WriteLine(@"Running Bit9 detector.");
        var sAcekDecode = Object_Fido_Configs.GetAsString("fido.detectors.bit9.acek", null);
        sAcekDecode = Aes_Crypto.DecryptStringAES(sAcekDecode, "1");
        var sUserID = Aes_Crypto.DecryptStringAES(Object_Fido_Configs.GetAsString("fido.detectors.bit9.userid", null), sAcekDecode);
        var sPwd = Aes_Crypto.DecryptStringAES(Object_Fido_Configs.GetAsString("fido.detectors.bit9.pwd", null), sAcekDecode);
        var sBit9Server = Object_Fido_Configs.GetAsString("fido.detectors.bit9.server", null);
        var sDb = Object_Fido_Configs.GetAsString("fido.detectors.bit9.db", null);
        var sBit9DetectorQuery = Object_Fido_Configs.GetAsString("fido.detectors.bit9.query", null);
        var sTempConn = Object_Fido_Configs.GetAsString("fido.detectors.bit9.connectionstring", null);
        var replacements = new Dictionary<string, string>
        {
          {"sUserID", sUserID},
          {"sPwd", sPwd},
          {"sBit9Server", sBit9Server},
          {"sDB", sDb}
        };

        //sTempConn = replacements.Aggregate(sTempConn, (current, srep) => current.Replace(srep.Key, srep.Value));
        //todo: SQL injection. really? this was the best you could think of? remove this and do it properly.
        var vConnection = new SqlConnection("user id=" + sUserID + ";password=" + sPwd + ";Server=" + sBit9Server + ",1433;Integrated Security=sspi;Database=" + sDb + ";connection timeout=60");
        var sqlCmd = new SqlCommand(sBit9DetectorQuery, vConnection) {CommandType = CommandType.Text};
        var lBit9Hash = new List<string>();

        vConnection.Open();

        using (var objReader = sqlCmd.ExecuteReader())
        {
          if (objReader.HasRows)
          {
            Console.WriteLine(@"New hashes found...");
            while (objReader.Read())
            {
              var oBit9Return = new object[objReader.FieldCount];
              var quant = objReader.GetSqlValues(oBit9Return);
              if (oBit9Return.GetValue(4) != null)
              {
                lBit9Hash.Add(oBit9Return.GetValue(4).ToString());
              }
            }
          }
        }
        if (lBit9Hash.Count == 0) return;
        Console.WriteLine(@"Processing " + lBit9Hash.Count().ToString(CultureInfo.InvariantCulture) + @" hashes.");
        var aryBit9Hash = lBit9Hash.ToArray();
        lFidoReturnValues.Hash = lBit9Hash;
        //todo: write additional code to include other threat feeds.
        var vtReturn = Feeds_VirusTotal.ParseHash(aryBit9Hash);
          
        if (!vtReturn.Any()) return;

        //todo: if return is 'not seen before' right helper function to upload file to threat feed.
        foreach (var vtEntry in vtReturn)
        {
          if (vtEntry.Positives <= 0)
          {
            continue;
          }
          
          var sHostInfo = GetHost(vtEntry.Resource);
          foreach (var sHostInfoList in sHostInfo)
          {
            var sSingleHostInfo = sHostInfoList.Split(',');
            var sHostName = sSingleHostInfo[0].Split('\\');
            //todo: need to write second tree for when file hasn't
            //executed, but does still exist on the system, 
            //sSingleHostInfo[1].ToLower() == "yes"
            if (sSingleHostInfo[2].ToLower() != "yes") continue;
            if (lFidoReturnValues.Bit9 == null)
            {
              lFidoReturnValues.Bit9 = new Bit9ReturnValues();
            }
            if (lFidoReturnValues.Bit9.VTReport == null)
            {
              lFidoReturnValues.Bit9.VTReport = new List<FileReport>();
            }

            lFidoReturnValues.IsHostKnown = true;
            lFidoReturnValues.Hostname = sHostName[1];
            lFidoReturnValues.SrcIP = sSingleHostInfo[1];
            lFidoReturnValues.Bit9.HostName = sSingleHostInfo[0];
            lFidoReturnValues.Bit9.VTReport.Add(vtEntry); 
            lFidoReturnValues.Bit9.FileExecuted = sSingleHostInfo[2];
            lFidoReturnValues.Bit9.FileDeleted = sSingleHostInfo[3];
            lFidoReturnValues.CurrentDetector = "bit9";
            lFidoReturnValues.MalwareType = "Malicious file";
            lFidoReturnValues.IsTargetOS = true;
            lFidoReturnValues.DstIP = string.Empty;
            var lMD5 = new List<string> {vtEntry.MD5};
            lMD5 = GetFileInfo(lMD5, lFidoReturnValues.Bit9);
            lFidoReturnValues.Bit9.FileName = lMD5[5] + @"\" + lMD5[6];
            lFidoReturnValues.Bit9.FileThreat = lMD5[51];
            lFidoReturnValues.Bit9.FileTrust = lMD5[50];
            //lFidoReturnValues.Hash = new List<FileReport> {vtEntry.MD5};
            Console.WriteLine(@"Malicious hashes found... continue to process.");
            TheDirector.Direct(lFidoReturnValues);
          }
        }
        vConnection.Close();
        Console.WriteLine(@"Exiting Bit9 detector.");
      }
      catch (Exception e)
      {
        // Get stack trace for the exception with source file information
        var st = new StackTrace(e, true);
        // Get the top stack frame
        var frame = st.GetFrame(0);
        // Get the line number from the stack frame
        var line = frame.GetFileLineNumber();
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught retrieving alerts from Bit9 on line " + line + ":" + e);
      }
    }

    public static List<string> GetFileInfo(IEnumerable<string> lFileHash, Bit9ReturnValues lBit9ReturnValues)
    {
      var lBit9Info = new List<string>();
      var oBit9Return = new object[69];

      var sAcekDecode = Object_Fido_Configs.GetAsString("fido.detectors.bit9.acek", null);
      sAcekDecode = Aes_Crypto.DecryptStringAES(sAcekDecode, "1");
      var sUserID = Aes_Crypto.DecryptStringAES(Object_Fido_Configs.GetAsString("fido.detectors.bit9.userid", null), sAcekDecode);
      var sPwd = Aes_Crypto.DecryptStringAES(Object_Fido_Configs.GetAsString("fido.detectors.bit9.pwd", null), sAcekDecode);
      var sBit9Server = Object_Fido_Configs.GetAsString("fido.detectors.bit9.server", null);
      var sDb = Object_Fido_Configs.GetAsString("fido.detectors.bit9.db", null);

      try
      {
        //todo: take connection string and encrypt to put in XML config
        var vConnection = new SqlConnection("user id=" + sUserID + ";password=" + sPwd + ";Server=" + sBit9Server + ",1433;Integrated Security=sspi;Database=" + sDb + ";connection timeout=60");
        if (lFileHash != null)
        {
          //todo: SQL injection. Store query in database and fill variables when retrieving
          foreach (var CMD in lFileHash.Select(sFileHash => "SELECT * FROM [das].[dbo].[Fido_FileInstanceInfo] WHERE MD5 = '" + sFileHash + "'").Select(sQuery => new SqlCommand(sQuery, vConnection)))
          {
            CMD.CommandType = CommandType.Text;
            vConnection.Open();
            using (var objReader = CMD.ExecuteReader())
            {
              if (objReader.HasRows)
              {
                while (objReader.Read())
                {
                  var quant = objReader.GetSqlValues(oBit9Return);
                  if (!oBit9Return.Any()) continue;
                  lBit9Info.AddRange(oBit9Return.Select(item => item.ToString()));
                }
              }
            }
            vConnection.Close();
          }
        }
        else if (lBit9ReturnValues != null)
        {
          //todo: SQL injection. Store query in database and fill values when retrieving
          var sQuery = "SELECT * FROM [das].[dbo].[Fido_FileInstanceInfo] WHERE FILE_NAME = '" + lBit9ReturnValues.FileName.ToLower() + "' AND Path_Name = '" + lBit9ReturnValues.FilePath.ToLower() + "' AND Computer_Name = '" + lBit9ReturnValues.HostName + "'";
          var CMD = new SqlCommand(sQuery, vConnection) {CommandType = CommandType.Text};
          vConnection.Open();
          using (var objReader = CMD.ExecuteReader())
          {
            if (objReader.HasRows)
            {
              while (objReader.Read())
              {
                var quant = objReader.GetSqlValues(oBit9Return);
                if (!oBit9Return.Any()) continue;
                lBit9Info.AddRange(oBit9Return.Select(item => item.ToString()));
              }
            }
          }
          vConnection.Close();
        }

        //if no count then no hash information exists
        if (lBit9Info.Count != 0)
        {
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught retrieving file information from Bit9:" + e);
      }
        
      return lBit9Info;
    }

    //get the specific machines events which happened on the computer... going back 2hrs.
    public static List<string> GetMachineEvents()
    {
      //todo: build this method out
      return null;
    }

    //if getevents is positive, get machine name and IP
    private static IEnumerable<string> GetHost(string sMD5)
    { 
      var sAcekDecode = Object_Fido_Configs.GetAsString("fido.detectors.bit9.acek", null);
      sAcekDecode = Aes_Crypto.DecryptStringAES(sAcekDecode, "1");
      var sUserID = Aes_Crypto.DecryptStringAES(Object_Fido_Configs.GetAsString("fido.detectors.bit9.userid", null), sAcekDecode);
      var sPwd = Aes_Crypto.DecryptStringAES(Object_Fido_Configs.GetAsString("fido.detectors.bit9.pwd", null), sAcekDecode);
      var sBit9Server = Object_Fido_Configs.GetAsString("fido.detectors.bit9.server", null);
      var sDB = Object_Fido_Configs.GetAsString("fido.detectors.bit9.db", null);
      var oBit9Return = new object[4];
      var lHostInfo = new List<string>();

      try
      {
        //todo: encrypt and retrived these values from DB.
        var vConnection = new SqlConnection("user id=" + sUserID + ";password=" + sPwd + ";Server=" + sBit9Server + ",1433;Integrated Security=sspi;Database=" + sDB + ";connection timeout=10");
        //todo: SQL injection. Store query in database and modify variables when retrieving
        var sQuery = "SELECT [Computer_Name],[IP_Address], [Executed], [Deleted] FROM [das].[dbo].[Fido_FileInstanceInfo] Where MD5 = '" + sMD5 + "'";
        using (var cmd = new SqlCommand(sQuery, vConnection) {CommandType = CommandType.Text})
        {
          vConnection.Open();
          using (var objReader = cmd.ExecuteReader())
          {
            if (objReader.HasRows)
            {
              while (objReader.Read())
              {
                var quant = objReader.GetSqlValues(oBit9Return);
                if (oBit9Return.GetValue(0) != null)
                {
                  lHostInfo.Add(oBit9Return.GetValue(0) + "," + oBit9Return.GetValue(1) + "," + oBit9Return.GetValue(2) + "," + oBit9Return.GetValue(3));
                }
              }
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught retrieving host information from Bit9:" + e);
      }
      return lHostInfo;
    }
  }
}
