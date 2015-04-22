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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Fido_Main.Director;
using Fido_Main.Director.Scoring;
using Fido_Main.Director.SysMgmt;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.FidoDB;
using Fido_Main.Fido_Support.Objects.Carbon_Black;
using Fido_Main.Fido_Support.Objects.Fido;
using Newtonsoft.Json;
using Exception = System.Exception;

namespace Fido_Main.Main.Detectors
{
  static class Detect_CarbonBlack
  {
    public static void GetCarbonBlackHost(string parameter, bool isParameter)
    {
      Console.WriteLine(@"Gathering alert data from Carbon Black.");
      //currently needed to bypass site without a valid cert.
      //todo: make ssl bypass configurable
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

      var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs("carbonblackv1");
      var request = parseConfigs.Server + parseConfigs.Query;
      if (isParameter)
      {
        request = parameter;
      }
      
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      alertRequest.Headers[@"X-Auth-Token"] = parseConfigs.APIKey;
      try
      {
        using (var cbResponse = alertRequest.GetResponse() as HttpWebResponse)
        {
          if (cbResponse != null && cbResponse.StatusCode == HttpStatusCode.OK)
          {
            using (var respStream = cbResponse.GetResponseStream())
            {
              if (respStream == null) return;
              var cbReader = new StreamReader(respStream, Encoding.UTF8);
              var stringreturn = cbReader.ReadToEnd();
              if (stringreturn == "[]") return;
              var cbReturn = JsonConvert.DeserializeObject<Object_CarbonBlack_Alert_Class.CarbonBlack>(stringreturn);
              if (cbReturn != null)
              {
                if (cbReturn.Total_Results >= 25)
                {
                  Console.WriteLine(@"Currently parsing items " + cbReturn.Start + @" to " + (cbReturn.Start + 25) +  @" out of " + cbReturn.Total_Results + @" total Carbon Black alerts.");
                  ParseCarbonBlackAlert(cbReturn);
                  GetCarbonBlackHost(parseConfigs.Server + "/api/v1/alert?q=&cb.fq.status=Unresolved&sort=alert_severity desc&rows=25&start=" + (cbReturn.Start + 25),true);
                }
                Console.WriteLine(@"Currently parsing items " + cbReturn.Start + @" to " + (cbReturn.Start + 25) + @" out of " + cbReturn.Total_Results + @" total Carbon Black alerts.");
                ParseCarbonBlackAlert(cbReturn);
              }
              var responseStream = cbResponse.GetResponseStream();
              if (responseStream != null) responseStream.Dispose();
              cbResponse.Close();
              Console.WriteLine(@"Finished retreiving CB alerts.");
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Carbon Black alert area:" + e);
      }
    }

    private static void ParseCarbonBlackAlert(Object_CarbonBlack_Alert_Class.CarbonBlack cbReturn)
    {
      var cbHost = string.Empty;
      var cbHostInt = 0;

      foreach (var cbEvent in cbReturn.Results)
      {
        Console.WriteLine(@"Formatting CarbonBlack event for: " + cbEvent.Hostname + @".");
        try
        {
          //initialize generic variables for CB values
          var lFidoReturnValues = new FidoReturnValues();
          if (lFidoReturnValues.PreviousAlerts == null)
          {
            lFidoReturnValues.PreviousAlerts = new EventAlerts();
          }

          if (lFidoReturnValues.CB == null)
          {
            lFidoReturnValues.CB = new CarbonBlackReturnValues { Alert = new CarbonBlackAlert() };
          }
          lFidoReturnValues.CurrentDetector = "carbonblackv1"; 
          lFidoReturnValues.CB.Alert.WatchListName = cbEvent.WatchlistName;
          lFidoReturnValues.CB.Alert.AlertType = cbEvent.AlertType;
          if (lFidoReturnValues.CB.Alert.WatchListName.Contains("binary") || lFidoReturnValues.CB.Alert.AlertType.Contains("binary"))
          {
            lFidoReturnValues.isBinary = true;
          }
          
          var dTable = new SqLiteDB();
          var cbData = dTable.GetDataTable(@"Select * from configs_dictionary_carbonblack");
          var cbDict = GetDict(cbData);

          foreach (var label in cbDict)
          {
            if (cbEvent.WatchlistName == label.Key)
            {
              lFidoReturnValues.MalwareType = label.Value;
              break;
            }
          }

          if (lFidoReturnValues.MalwareType == null) lFidoReturnValues.MalwareType = "Malicious file detected.";

          lFidoReturnValues.CB.Alert.EventID = cbEvent.UniqueID;
          lFidoReturnValues.AlertID = cbEvent.UniqueID;
          lFidoReturnValues.CB.Alert.EventTime = Convert.ToDateTime(cbEvent.CreatedTime).ToUniversalTime().ToString(CultureInfo.InvariantCulture);
          lFidoReturnValues.TimeOccurred = Convert.ToDateTime(cbEvent.CreatedTime).ToUniversalTime().ToString(CultureInfo.InvariantCulture);
          lFidoReturnValues.Hostname = cbEvent.Hostname;

          //todo: this was supposed to limit the total # of alerts sent from a single host,
          //however, it is poo and needs to be redone.
          if (lFidoReturnValues.Hostname != cbHost)
          {
            cbHost = lFidoReturnValues.Hostname;
          }
          else
          {
            cbHostInt++;  
          }
          
          if (cbHostInt >= 25)
          {
            CloseCarbonBlackAlert(lFidoReturnValues);
          }
          lFidoReturnValues.Username = cbEvent.Username;
          lFidoReturnValues.Hash = new List<string> {cbEvent.MD5};
          lFidoReturnValues.CB.Alert.MD5Hash = cbEvent.MD5;
          lFidoReturnValues.CB.Inventory = SysMgmt_CarbonBlack.GetCarbonBlackHost(lFidoReturnValues, true);
          if (string.IsNullOrEmpty(cbEvent.ProcessPath))
          {
            if (string.IsNullOrEmpty(cbEvent.ProcessPath)) lFidoReturnValues.CB.Alert.ProcessPath = cbEvent.ObservedFilename[0];
          }
          else
          {
            lFidoReturnValues.CB.Alert.ProcessPath = cbEvent.ProcessPath;  
          }

          if ((cbEvent.ObservedHosts.HostCount != 0) && (cbEvent.ObservedHosts.HostCount != null))
          {
            lFidoReturnValues.CB.Alert.HostCount = cbEvent.ObservedHosts.HostCount.ToString(CultureInfo.InvariantCulture);
          }
          else
          {
            lFidoReturnValues.CB.Alert.HostCount = "0";
          }

          if ((cbEvent.NetconnCount != 0) && (cbEvent.NetconnCount != null))
          {
            lFidoReturnValues.CB.Alert.NetConn = cbEvent.NetconnCount.ToString(CultureInfo.InvariantCulture);
          }
          else
          {
            lFidoReturnValues.CB.Alert.NetConn = "0";
          }

          if (lFidoReturnValues.CB.Inventory != null)
          {
            var sFilter = new[] {"|", ","};
            var sIP = lFidoReturnValues.CB.Inventory.NetworkAdapters.Split(sFilter,StringSplitOptions.RemoveEmptyEntries);
            lFidoReturnValues.SrcIP = sIP[0];
          }

          var isRunDirector = false;
          //Check to see if ID has been processed before
          lFidoReturnValues.PreviousAlerts = Matrix_Historical_Helper.GetPreviousMachineAlerts(lFidoReturnValues, false);
          if (lFidoReturnValues.PreviousAlerts.Alerts != null && lFidoReturnValues.PreviousAlerts.Alerts.Rows.Count > 0)
          {
            isRunDirector = PreviousAlert(lFidoReturnValues, lFidoReturnValues.AlertID, lFidoReturnValues.TimeOccurred);
          }
          if (isRunDirector || lFidoReturnValues.MalwareType.Contains("EICAR")) continue;
          //todo: build better filetype versus targetted OS, then remove this.
          lFidoReturnValues.IsTargetOS = true;
          TheDirector.Direct(lFidoReturnValues);
          //CloseCarbonBlackAlert(lFidoReturnValues);
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Carbon Black v1 Detector when formatting json:" + e);
        }
      }
    }

    private static void CloseCarbonBlackAlert(FidoReturnValues lFidoReturnValues)
    {
      Console.WriteLine(@"Closing CarbonBlack event for: " + lFidoReturnValues.AlertID + @".");
      //currently needed to bypass site without a valid cert.
      //todo: make ssl bypass configurable
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

      var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs("carbonblackv1");
      var request = parseConfigs.Server + parseConfigs.Query2 + lFidoReturnValues.AlertID + parseConfigs.Query3;
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "POST";
      alertRequest.ContentType = "application/json";
      alertRequest.Headers[@"X-Auth-Token"] = parseConfigs.APIKey;
      try
      {
        using (var cbResponse = alertRequest.GetResponse() as HttpWebResponse)
        {
          if (cbResponse != null && cbResponse.StatusCode == HttpStatusCode.OK)
          {
            using (var respStream = cbResponse.GetResponseStream())
            {
              if (respStream == null) return;
              var cbReader = new StreamReader(respStream, Encoding.UTF8);
              var stringreturn = cbReader.ReadToEnd();
              if (stringreturn == "[]") return;
              var cbReturn = JsonConvert.DeserializeObject<Object_CarbonBlack_Alert_Class.CarbonBlack>(stringreturn);
              if (cbReturn != null)
              {
                ParseCarbonBlackAlert(cbReturn);
              }
              var responseStream = cbResponse.GetResponseStream();
              if (responseStream != null) responseStream.Dispose();
              cbResponse.Close();
              Console.WriteLine(@"Finished retreiving CB alerts.");
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Carbon Black alert area:" + e);
      }
    }

    private static bool PreviousAlert(FidoReturnValues lFidoReturnValues, string event_id, string event_time)
    {
      var isRunDirector = false;
      for (var j = 0; j < lFidoReturnValues.PreviousAlerts.Alerts.Rows.Count; j++)
      {
        if (lFidoReturnValues.PreviousAlerts.Alerts.Rows[j][6].ToString() != event_id) continue;
        if (Convert.ToDateTime(event_time) == Convert.ToDateTime(lFidoReturnValues.PreviousAlerts.Alerts.Rows[j][4].ToString()))
        {
          isRunDirector = true;
        }
      }
      return isRunDirector;
    }

    private static Dictionary<string, string> GetDict(DataTable dt)
    {
      return dt.AsEnumerable()
        .ToDictionary<DataRow, string, string>(row => row.Field<string>(1),
                                  row => row.Field<string>(2));
    }
  }
}
