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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Fido_Main.Director;
using Fido_Main.Director.Scoring;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.ProtectWise;
using Newtonsoft.Json;

namespace Fido_Main.Main.Detectors
{
  static class Detect_ProtectWise_v1
  {

    public static void GetProtectWiseEvents()
    {
      Console.WriteLine(@"Running ProtectWise v1 detector.");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs("protectwisev1-event");
      var getTime = DateTime.Now.ToUniversalTime();
      var timer = parseConfigs.Query3.Trim();
      var timeRange = Convert.ToDouble(timer) * -1;
      var oldtime = getTime.AddMinutes(timeRange);
      var currentTime = ToEpochTime(getTime).ToString(CultureInfo.InvariantCulture) + "000";
      var newoldtime = ToEpochTime(oldtime).ToString(CultureInfo.InvariantCulture) + "000";
      var request = parseConfigs.Server + parseConfigs.Query.Replace("%currenttime%", currentTime).Replace("%minustime%", newoldtime);
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Headers[@"X-Access-Token"] = parseConfigs.APIKey;
      alertRequest.Method = "GET";
      try
      {
        using (var protectwiseResponse = alertRequest.GetResponse() as HttpWebResponse)
        {
          if (protectwiseResponse != null && protectwiseResponse.StatusCode == HttpStatusCode.OK)
          {
            using (var respStream = protectwiseResponse.GetResponseStream())
            {
              if (respStream == null) return;
              var protectwiseReader = new StreamReader(respStream, Encoding.UTF8);
              var stringreturn = protectwiseReader.ReadToEnd();
              var protectwiseReturn = JsonConvert.DeserializeObject<Object_ProtectWise_Threat_ConfigClass.ProtectWise_Events>(stringreturn);
              if (protectwiseReturn.Events != null)
              {
                ParseProtectWiseEvent(protectwiseReturn);
              }
              
              var responseStream = protectwiseResponse.GetResponseStream();
              if (responseStream != null) responseStream.Dispose();
              protectwiseResponse.Close();
              Console.WriteLine(@"Finished processing ProtectWise events detector.");
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in ProtectWise v1 Detector when getting json:" + e);
      }
    }

    private static void ParseProtectWiseEvent(Object_ProtectWise_Threat_ConfigClass.ProtectWise_Events protectWiseReturn)
    {
      protectWiseReturn.Events = protectWiseReturn.Events.Reverse().ToArray();
      foreach (var pevent in protectWiseReturn.Events)
      {
        Console.WriteLine(@"Gathering ProtectWise observations for event: " + pevent.Message + @".");
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
        var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs("protectwisev1-event");
        var request = parseConfigs.Server + parseConfigs.Query2 + pevent.Id;
        var alertRequest = (HttpWebRequest) WebRequest.Create(request);
        alertRequest.Headers[@"X-Access-Token"] = parseConfigs.APIKey;
        alertRequest.Method = "GET";
        try
        {
          using (var protectwiseResponse = alertRequest.GetResponse() as HttpWebResponse)
          {
            if (protectwiseResponse != null && protectwiseResponse.StatusCode == HttpStatusCode.OK)
            {
              using (var respStream = protectwiseResponse.GetResponseStream())
              {
                if (respStream == null) return;
                var protectwiseReader = new StreamReader(respStream, Encoding.UTF8);
                var stringreturn = protectwiseReader.ReadToEnd();
                var protectwiseReturn = JsonConvert.DeserializeObject<Object_ProtectWise_Threat_ConfigClass.ProtectWise_Search_Event>(stringreturn);
                if (protectwiseReturn != null)
                {
                  ParseProtectWiseObservation(protectwiseReturn, pevent.Message);
                }

                var responseStream = protectwiseResponse.GetResponseStream();
                if (responseStream != null) responseStream.Dispose();
                protectwiseResponse.Close();
              }
            }
          }
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in ProtectWise v1 Detector when getting json:" + e);
        }
      }
    }

    private static void ParseProtectWiseObservation(Object_ProtectWise_Threat_ConfigClass.ProtectWise_Search_Event protectwiseReturn, string malwareType)
    {
      try
      {
        //protectwiseReturn.Observations = protectwiseReturn.Observations.Reverse().ToArray();
        for (var i = 0; i < protectwiseReturn.Observations.Count(); i++)
        {
          if (protectwiseReturn.Observations[i].Flow.IP.DstIP == "0.0.0.0") continue;
          Console.WriteLine(@"Processing ProtectWise observation " + (i + 1).ToString(CultureInfo.InvariantCulture) + @" of " + protectwiseReturn.Observations.Count().ToString(CultureInfo.InvariantCulture) + @".");

          //initialize generic variables for Cyphort values
          var lFidoReturnValues = new FidoReturnValues();
          if (lFidoReturnValues.PreviousAlerts == null)
          {
            lFidoReturnValues.PreviousAlerts = new EventAlerts();
          }
          
          if (lFidoReturnValues.ProtectWise == null)
          {
            lFidoReturnValues.ProtectWise = new ProtectWiseReturnValues();
          }
          lFidoReturnValues.ProtectWise.EventDetails = protectwiseReturn;

          lFidoReturnValues.MalwareType = protectwiseReturn.Observations[i].Category + " : " + protectwiseReturn.Observations[i].ThreatSubCategory + " (" + protectwiseReturn.Observations[i].KillChainStage + ")";

          //Assign generic event deatils for use in TheDirector
          lFidoReturnValues.CurrentDetector = "protectwisev1";
          lFidoReturnValues.MalwareType = malwareType;
          if (!string.IsNullOrEmpty(lFidoReturnValues.ProtectWise.EventDetails.Id))
          {
            if (protectwiseReturn.Observations[i].Flow.IP.SrcIP == "0.0.0.0" || protectwiseReturn.Observations[i].Flow.IP.DstIP == "0.0.0.0") continue;
            lFidoReturnValues.ProtectWise.IncidentDetails = new Object_ProtectWise_Threat_ConfigClass.ProtectWise_Observation();
            if (protectwiseReturn.Netflow[i].GEO != null)
            {
              lFidoReturnValues.ProtectWise.GEO = new Object_ProtectWise_Threat_ConfigClass.ProtectWise_GEO();
              lFidoReturnValues.ProtectWise.GEO = protectwiseReturn.Netflow[i].GEO;
            }
            lFidoReturnValues.ProtectWise.IncidentDetails = protectwiseReturn.Observations[i];
            if (protectwiseReturn.Observations[i].Flow.IP.DstIP.StartsWith("10."))
            {
              lFidoReturnValues.SrcIP = protectwiseReturn.Observations[i].Flow.IP.DstIP;
              lFidoReturnValues.ProtectWise.DstIP = protectwiseReturn.Observations[i].Flow.IP.SrcIP;
              lFidoReturnValues.DstIP = protectwiseReturn.Observations[i].Flow.IP.SrcIP;
              lFidoReturnValues.ProtectWise.URL = protectwiseReturn.Observations[i].Flow.IP.SrcIP;
            }
            else
            {
              lFidoReturnValues.DstIP = protectwiseReturn.Observations[i].Flow.IP.DstIP;
              lFidoReturnValues.ProtectWise.DstIP = protectwiseReturn.Observations[i].Flow.IP.DstIP;
              lFidoReturnValues.SrcIP = protectwiseReturn.Observations[i].Flow.IP.SrcIP;
              lFidoReturnValues.ProtectWise.URL = protectwiseReturn.Observations[i].Flow.IP.DstIP;
            }
            
            lFidoReturnValues.ProtectWise.EventID = protectwiseReturn.Observations[i].EventID;
            lFidoReturnValues.AlertID = protectwiseReturn.Observations[i].EventID;
            lFidoReturnValues.TimeOccurred = FromEpochTime(protectwiseReturn.Observations[i].EventTime).ToString();
            lFidoReturnValues.ProtectWise.EventTime = FromEpochTime(protectwiseReturn.Observations[i].EventTime).ToString();
            if (protectwiseReturn.Observations[i].Data.URL_Reputation != null)
            {
              var getDomain = protectwiseReturn.Observations[i].Data.URL_Reputation.Url.Split('/');
              lFidoReturnValues.DNSName = getDomain[0].Replace(".", "(.)");
            }

            //Check to see if ID has been processed before
            var isRunDirector = false;
            lFidoReturnValues.PreviousAlerts = Matrix_Historical_Helper.GetPreviousMachineAlerts(lFidoReturnValues, false);
            if (lFidoReturnValues.PreviousAlerts.Alerts != null && lFidoReturnValues.PreviousAlerts.Alerts.Rows.Count > 0)
            {
              isRunDirector = PreviousAlert(lFidoReturnValues, lFidoReturnValues.ProtectWise.EventID, lFidoReturnValues.ProtectWise.EventTime);
            }
            if (isRunDirector || lFidoReturnValues.MalwareType.Contains("EICAR")) return;

            if (lFidoReturnValues.ProtectWise.IncidentDetails.Data.Ip_Reputation != null)
            {
              lFidoReturnValues = FormatIPReturnValues(lFidoReturnValues);
            }

            if (lFidoReturnValues.ProtectWise.IncidentDetails.Data.URL_Reputation != null)
            {
              lFidoReturnValues = FormatURLReturnValues(lFidoReturnValues);
            }

            if (lFidoReturnValues.ProtectWise.IncidentDetails.Data.File_Reputation != null)
            {
            }

            if (lFidoReturnValues.ProtectWise.IncidentDetails.Data.DNS_Reputation != null)
            {
            }

            if (lFidoReturnValues.ProtectWise.IncidentDetails.Data.IdsEvent != null)
            {
              lFidoReturnValues = FormatIdsReturnValues(lFidoReturnValues);
            }

          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in ProtectWise v1 Detector parse:" + e);
      }
    }

    private static FidoReturnValues FormatURLReturnValues(FidoReturnValues lFidoReturnValues)
    {
      try
      {
        lFidoReturnValues.ProtectWise.URL = lFidoReturnValues.ProtectWise.IncidentDetails.Data.URL_Reputation.Url;
        //todo: build better filetype versus targetted OS, then remove this.
        lFidoReturnValues.IsTargetOS = true;
        TheDirector.Direct(lFidoReturnValues);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in ProtectWise v1 URL reputation return:" + e); ;
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues FormatIPReturnValues(FidoReturnValues lFidoReturnValues)
    {
      try
      {
        //todo: build better filetype versus targetted OS, then remove this.
        lFidoReturnValues.IsTargetOS = true;
        TheDirector.Direct(lFidoReturnValues);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in ProtectWise v1 IP reputation return:" + e); ;
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues FormatIdsReturnValues(FidoReturnValues lFidoReturnValues)
    {
      try
      {
        //todo: build better filetype versus targetted OS, then remove this.
        lFidoReturnValues.IsTargetOS = true;
        TheDirector.Direct(lFidoReturnValues);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in ProtectWise v1 IP reputation return:" + e); ;
      }

      return lFidoReturnValues;
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

    private static DateTime? FromEpochTime(string unixTime)
    {
      return new DateTime(1970, 1, 1, 0, 0, 0).AddMilliseconds(Convert.ToDouble(unixTime));
    }

    private static long ToEpochTime(this DateTime date)
    {
      var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
      return Convert.ToInt64((date - epoch).TotalSeconds);
    }

    //private static void GetProtectWiseEvent(FidoReturnValues lFidoReturnValues)
    //{
    //  Console.WriteLine(@"Pulling ProtectWise incident details.");
    //  ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;

    //  var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs(lFidoReturnValues.ProtectWise.ProtectWiseType);
    //  var request = string.Empty;
    //  switch (lFidoReturnValues.ProtectWise.ProtectWiseType)
    //  {

    //    case "protectwisev1-observation":
    //      request = parseConfigs.Server + parseConfigs.Query2;
    //      request = request.Replace("%incidentid%", lFidoReturnValues.ProtectWise.EventID);
    //      break;
    //    case "protectwisev1-event":
    //      request = parseConfigs.Server + parseConfigs.Query2 + lFidoReturnValues.ProtectWise.EventID;
    //      break;
    //  }

    //  var alertRequest = (HttpWebRequest)WebRequest.Create(request);
    //  alertRequest.Headers[@"X-Access-Token"] = parseConfigs.APIKey;
    //  alertRequest.Method = "GET";
    //  try
    //  {
    //    using (var protectwiseResponse = alertRequest.GetResponse() as HttpWebResponse)
    //    {
    //      if (protectwiseResponse != null && protectwiseResponse.StatusCode == HttpStatusCode.OK)
    //      {
    //        using (var respStream = protectwiseResponse.GetResponseStream())
    //        {
    //          if (respStream == null) return;
    //          var protectwiseReader = new StreamReader(respStream, Encoding.UTF8);
    //          var stringreturn = protectwiseReader.ReadToEnd();
    //          var protectwiseReturn = JsonConvert.DeserializeObject<Object_ProtectWise_Threat_ConfigClass.ProtectWise_Observation>(stringreturn);
    //          if (protectwiseReturn.EventID != null)
    //          {
    //            lFidoReturnValues.ProtectWise.IncidentDetails = new Object_ProtectWise_Threat_ConfigClass.ProtectWise_Observation();
    //            lFidoReturnValues.ProtectWise.IncidentDetails = protectwiseReturn;
    //            lFidoReturnValues.DstIP = protectwiseReturn.Flow.IP.DstIP;
    //            lFidoReturnValues.ProtectWise.DstIP = protectwiseReturn.Flow.IP.DstIP;
    //            lFidoReturnValues.SrcIP = protectwiseReturn.Flow.IP.SrcIP;

    //            //Check to see if ID has been processed before
    //            var isRunDirector = false;
    //            lFidoReturnValues.PreviousAlerts = Matrix_Historical_Helper.GetPreviousMachineAlerts(lFidoReturnValues, false);
    //            if (lFidoReturnValues.PreviousAlerts.Alerts != null && lFidoReturnValues.PreviousAlerts.Alerts.Rows.Count > 0)
    //            {
    //              isRunDirector = PreviousAlert(lFidoReturnValues, lFidoReturnValues.ProtectWise.EventID, lFidoReturnValues.ProtectWise.EventTime);
    //            }
    //            if (isRunDirector || lFidoReturnValues.MalwareType.Contains("EICAR")) return;

    //            if (lFidoReturnValues.ProtectWise.IncidentDetails.Data.Ip_Reputation != null)
    //            {
    //              lFidoReturnValues = FormatIPReturnValues(lFidoReturnValues);
    //            }

    //            if (lFidoReturnValues.ProtectWise.IncidentDetails.Data.URL_Reputation != null)
    //            {
    //              lFidoReturnValues = FormatURLReturnValues(lFidoReturnValues);
    //            }

    //            if (lFidoReturnValues.ProtectWise.IncidentDetails.Data.File_Reputation != null)
    //            {
    //            }

    //            if (lFidoReturnValues.ProtectWise.IncidentDetails.Data.DNS_Reputation != null)
    //            {
    //            }
    //          }
    //        }
    //      }
    //    }
    //  }
    //  catch (Exception e)
    //  {
    //    Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in ProtectWise v1 Detector getting event json:" + e);
    //  }
    //}

    //public static void GetProtectWiseObservations()
    //{
    //  Console.WriteLine(@"Running ProtectWise v1 detector.");
    //  ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;

    //  var getTime = DateTime.Now.ToUniversalTime();
    //  var oldtime = getTime.AddMinutes(-15);
    //  var currentTime = ToEpochTime(getTime).ToString(CultureInfo.InvariantCulture) + "000";
    //  var newoldtime = ToEpochTime(oldtime).ToString(CultureInfo.InvariantCulture) + "000";
    //  var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs("protectwisev1-observation");
    //  var request = parseConfigs.Server + parseConfigs.Query.Replace("%currenttime%", currentTime).Replace("%minustime%", newoldtime);
    //  var alertRequest = (HttpWebRequest)WebRequest.Create(request);
    //  alertRequest.Headers[@"X-Access-Token"] = parseConfigs.APIKey;
    //  alertRequest.Method = "GET";
    //  try
    //  {
    //    using (var protectwiseResponse = alertRequest.GetResponse() as HttpWebResponse)
    //    {
    //      if (protectwiseResponse != null && protectwiseResponse.StatusCode == HttpStatusCode.OK)
    //      {
    //        using (var respStream = protectwiseResponse.GetResponseStream())
    //        {
    //          if (respStream == null) return;
    //          var protectwiseReader = new StreamReader(respStream, Encoding.UTF8);
    //          var stringreturn = protectwiseReader.ReadToEnd();
    //          var protectwiseReturn = JsonConvert.DeserializeObject<Object_ProtectWise_Search_ConfigClass.ProtectWise_Search>(stringreturn);
    //          if (protectwiseReturn.Observations != null)
    //          {
    //            ParseProtectWiseObservation(protectwiseReturn, "protectwisev1-observation", null);
    //          }
    //          var responseStream = protectwiseResponse.GetResponseStream();
    //          if (responseStream != null) responseStream.Dispose();
    //          protectwiseResponse.Close();
    //          Console.WriteLine(@"Finished processing ProtectWise observations detector.");
    //        }
    //      }
    //    }
    //  }
    //  catch (Exception e)
    //  {
    //    Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in ProtectWise v1 Detector when getting json:" + e);
    //  }
    //}

  }
}
