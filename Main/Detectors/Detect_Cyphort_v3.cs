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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Fido_Main.Director;
using Fido_Main.Director.Scoring;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Cyphort;
using Fido_Main.Fido_Support.Objects.Fido;
using Newtonsoft.Json;

namespace Fido_Main.Main.Detectors
{
  public static class Detect_Cyphort_v3
  {
    //This function will grab the API information and build a query string.
    //Then it will assign the json return to an object. If any of the objects
    //have a value they will be sent to ParseCyphort helper function.
    public static void GetCyphortAlerts()
    {
      Console.WriteLine(@"Running Cyphort v3 detector.");
      //currently needed to bypass site without a valid cert.
      //todo: make ssl bypass configurable
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
      
      var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs("cyphortv3");
      var request = parseConfigs.Server + parseConfigs.Query + parseConfigs.APIKey;
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      try
      {
        using (var cyphortResponse = alertRequest.GetResponse() as HttpWebResponse)
        {
          if (cyphortResponse != null && cyphortResponse.StatusCode == HttpStatusCode.OK)
          {
            using (var respStream = cyphortResponse.GetResponseStream())
            {
              if (respStream == null) return;
              var cyphortReader = new StreamReader(respStream, Encoding.UTF8);
              var stringreturn = cyphortReader.ReadToEnd();
              var cyphortReturn = JsonConvert.DeserializeObject<Object_Cyphort_Class.CyphortEvent>(stringreturn);
              if (cyphortReturn.Event_Array.Any())
              {
                ParseCyphort(cyphortReturn);
              }
              var responseStream = cyphortResponse.GetResponseStream();
              if (responseStream != null) responseStream.Dispose();
              cyphortResponse.Close();
              Console.WriteLine(@"Finished processing Cyphort detector.");
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Cyphort Detector getting json:" + e);
      }
    }

    //This function is designed get the incidents from an event, then determine if the 
    //incidents have already been processed. If they have not, they will be handed off
    //to the GetCyphortIncident function to gather necessary information before being
    //sent to TheDirector.
    private static void ParseCyphort(Object_Cyphort_Class.CyphortEvent cyphortReturn)
    {
      try
      {
        if (cyphortReturn.Event_Array.Any())
        {
          cyphortReturn.Event_Array = cyphortReturn.Event_Array.Reverse().ToArray();
          for (var i = 0; i < cyphortReturn.Event_Array.Count(); i++)
          {
            Console.WriteLine(@"Processing Cyphort event " + (i + 1).ToString(CultureInfo.InvariantCulture) + @" of " + cyphortReturn.Event_Array.Count().ToString(CultureInfo.InvariantCulture) + @".");
            
            //We don't currently process IPv6, so if detected exit and process next alert
            if ((cyphortReturn.Event_Array[i].Endpoint_ip != null) && (cyphortReturn.Event_Array[i].Endpoint_ip.Contains(":"))) continue;

            //initialize generic variables for Cyphort values
            var lFidoReturnValues = new FidoReturnValues();
            if (lFidoReturnValues.PreviousAlerts == null)
            {
              lFidoReturnValues.PreviousAlerts = new EventAlerts();
            }

            if (lFidoReturnValues.Cyphort == null)
            {
              lFidoReturnValues.Cyphort = new CyphortReturnValues();
            }

            //Convert Cyphort classifications to more readable values
            if (cyphortReturn.Event_Array[i].Event_type == "http")
            {
              lFidoReturnValues.MalwareType = "Malware downloaded: " + cyphortReturn.Event_Array[i].Event_name + " Type: " + cyphortReturn.Event_Array[i].Event_category;
            }
            else if (cyphortReturn.Event_Array[i].Event_type == "cnc")
            {
              lFidoReturnValues.MalwareType = "CNC Detected: " + cyphortReturn.Event_Array[i].Event_name;
            }

            //Assign generic event deatils for use in TheDirector
            lFidoReturnValues.CurrentDetector = "cyphortv3";
            lFidoReturnValues.Cyphort.IncidentID = cyphortReturn.Event_Array[i].Incident_id;
            lFidoReturnValues.SrcIP = cyphortReturn.Event_Array[i].Endpoint_ip;
            lFidoReturnValues.Cyphort.EventTime = Convert.ToDateTime(cyphortReturn.Event_Array[i].Last_activity_time).ToUniversalTime().ToString(CultureInfo.InvariantCulture);
            lFidoReturnValues.TimeOccurred = Convert.ToDateTime(cyphortReturn.Event_Array[i].Last_activity_time).ToUniversalTime().ToString(CultureInfo.InvariantCulture); 
            lFidoReturnValues.DstIP = cyphortReturn.Event_Array[i].Source_ip;
            lFidoReturnValues.Cyphort.DstIP = cyphortReturn.Event_Array[i].Source_ip;
            
            //Send information gathered thus far to function to gather incident details
            //and further parsing to determine if sending to TheDirector is needed.
            GetCyphortIncident(lFidoReturnValues);
            
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Cyphortv3 Detector parse:" + e);
      }
    }

    private static void GetCyphortIncident(FidoReturnValues lFidoReturnValues)
    {
      Console.WriteLine(@"Pulling Cyphort incident details.");
      //currently needed to bypass site without a valid cert.
      //todo: make ssl bypass configurable
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

      var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs("cyphortv3");
      var request = parseConfigs.Server + parseConfigs.Query2 + parseConfigs.APIKey;
      request = request.Replace("%incidentid%", lFidoReturnValues.Cyphort.IncidentID);
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      try
      {
        using (var cyphortResponse = alertRequest.GetResponse() as HttpWebResponse)
        {
          if (cyphortResponse != null && cyphortResponse.StatusCode == HttpStatusCode.OK)
          {
            using (var respStream = cyphortResponse.GetResponseStream())
            {
              if (respStream == null) return;
              var cyphortReader = new StreamReader(respStream, Encoding.UTF8);
              var stringreturn = cyphortReader.ReadToEnd();
              var cyphortReturn = JsonConvert.DeserializeObject<Object_Cyphort_Class.CyphortIncident>(stringreturn);
              if (cyphortReturn.Incident != null)
              {
                lFidoReturnValues.Cyphort.IncidentDetails = new Object_Cyphort_Class.CyphortIncident();
                lFidoReturnValues.Cyphort.IncidentDetails = cyphortReturn;
                if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_name != null)
                {
                  lFidoReturnValues.DNSName = lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_name.Replace(".", "(.)");  
                }
                

                if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Has_exploit == "1")
                {
                }

                if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Has_download == "1")
                {
                  lFidoReturnValues = FormatDownloadReturnValues(lFidoReturnValues);
                }

                if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Has_execution == "1")
                {
                }

                if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Has_infection == "1")
                {
                  lFidoReturnValues = FormatInfectionReturnValues(lFidoReturnValues);
                }

                if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Has_data_theft == "1")
                {
                }

                if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Has_file_submission == "1")
                {
                }
              }
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Cyphortv3 Detector getting json:" + e);
      }
    }

    private static FidoReturnValues FormatDownloadReturnValues(FidoReturnValues lFidoReturnValues)
    {
      lFidoReturnValues.Cyphort.DstIP = lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_ip;
      lFidoReturnValues.Cyphort.URL = new List<string>();
      lFidoReturnValues.Cyphort.MD5Hash = new List<string>();
      lFidoReturnValues.Cyphort.Domain = new List<string>();

      try
      {
        foreach (var download in lFidoReturnValues.Cyphort.IncidentDetails.Incident.DownloadArray)
        {
          if (!string.IsNullOrEmpty(download.Event_id)) lFidoReturnValues.Cyphort.EventID = download.Event_id;
          if (!string.IsNullOrEmpty(download.Event_id)) lFidoReturnValues.AlertID = download.Event_id;
          if (!string.IsNullOrEmpty(download.Source_url))
          {
            lFidoReturnValues.Cyphort.URL.Add(download.Source_url);
            lFidoReturnValues.Url = new List<string> {download.Source_url};
          }
          if (!string.IsNullOrEmpty(download.File_md5_string))
          {
            lFidoReturnValues.Cyphort.MD5Hash.Add(download.File_md5_string);
            lFidoReturnValues.Hash = new List<string> {download.File_md5_string};
          }
          if (download.Req_headers != null)
          {
            lFidoReturnValues.Cyphort.Domain.Add(download.Req_headers.Host);
            lFidoReturnValues.DNSName = download.Req_headers.Host.Replace(".", "(.)");
          }
          
          //Check to see if ID has been processed before
          var isRunDirector = false;
          lFidoReturnValues.PreviousAlerts = Matrix_Historical_Helper.GetPreviousMachineAlerts(lFidoReturnValues, false);
          if (lFidoReturnValues.PreviousAlerts.Alerts != null && lFidoReturnValues.PreviousAlerts.Alerts.Rows.Count > 0)
          {
            isRunDirector = PreviousAlert(lFidoReturnValues, lFidoReturnValues.Cyphort.EventID, lFidoReturnValues.Cyphort.EventTime);
          }
          if (isRunDirector || lFidoReturnValues.MalwareType.Contains("EICAR")) continue;
          //todo: build better filetype versus targetted OS, then remove this.
          lFidoReturnValues.IsTargetOS = true;
          Console.WriteLine(@"Processing download incident " + lFidoReturnValues.Cyphort.EventID + @" through to the Director.");
          TheDirector.Direct(lFidoReturnValues);
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Cyphortv3 download return:" + e);
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

    private static FidoReturnValues FormatInfectionReturnValues(FidoReturnValues lFidoReturnValues)
    {
      lFidoReturnValues.Cyphort.DstIP = lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_ip;
      lFidoReturnValues.Cyphort.Domain = new List<string>();
      lFidoReturnValues.Cyphort.URL = new List<string>();
      lFidoReturnValues.Cyphort.MD5Hash = new List<string>();

      try
      {
        foreach (var infection in lFidoReturnValues.Cyphort.IncidentDetails.Incident.InfectionArray)
        {
          lFidoReturnValues.Cyphort.EventID = infection.Infection_id;
          lFidoReturnValues.AlertID = infection.Infection_id;
          lFidoReturnValues.Cyphort.URL.Add(string.Empty);
          lFidoReturnValues.Cyphort.MD5Hash.Add(string.Empty);
          lFidoReturnValues.Cyphort.Domain.Add(infection.Cnc_servers);
          lFidoReturnValues.DNSName = infection.Cnc_servers.Replace(".", "(.)");

          var isRunDirector = false;
          //Check to see if ID has been processed before
          lFidoReturnValues.PreviousAlerts = Matrix_Historical_Helper.GetPreviousMachineAlerts(lFidoReturnValues, false);
          if (lFidoReturnValues.PreviousAlerts.Alerts != null && lFidoReturnValues.PreviousAlerts.Alerts.Rows.Count > 0)
          {
            isRunDirector = PreviousAlert(lFidoReturnValues, lFidoReturnValues.Cyphort.EventID, lFidoReturnValues.Cyphort.EventTime);
          }
          if (isRunDirector || lFidoReturnValues.MalwareType.Contains("EICAR")) continue;
          //todo: build better filetype versus targetted OS, then remove this.
          lFidoReturnValues.IsTargetOS = true;
          Console.WriteLine(@"Processing CNC incident " + lFidoReturnValues.Cyphort.EventID + @" through to the Director.");
          TheDirector.Direct(lFidoReturnValues);
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Cyphortv3 infection return:" + e);
      }


      return lFidoReturnValues;
    }
  }
}
