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
using System.Net;
using System.Net.Security;
using System.Text;
using System.Threading;
using System.Xml;
using Fido_Main.Director;
using Fido_Main.Director.Scoring;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.PaloAlto;
using Newtonsoft.Json;
using Formatting = Newtonsoft.Json.Formatting;

namespace Fido_Main.Main.Detectors
{
  static class Detect_PaloAlto
  {
    
    public static void GetPANJob()
    {
      Console.WriteLine(@"Running PAN v1 detector.");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate { return true; });
      
      var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs("panv1");
      var request = parseConfigs.Server + parseConfigs.Query + parseConfigs.APIKey;
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      try
      {
        using (var panResponse = alertRequest.GetResponse() as HttpWebResponse)
        {
          if (panResponse != null && panResponse.StatusCode == HttpStatusCode.OK)
          {
            using (var respStream = panResponse.GetResponseStream())
            {
              if (respStream == null) return;
              var panReader = new StreamReader(respStream, Encoding.UTF8);
              var stringreturn = panReader.ReadToEnd();

              if (stringreturn.TrimStart().StartsWith("<"))
              {
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(stringreturn);
                stringreturn = JsonConvert.SerializeXmlNode(doc, Formatting.None, true);
              }
              var panReturn = JsonConvert.DeserializeObject<Object_PaloAlto_Class.GetJob>(stringreturn);
              if (string.IsNullOrEmpty(panReturn.Result.Job)) return;
              //We need to let the PAN finish processing the request before trying to pull the report
              Thread.Sleep(10000);
              RunPANJob(panReturn.Result.Job);
              Console.WriteLine(@"Finished processing PAN v1 detector.");
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in PAN v1 Detector getting json:" + e);
      }
    }

    public static void RunPANJob(string jobID)
    {
      Console.WriteLine(@"Running PAN job " + jobID + @".");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate { return true; });

      var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs("panv1");
      var request = parseConfigs.Server + parseConfigs.Query2 + parseConfigs.APIKey;
      request = request.Replace("%jobid%", jobID);
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Timeout = 180000;
      alertRequest.Method = "GET";
      try
      {
        using (var panResponse = alertRequest.GetResponse() as HttpWebResponse)
        {
          if (panResponse != null && panResponse.StatusCode == HttpStatusCode.OK)
          {
            using (var respStream = panResponse.GetResponseStream())
            {
              if (respStream == null) return;
              var panReader = new StreamReader(respStream, Encoding.UTF8);
              var stringreturn = panReader.ReadToEnd();

              if (stringreturn.TrimStart().StartsWith("<"))
              {
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(stringreturn);
                stringreturn = JsonConvert.SerializeXmlNode(doc, Formatting.None, true);
              }
              var panReturn = JsonConvert.DeserializeObject<Object_PaloAlto_Class.PanReturn>(stringreturn);
              if ((panReturn == null) || (panReturn.Result.Log.Logs.Entry == null)) return;
              ParsePan(panReturn);
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in PAN v1 Detector getting json:" + e);
      }
    }

    private static void ParsePan(Object_PaloAlto_Class.PanReturn panReturn)
    {
      try
      {
        foreach (var entry in panReturn.Result.Log.Logs.Entry)
        {
          if (entry.App == "dns") continue;

          Console.WriteLine(@"Processing PAN " + entry.SubType + @" event.");

          //initialize generic variables for PAN values
          var lFidoReturnValues = new FidoReturnValues();
          if (lFidoReturnValues.PreviousAlerts == null)
          {
            lFidoReturnValues.PreviousAlerts = new EventAlerts();
          }

          if (lFidoReturnValues.PaloAlto == null)
          {
            lFidoReturnValues.PaloAlto = new PaloAltoReturnValues();
          }

          //Convert PAN classifications to more readable values
          lFidoReturnValues.MalwareType = entry.Type + " " + entry.SubType;
          lFidoReturnValues.CurrentDetector = "panv1";
          lFidoReturnValues.PaloAlto.EventID = entry.EventID;
          lFidoReturnValues.AlertID = entry.EventID;
          if (entry.Direction == "client-to-server")
          {
            lFidoReturnValues.PaloAlto.isDst = true;
          }
          else
          {
            lFidoReturnValues.PaloAlto.isDst = false;
          }

          if (lFidoReturnValues.PaloAlto.isDst)
          {
            lFidoReturnValues.SrcIP = entry.SrcIP;
            lFidoReturnValues.DstIP = entry.DstIP;
            lFidoReturnValues.PaloAlto.DstIp = entry.DstIP;
          }
          else
          {
            lFidoReturnValues.SrcIP = entry.DstIP;
            lFidoReturnValues.DstIP = entry.SrcIP;
            lFidoReturnValues.PaloAlto.DstIp = entry.SrcIP;
          }

          if (!string.IsNullOrEmpty(entry.DstUser))
          {
            lFidoReturnValues.PaloAlto.DstUser = entry.DstUser.Replace(@"corp\", string.Empty);
            lFidoReturnValues.Username = entry.DstUser;
          }


          lFidoReturnValues.PaloAlto.EventTime = entry.ReceivedTime.ToString(CultureInfo.InvariantCulture);
          lFidoReturnValues.TimeOccurred = entry.ReceivedTime.ToString(CultureInfo.InvariantCulture);

          var isRunDirector = false;
          //Check to see if ID has been processed before
          lFidoReturnValues.PreviousAlerts = Matrix_Historical_Helper.GetPreviousMachineAlerts(lFidoReturnValues, false);
          if (lFidoReturnValues.PreviousAlerts.Alerts != null && lFidoReturnValues.PreviousAlerts.Alerts.Rows.Count > 0)
          {
            isRunDirector = PreviousAlert(lFidoReturnValues, lFidoReturnValues.PaloAlto.EventID, lFidoReturnValues.PaloAlto.EventTime);
          }
          if (isRunDirector || lFidoReturnValues.MalwareType.Contains("EICAR")) continue;
          //todo: build better filetype versus targetted OS, then remove this.
          lFidoReturnValues.IsTargetOS = true;
          Console.WriteLine(@"Processing PAN incident " + lFidoReturnValues.PaloAlto.EventID + @" through to the Director.");
          TheDirector.Direct(lFidoReturnValues);

        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in PANv1 Detector parse:" + e);
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

  }
}
