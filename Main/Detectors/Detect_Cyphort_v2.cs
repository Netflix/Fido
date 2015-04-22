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
using System.Net.Security;
using System.Text;
using Fido_Main.Director;
using Fido_Main.Director.Scoring;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using Newtonsoft.Json;

namespace Fido_Main.Main.Detectors
{
  public class Detect_Cyphort_v2
  {
    //This function will grab the API information and build a query string.
    //Then it will assign the json return to an object. If any of the objects
    //have a value they will be sent to ParseCyphort helper function.
    public static void GetCyphortAlerts()
    {
      Console.WriteLine(@"Running Cyphort v2 detector.");
      //currently needed to bypass site without a valid cert.
      //todo: make ssl bypass configurable
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
      
      var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs("cyphortv2");
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
              var cyphortReturn = JsonConvert.DeserializeObject<CyphortClass>(stringreturn);
              if (cyphortReturn.correlations_array.Any() | cyphortReturn.infections_array.Any() | cyphortReturn.downloads_array.Any())
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

    //Helper function to assign important values to FidoReturnValues objects and then
    //handoff to TheDirector for FIDO processing.
    private static void ParseCyphort(CyphortClass cyphortReturn)
    {
      try
      {
        if (cyphortReturn.correlations_array != null && cyphortReturn.correlations_array.Any())
        {
          cyphortReturn.correlations_array = cyphortReturn.correlations_array.Reverse().ToArray();
          for (var i = 0; i < cyphortReturn.correlations_array.Count(); i++)
          {
            Console.WriteLine(@"Processing correlation alert " + (i + 1).ToString(CultureInfo.InvariantCulture) + @" of " + cyphortReturn.correlations_array.Count().ToString(CultureInfo.InvariantCulture) + @".");
            var lFidoReturnValues = new FidoReturnValues();
            var isRunDirector = false;
            if (lFidoReturnValues.PreviousAlerts == null)
            {
              lFidoReturnValues.PreviousAlerts = new EventAlerts();
            }

            if (lFidoReturnValues.Cyphort == null)
            {
              lFidoReturnValues.Cyphort = new CyphortReturnValues();
            }
            if (cyphortReturn.correlations_array[i][4].Contains(":")) continue;
            lFidoReturnValues.SrcIP = cyphortReturn.correlations_array[i][4];
            lFidoReturnValues.MalwareType = cyphortReturn.correlations_array[i][19] + " and download";
            lFidoReturnValues.DstIP = cyphortReturn.correlations_array[i][16];
            lFidoReturnValues.Cyphort.DstIP = cyphortReturn.correlations_array[i][16];
            lFidoReturnValues.TimeOccurred = Convert.ToDateTime(cyphortReturn.correlations_array[i][2]).ToUniversalTime().ToString(CultureInfo.InvariantCulture);
            lFidoReturnValues.Cyphort.EventTime = Convert.ToDateTime(cyphortReturn.correlations_array[i][2]).ToUniversalTime().ToString(CultureInfo.InvariantCulture);
            lFidoReturnValues.Cyphort.EventID = cyphortReturn.correlations_array[i][1];
            lFidoReturnValues.AlertID = lFidoReturnValues.Cyphort.EventID;
            lFidoReturnValues.Cyphort.URL = new List<string> { cyphortReturn.correlations_array[i][12] };
            lFidoReturnValues.Url = new List<string> { cyphortReturn.correlations_array[i][12] };
            lFidoReturnValues.Cyphort.Domain = new List<string> { cyphortReturn.correlations_array[i][11] };
            lFidoReturnValues.Cyphort.MD5Hash = new List<string> { cyphortReturn.correlations_array[i][7] };
            lFidoReturnValues.Hash = new List<string> { cyphortReturn.correlations_array[i][7] };
            lFidoReturnValues.CurrentDetector = "cyphortv2";

            //Using the Hostname/SrcIP, check the FidoDB to see if any previous alerts were generated
            lFidoReturnValues.PreviousAlerts = Matrix_Historical_Helper.GetPreviousMachineAlerts(lFidoReturnValues, false);

            //If previous alerts were generated then run PreviousAlert to compare the AlertID of the newly generated
            //alert versus previous alerts.
            if (lFidoReturnValues.PreviousAlerts.Alerts != null && lFidoReturnValues.PreviousAlerts.Alerts.Rows.Count > 0)
            {
              isRunDirector = PreviousAlert(lFidoReturnValues);
            }

            //If the type of alert is a test alert then exit, or if the alert is has already been processed
            if (isRunDirector || lFidoReturnValues.MalwareType.Contains("VIRUS_EICAR_TEST_FILE.CY")) continue;
            //todo: build better filetype versus targetted OS, then remove this.
            lFidoReturnValues.IsTargetOS = true;
            TheDirector.Direct(lFidoReturnValues);
          }
        }

        if (cyphortReturn.downloads_array != null && cyphortReturn.downloads_array.Any())
        {
          cyphortReturn.downloads_array = cyphortReturn.downloads_array.Reverse().ToArray();
          for (var i = 0; i < cyphortReturn.downloads_array.Count(); i++)
          {
            Console.WriteLine(@"Processing download alert " + (i + 1).ToString(CultureInfo.InvariantCulture) + @" of " + cyphortReturn.downloads_array.Count().ToString(CultureInfo.InvariantCulture) + @".");
            var lFidoReturnValues = new FidoReturnValues();
            var isRunDirector = false;
            if (lFidoReturnValues.PreviousAlerts == null)
            {
              lFidoReturnValues.PreviousAlerts = new EventAlerts();
            }
            if (lFidoReturnValues.Cyphort == null)
            {
              lFidoReturnValues.Cyphort = new CyphortReturnValues();
            }
            if (cyphortReturn.downloads_array[i][4].Contains(":")) continue;
            lFidoReturnValues.SrcIP = cyphortReturn.downloads_array[i][4];
            lFidoReturnValues.MalwareType = cyphortReturn.downloads_array[i][20] + " download detected";
            lFidoReturnValues.DstIP = cyphortReturn.downloads_array[i][16];
            lFidoReturnValues.Cyphort.DstIP = cyphortReturn.downloads_array[i][16];
            lFidoReturnValues.TimeOccurred = Convert.ToDateTime(cyphortReturn.downloads_array[i][2]).ToString(CultureInfo.InvariantCulture);
            lFidoReturnValues.Cyphort.EventTime = Convert.ToDateTime(cyphortReturn.downloads_array[i][2]).ToString(CultureInfo.InvariantCulture);
            lFidoReturnValues.Cyphort.EventID = cyphortReturn.downloads_array[i][0];
            lFidoReturnValues.AlertID = lFidoReturnValues.Cyphort.EventID;
            lFidoReturnValues.Cyphort.URL = new List<string> {cyphortReturn.downloads_array[i][12]};
            lFidoReturnValues.Url = new List<string> {cyphortReturn.downloads_array[i][12]};
            lFidoReturnValues.Cyphort.Domain = new List<string> { cyphortReturn.downloads_array[i][11] };
            lFidoReturnValues.Cyphort.MD5Hash = new List<string> { cyphortReturn.downloads_array[i][7] };
            lFidoReturnValues.Hash = new List<string> { cyphortReturn.downloads_array[i][7] };
            lFidoReturnValues.CurrentDetector = "cyphortv2";
            lFidoReturnValues.PreviousAlerts = Matrix_Historical_Helper.GetPreviousMachineAlerts(lFidoReturnValues, false);
            if (lFidoReturnValues.PreviousAlerts.Alerts != null && lFidoReturnValues.PreviousAlerts.Alerts.Rows.Count > 0)
            {
              isRunDirector = PreviousAlert(lFidoReturnValues);
            }
            if (isRunDirector || lFidoReturnValues.MalwareType.Contains("VIRUS_EICAR_TEST_FILE.CY")) continue;
            //todo: build better filetype versus targetted OS, then remove this.
            lFidoReturnValues.IsTargetOS = true;
            TheDirector.Direct(lFidoReturnValues);
          }
        }

        if (cyphortReturn.infections_array != null && cyphortReturn.infections_array.Any())
        {
          cyphortReturn.infections_array = cyphortReturn.infections_array.Reverse().ToArray();
          for (var i = 0; i < cyphortReturn.infections_array.Count(); i++)
          {
            Console.WriteLine(@"Processing infection alert " + (i + 1).ToString(CultureInfo.InvariantCulture) + @" of " + cyphortReturn.infections_array.Count().ToString(CultureInfo.InvariantCulture) + @".");
            var lFidoReturnValues = new FidoReturnValues();
            var isRunDirector = false;
            if (lFidoReturnValues.PreviousAlerts == null)
            {
              lFidoReturnValues.PreviousAlerts = new EventAlerts();
            }

            if (lFidoReturnValues.Cyphort == null)
            {
              lFidoReturnValues.Cyphort = new CyphortReturnValues();
            }
            if (cyphortReturn.infections_array[i][4].Contains(":")) continue;
            lFidoReturnValues.SrcIP = cyphortReturn.infections_array[i][4];
            lFidoReturnValues.MalwareType = "C&C external communication detected";
            lFidoReturnValues.DstIP = cyphortReturn.infections_array[i][16];
            lFidoReturnValues.Cyphort.DstIP = cyphortReturn.infections_array[i][16];
            lFidoReturnValues.TimeOccurred = Convert.ToDateTime(cyphortReturn.infections_array[i][2]).ToString(CultureInfo.InvariantCulture);
            lFidoReturnValues.Cyphort.EventTime = Convert.ToDateTime(cyphortReturn.infections_array[i][2]).ToString(CultureInfo.InvariantCulture);
            lFidoReturnValues.Cyphort.EventID = cyphortReturn.infections_array[i][1];
            lFidoReturnValues.AlertID = lFidoReturnValues.Cyphort.EventID;
            lFidoReturnValues.Cyphort.URL = new List<string> { cyphortReturn.infections_array[i][12] };
            lFidoReturnValues.Url = new List<string> { cyphortReturn.infections_array[i][12] };
            lFidoReturnValues.Cyphort.Domain = new List<string> { cyphortReturn.infections_array[i][11] };
            lFidoReturnValues.Cyphort.MD5Hash = new List<string> { cyphortReturn.infections_array[i][7] };
            lFidoReturnValues.Hash = new List<string> { cyphortReturn.infections_array[i][7] };
            lFidoReturnValues.CurrentDetector = "cyphortv2";
            lFidoReturnValues.PreviousAlerts = Matrix_Historical_Helper.GetPreviousMachineAlerts(lFidoReturnValues, false);
            if (lFidoReturnValues.PreviousAlerts.Alerts != null && lFidoReturnValues.PreviousAlerts.Alerts.Rows.Count > 0)
            {
              isRunDirector = PreviousAlert(lFidoReturnValues);
            }
            if (isRunDirector || lFidoReturnValues.MalwareType.Contains("VIRUS_EICAR_TEST_FILE.CY")) continue;
            //todo: build better filetype versus targetted OS, then remove this.
            lFidoReturnValues.IsTargetOS = true;
            TheDirector.Direct(lFidoReturnValues);
          }

        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Cyphort Detector parse:" + e);
      }
    }

    private static bool PreviousAlert(FidoReturnValues lFidoReturnValues)
    {
      var isRunDirector = false;
      for (var j = 0; j < lFidoReturnValues.PreviousAlerts.Alerts.Rows.Count; j++)
      {
        if (lFidoReturnValues.PreviousAlerts.Alerts.Rows[j][6].ToString() == lFidoReturnValues.AlertID)
        {
          isRunDirector = true;
        }
      }
      return isRunDirector;
    }

    private static bool TargetOSFileType(string[] cyphortArray)
    {
      if (cyphortArray != null && cyphortArray.Any())
      {
        if (cyphortArray[6].ToLower().Contains("macos"))
        {
          if (cyphortArray[14].ToLower().Contains("dmg"))
          {
            return true;
          }
          if (cyphortArray[14].ToLower().Contains("zip"))
          {
            return true;
          }
        }
        else if (cyphortArray[6].ToLower().Contains("windows"))
        {
          if (cyphortArray[14].ToLower().Contains("pe32"))
          {
            return true;
          }
          if (cyphortArray[14].ToLower().Contains("zip"))
          {
            return true;
          }
          if (cyphortArray[14].ToLower().Contains("mach-o"))
          {
            return true;
          }
          if (cyphortArray[14].ToLower().Contains("ascii"))
          {
            return true;
          }
        }
        else if (cyphortArray[6].ToLower().Contains("linux"))
        {
          return false;
        }
        else if (cyphortArray[6].ToLower().Contains("unknown"))
        {
          return true;
        }

      }
      return true;
    }

    private class CyphortClass
    {
      public int first_dummy_value { get; set; }
      public string[][] downloads_array { get; set; }
      public string[][] correlations_array { get; set; }
      public string[][] infections_array { get; set; }

    }
  }
}
