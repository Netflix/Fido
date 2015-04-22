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
using System.IO;
using System.Net;
using System.Text;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.ThreatGRID;
using Newtonsoft.Json;
using Exception = System.Exception;

namespace Fido_Main.Director.Threat_Feeds
{
  static class Feeds_ThreatGRID
  {
    public static Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search SearchInfo(string sArtifact, bool bHash, Int16 iDays)
    {
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var ThreatGRIDReturn = new Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search();
      var request = Request(sArtifact, bHash, iDays);

      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      try
      {
        using (var ThreatGRIDResponse = alertRequest.GetResponse() as HttpWebResponse)
        {
          if (ThreatGRIDResponse != null && ThreatGRIDResponse.StatusCode == HttpStatusCode.OK)
          {
            using (var respStream = ThreatGRIDResponse.GetResponseStream())
            {
              if (respStream == null) return null;
              var ThreatGRIDReader = new StreamReader(respStream, Encoding.UTF8);
              var stringreturn = ThreatGRIDReader.ReadToEnd();
              ThreatGRIDReturn = JsonConvert.DeserializeObject<Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search>(stringreturn);
              ThreatGRIDResponse.Close();
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving ThreatGRID search information:" + e + "Query : " + request);
      }
      return ThreatGRIDReturn;
    }

    private static string Request(string sArtifact, bool bHash, Int16 iDays)
    {
      var parseConfigs = Object_ThreatGRID_Configs.GetThreatGridConfigs("search-level");
      var searchdate = DateTime.Now.AddDays(iDays);
      string request;
      if (bHash)
      {
        request = parseConfigs.ApiBaseUrl + parseConfigs.ApiFuncCall + "?checksum=" + sArtifact + parseConfigs.ApiQueryString + searchdate + "&api_key=" + parseConfigs.ApiKey;
      }
      else
      {
        request = parseConfigs.ApiBaseUrl + parseConfigs.ApiFuncCall + "?ip=" + sArtifact + parseConfigs.ApiQueryString + searchdate.ToShortDateString() + "&api_key=" + parseConfigs.ApiKey;
      }
      return request;
    }

    public static Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info ThreatInfo(string sHash)
    {
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var ThreatGRIDReturn = new Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info();
      var parseConfigs = Object_ThreatGRID_Configs.GetThreatGridConfigs("hash-threat-level");
      var request = parseConfigs.ApiBaseUrl + parseConfigs.ApiFuncCall + sHash + "/threat?" + parseConfigs.ApiQueryString + "&api_key=" + parseConfigs.ApiKey;
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      //alertRequest.Timeout = 120000;
      try
      {

        using (var ThreatGRIDResponse = alertRequest.GetResponse() as HttpWebResponse)
        {
          if (ThreatGRIDResponse != null && ThreatGRIDResponse.StatusCode == HttpStatusCode.OK)
          {
            using (var respStream = ThreatGRIDResponse.GetResponseStream())
            {
              if (respStream == null) return null;
              var ThreatGRIDReader = new StreamReader(respStream, Encoding.UTF8);
              var stringreturn = ThreatGRIDReader.ReadToEnd();
              ThreatGRIDReturn = JsonConvert.DeserializeObject<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>(stringreturn);
              ThreatGRIDResponse.Close();
              return ThreatGRIDReturn;
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving ThreatGRID threat information:" + e + "Query : " + request);
      }
      return ThreatGRIDReturn;
    }

    public static void ReportHTML(string sHash)
    {
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var parseConfigs = Object_ThreatGRID_Configs.GetThreatGridConfigs("report-level");
      var request = parseConfigs.ApiBaseUrl + parseConfigs.ApiFuncCall + sHash + "/report.html?" + parseConfigs.ApiQueryString + "&api_key=" + parseConfigs.ApiKey;
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      try
      {
        using (var ThreatGRIDResponse = alertRequest.GetResponse() as HttpWebResponse)
        {
          if (ThreatGRIDResponse != null && ThreatGRIDResponse.StatusCode == HttpStatusCode.OK)
          {
            using (var respStream = ThreatGRIDResponse.GetResponseStream())
            {
              if (respStream == null) return;
              //todo: move this to the DB
              using (var file = File.Create(Environment.CurrentDirectory + @"\reports\threatgrid\" + sHash + ".html"))
              {
                respStream.CopyTo(file);
              }
              ThreatGRIDResponse.Close();
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught downloading ThreatGRID report information:" + e);
      }
    }

    public static Object_ThreatGRID_IP_ConfigClass.ThreatGRID_IP_HLInfo HlInfo(string sIP)
    {
      Console.WriteLine(@"Gathering ThreatGRID IP information.");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var ThreatGRIDReturn = new Object_ThreatGRID_IP_ConfigClass.ThreatGRID_IP_HLInfo();
      var parseConfigs = Object_ThreatGRID_Configs.GetThreatGridConfigs("ip-high-level");
      var request = parseConfigs.ApiBaseUrl + parseConfigs.ApiFuncCall + sIP + "?" + parseConfigs.ApiQueryString + "&api_key=" + parseConfigs.ApiKey;
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      try
      {
        using (var ThreatGRIDResponse = alertRequest.GetResponse() as HttpWebResponse)
        {
          if (ThreatGRIDResponse != null && ThreatGRIDResponse.StatusCode == HttpStatusCode.OK)
          {
            using (var respStream = ThreatGRIDResponse.GetResponseStream())
            {
              if (respStream == null) return null;
              var ThreatGRIDReader = new StreamReader(respStream, Encoding.UTF8);
              var stringreturn = ThreatGRIDReader.ReadToEnd();
              ThreatGRIDReturn = JsonConvert.DeserializeObject<Object_ThreatGRID_IP_ConfigClass.ThreatGRID_IP_HLInfo>(stringreturn);
              ThreatGRIDResponse.Close();
              return ThreatGRIDReturn;
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving ThreatGRID IP information:" + e + "Query : " + request);
      }
      return ThreatGRIDReturn;
    }
  }
}
