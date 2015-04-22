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
using System.Data;
using System.IO;
using System.Net;
using System.Text;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.FidoDB;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.Carbon_Black;
using Newtonsoft.Json;

namespace Fido_Main.Director.SysMgmt
{
  class SysMgmt_CarbonBlack
  {
    public static Object_CarbonBlack_Inventory_Class.CarbonBlackEntry GetCarbonBlackHost(FidoReturnValues lFidoReturnValues, bool isHostname)
    {
      Console.WriteLine(@"Gathering inventory data from Carbon Black.");
      //currently needed to bypass site without a valid cert.
      //todo: make ssl bypass configurable
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
      var parseConfigs = new ParseCBConfigs();
      parseConfigs = ParseDetectorConfigs(isHostname ? "get_host_by_name" : "get_host_by_ip");
      var request = string.Empty;
      if (isHostname)
      {
        request = parseConfigs.BaseURL + parseConfigs.APIFunction + parseConfigs.APIQuery + lFidoReturnValues.Hostname;
      }
      else
      {
        request = parseConfigs.BaseURL + parseConfigs.APIFunction + parseConfigs.APIQuery + lFidoReturnValues.SrcIP;  
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
              if (respStream == null) return null;
              var cbReader = new StreamReader(respStream, Encoding.UTF8);
              var stringreturn = cbReader.ReadToEnd();
              if (stringreturn == "[]") return null;
              var cbTempReturn = JsonConvert.DeserializeObject<Object_CarbonBlack_Inventory_Class.CarbonBlackEntry[]>(stringreturn);
              var cbLastRun = cbTempReturn[0].LastUpdated;
              var cbReturn = new Object_CarbonBlack_Inventory_Class.CarbonBlackEntry();
              foreach (var entry in cbTempReturn)
              {
                if (entry.LastUpdated >= cbLastRun)
                {
                  cbReturn = entry;
                }
              }

              var responseStream = cbResponse.GetResponseStream();
              if (responseStream != null) responseStream.Dispose();
              cbResponse.Close();
              Console.WriteLine(@"Finished retreiving CB inventory.");
              return cbReturn;
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Carbon Black sysmgmt area:" + e);
      }

      return null;
    }

    private static ParseCBConfigs ParseDetectorConfigs(string detect)
    {
      //todo: move this to the database, assign a variable to 'detect' and replace being using in GEtFidoConfigs
      var query = @"SELECT * from configs_sysmgmt_carbonblack WHERE api_call = '" + detect + @"'";

      var fidoSQlite = new SqLiteDB(); 
      var fidoData = new DataTable();
      var cbReturn = new ParseCBConfigs();
      try
      {
        fidoData = fidoSQlite.GetDataTable(query);
        cbReturn = CBConfigs(fidoData);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to format datatable return." + e);
      }
      return cbReturn;
    }

    private static ParseCBConfigs CBConfigs(DataTable cbData)
    {
      try
      {
        var reformat = new ParseCBConfigs
        {
          APIKey = Convert.ToString(cbData.Rows[0].ItemArray[1]),
          BaseURL = Convert.ToString(cbData.Rows[0].ItemArray[2]),
          APICall = Convert.ToString(cbData.Rows[0].ItemArray[3]),
          APIFunction = Convert.ToString(cbData.Rows[0].ItemArray[4]),
          APIQuery = Convert.ToString(cbData.Rows[0].ItemArray[5])
        };

        return reformat;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to format datatable return." + e);
      }
      return null;
    }

    private class ParseCBConfigs
    {
      internal string APIKey { get; set; }
      internal string BaseURL { get; set; }
      internal string APICall { get; set; }
      internal string APIFunction { get; set; }
      internal string APIQuery { get; set; }
    }


  }

}
