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
using Fido_Main.Fido_Support.ErrorHandling;
using Newtonsoft.Json;

namespace Fido_Main.Fido_Support.Objects.ThreatGRID
{
  internal class Object_ThreatGRID_IP_ConfigClass
  {

    public class ThreatGRID_IP_HLInfo
    {
      [JsonProperty("data")]
      internal ThreatGRID_IP_HLDetail Data_Array { get; set; }

      [JsonProperty("id")]
      internal string Id { get; set; }

      [JsonProperty("api_version")]
      internal string API_Version { get; set; }
    }

    internal class ThreatGRID_IP_HLDetail
    {
      [JsonProperty("ip")]
      internal string IP { get; set; }

      [JsonProperty("asn")]
      internal ThreatGRID_IP_ASNDetail ASN_Array { get; set; }

      [JsonProperty("location")]
      internal ThreatGRID_IP_Location Location_Array { get; set; }
    }

    internal class ThreatGRID_IP_ASNDetail
    {
      [JsonProperty("org")]
      internal string Org { get; set; }

      [JsonProperty("asn")]
      internal string ASN { get; set; }
    }

    internal class ThreatGRID_IP_Location
    {
      [JsonProperty("city")]
      internal string City { get; set; }

      [JsonProperty("region")]
      internal string Region { get; set; }

      [JsonProperty("country")]
      internal string Country { get; set; }
    }

    internal class ParseConfigs
    {
      internal Int16 PrimeKey { get; set; }
      internal string ApiCall { get; set; }
      internal string ApiBaseUrl { get; set; }
      internal string ApiFuncCall { get; set; }
      internal string ApiQueryString { get; set; }
      internal string ApiKey { get; set; }
    }

    internal static ParseConfigs FormatParse(DataTable dbReturn)
    {
      try
      {
        var reformat = new ParseConfigs
        {
          PrimeKey = Convert.ToInt16(dbReturn.Rows[0].ItemArray[0]),
          ApiCall = Convert.ToString(dbReturn.Rows[0].ItemArray[1]),
          ApiBaseUrl = Convert.ToString(dbReturn.Rows[0].ItemArray[2]),
          ApiFuncCall = Convert.ToString(dbReturn.Rows[0].ItemArray[3]),
          ApiQueryString = Convert.ToString(dbReturn.Rows[0].ItemArray[4]),
          ApiKey = Convert.ToString(dbReturn.Rows[0].ItemArray[5])
        };

        return reformat;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to format datatable return." + e);
      }
      return null;
    }
  }
}