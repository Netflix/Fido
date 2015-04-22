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

using Newtonsoft.Json;

namespace Fido_Main.Fido_Support.Objects.ThreatGRID
{
  public static class Object_ThreatGRID_Search_ConfigClass
  {
    public class ThreatGRID_Search
    {
      [JsonProperty("data")]
      internal ThreatGRID_Search_Detail Data { get; set; }

      [JsonProperty("id")]
      internal string Id { get; set; }

      [JsonProperty("api_version")]
      internal string API_Version { get; set; }
    }

    public class ThreatGRID_Search_Detail
    {
      [JsonProperty("index")]
      internal string Index { get; set; }

      [JsonProperty("current_item_count")]
      internal string CurrentItemCount { get; set; }

      [JsonProperty("items_per_page")]
      internal string ItemsPerPage { get; set; }

      [JsonProperty("items")]
      internal ThreatGRID_Search_Item_Detail[] Items { get; set; }
    }

    public class ThreatGRID_Search_Item_Detail
    {
      [JsonProperty("data")]
      internal Search_Data_Detail DataDetail { get; set; }

      [JsonProperty("relation")]
      internal string Relation { get; set; }

      [JsonProperty("ip")]
      internal string CIDR { get; set; }

      [JsonProperty("ts")]
      internal string TimeStamp { get; set; }

      [JsonProperty("sample")]
      internal string HashID { get; set; }
    }

    public class Search_Data_Detail
    {
      [JsonProperty("network-streams")]
      internal Search_Data_NetworkStreams[] NetworkStreams { get; set; }

      [JsonProperty("queries")]
      internal Search_Data_DNS_Query[] DNSQueries { get; set; }

    }

    public class Search_Data_NetworkStreams
    {
      [JsonProperty("dst_port")]
      internal string DSTPort { get; set; }

      [JsonProperty("src_port")]
      internal string SRCPort { get; set; }
    }

    public class Search_Data_DNS_Query
    {
      [JsonProperty("query")]
      internal string DNSQuery { get; set; }

      [JsonProperty("type")]
      internal string RecordType { get; set; }
    }

  }
}