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

using System.Collections.Generic;
using Newtonsoft.Json;

namespace Fido_Main.Fido_Support.Objects.Carbon_Black
{
  class Object_CarbonBlack_Alert_Class
  {

    public class CarbonBlack
    {
      [JsonProperty("start")]
      public int Start { get; set; }

      [JsonProperty("total_results")]
      public int Total_Results { get; set; }

      [JsonProperty("results")]
      public List<Result> Results { get; set; }
    }

    internal class Result
    {
      [JsonProperty("username")]
      internal string Username { get; set; }

      [JsonProperty("alert_type")]
      internal string AlertType { get; set; }
      
      [JsonProperty("sensor_criticality")]
      internal double SensorCriticality { get; set; }
      
      [JsonProperty("modload_count")]
      internal int ModloadCount { get; set; }

      [JsonProperty("observed_filename")]
      internal List<string> ObservedFilename { get; set; }

      [JsonProperty("report_score")]
      internal int ReportScore { get; set; }
      
      [JsonProperty("watchlist_id")]
      internal string WatchlistID { get; set; }
      
      [JsonProperty("sensor_id")]
      internal int SensorID { get; set; }
      
      [JsonProperty("created_time")]
      internal string CreatedTime { get; set; }
      
      [JsonProperty("ioc_type")]
      internal string IOCType { get; set; }
      
      [JsonProperty("watchlist_name")]
      internal string WatchlistName { get; set; }
      
      [JsonProperty("ioc_confidence")]
      internal double IOCConfidence { get; set; }
      
      [JsonProperty("alert_severity")]
      internal double AlertSeverity { get; set; }
      
      [JsonProperty("crossproc_count")]
      internal int CrossprocCount { get; set; }
      
      [JsonProperty("group")]
      internal string Group { get; set; }
      
      [JsonProperty("hostname")]
      internal string Hostname { get; set; }
      
      [JsonProperty("filemod_count")]
      internal int FilemodCount { get; set; }
      
      [JsonProperty("feed_name")]
      internal string FeedName { get; set; }
      
      [JsonProperty("netconn_count")]
      internal int NetconnCount { get; set; }
      
      [JsonProperty("status")]
      internal string Status { get; set; }
      
      [JsonProperty("observed_hosts")]
      internal ObservedHosts ObservedHosts { get; set; }
      
      [JsonProperty("process_path")]
      internal string ProcessPath { get; set; }
      
      [JsonProperty("process_name")]
      internal string ProcessName { get; set; }
      
      [JsonProperty("process_id")]
      internal string ProcessId { get; set; }
      
      [JsonProperty("_version_")]
      internal object Version { get; set; }
      
      [JsonProperty("regmod_count")]
      internal int RegmodCount { get; set; }
      
      [JsonProperty("md5")]
      internal string MD5 { get; set; }
      
      [JsonProperty("segment_id")]
      internal int SegmentID { get; set; }
      
      [JsonProperty("total_hosts")]
      internal string TotalHosts { get; set; }
      
      [JsonProperty("feed_id")]
      internal int FeedID { get; set; }
      
      [JsonProperty("os_type")]
      internal string OSType { get; set; }
      
      [JsonProperty("childproc_count")]
      internal int ChildprocCount { get; set; }
      
      [JsonProperty("unique_id")]
      internal string UniqueID { get; set; }

      [JsonProperty("feed_rating")]
      internal double FeedRating { get; set; }
    }

    internal class ObservedHosts
    {
      [JsonProperty("numFound")]
      internal int NumFound { get; set; }

      [JsonProperty("hostCount")]
      internal int HostCount { get; set; }

      [JsonProperty("globalCount")]
      internal int GlobalCount { get; set; }

      [JsonProperty("hostnames")]
      internal List<Hostnames> Hostnames { get; set; }

      [JsonProperty("processCount")]
      internal int ProcessCount { get; set; }

      [JsonProperty("numDocs")]
      internal string NumDocs { get; set; }

      [JsonProperty("processTotal")]
      internal int ProcessTotal { get; set; }
    }

    internal class Hostnames
    {
      [JsonProperty("name")]
      internal string Name { get; set; }

      [JsonProperty("value")]
      internal int Value { get; set; }
    }
  }
}
