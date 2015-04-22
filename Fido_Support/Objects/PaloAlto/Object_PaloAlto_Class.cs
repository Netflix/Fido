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
using Newtonsoft.Json;

namespace Fido_Main.Fido_Support.Objects.PaloAlto
{
  static class Object_PaloAlto_Class
  {
    
    public class GetJob
    {
      [JsonProperty("result")]
      internal GetResult Result { get; set; }
    }

    public class GetResult
    {
      [JsonProperty("job")]
      internal string Job { get; set; }
    }

    public class PanReturn
    {
      [JsonProperty("result")]
      internal Result Result { get; set; }
    }

    public class Result
    {
      [JsonProperty("log")]
      internal Log Log { get; set; }
    }

    public class Log
    {
      [JsonProperty("logs")]
      internal Logs Logs { get; set; }
    }

    public class Logs
    {
      [JsonProperty("entry")]
      internal Entries[] Entry { get; set; }
    }

    public class Entries
    {
      [JsonProperty("@logid")]
      internal string EventID { get; set; }

      [JsonProperty("receive_time")]
      internal DateTime ReceivedTime { get; set; }

      [JsonProperty("type")]
      internal string Type { get; set; }

      [JsonProperty("subtype")]
      internal string SubType { get; set; }

      [JsonProperty("src")]
      internal string SrcIP { get; set; }

      [JsonProperty("dst")]
      internal string DstIP { get; set; }

      [JsonProperty("dstuser")]
      internal string DstUser { get; set; }

      [JsonProperty("app")]
      internal string App { get; set; }

      [JsonProperty("sport")]
      internal string SourcePort { get; set; }

      [JsonProperty("dport")]
      internal string DestinationPort { get; set; }

      [JsonProperty("proto")]
      internal string Protocol { get; set; }

      [JsonProperty("severity")]
      internal string Severity { get; set; }

      [JsonProperty("direction")]
      internal string Direction { get; set; }

      [JsonProperty("misc")]
      internal string Misc { get; set; }
    }

  }
}
