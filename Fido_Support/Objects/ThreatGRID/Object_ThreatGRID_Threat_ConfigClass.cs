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

namespace Fido_Main.Fido_Support.Objects.ThreatGRID
{
  internal class Object_ThreatGRID_Threat_ConfigClass
  {
    public class ThreatGRID_Threat_Info
    {
      [JsonProperty("data")]
      internal ThreatGRID_Threat_Detail Data_Array { get; set; }

      [JsonProperty("id")]
      internal string Id { get; set; }

      [JsonProperty("api_version")]
      internal string API_Version { get; set; }
    }

    internal class ThreatGRID_Threat_Detail
    {
      [JsonProperty("sample")]
      internal string Sample { get; set; }

      [JsonProperty("score")]
      internal Int16 Score { get; set; }

      [JsonProperty("count")]
      internal Int16 Count { get; set; }

      [JsonProperty("max-confidence")]
      internal Int16 MaxConfidence { get; set; }

      [JsonProperty("max-severity")]
      internal Int16 MaxSeverity { get; set; }

      [JsonProperty("bis")]
      internal string[] BIS { get; set; }
    }
  }
}
