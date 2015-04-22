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

namespace Fido_Main.Fido_Support.Objects.Carbon_Black
{
  static class Object_CarbonBlack_Inventory_Class
  {
    
    public class CarbonBlackEntry
    {
      [JsonProperty("os_environment_display_string")]
      internal string OSName { get; set; }

      [JsonProperty("supports_cblr")]
      internal string SupportsCBLR { get; set; }

      [JsonProperty("last_update")]
      internal DateTime LastUpdated { get; set; }

      [JsonProperty("build_id")]
      internal string BuildID { get; set; }

      [JsonProperty("is_isolating")]
      internal bool isIsolating { get; set; }

      [JsonProperty("computer_dns_name")]
      internal string HostDNSName { get; set; }

      [JsonProperty("id")]
      internal Int16 ID { get; set; }

      [JsonProperty("network_isolation_enabled")]
      internal bool NetworkIsolationEnabled { get; set; }

      [JsonProperty("status")]
      internal string Status { get; set; }

      [JsonProperty("sensor_health_message")]
      internal string SensorHealthMessage { get; set; }

      [JsonProperty("build_version_string")]
      internal string ClientVersion { get; set; }

      [JsonProperty("computer_sid")]
      internal string ComputerSID { get; set; }

      [JsonProperty("next_checkin_time")]
      internal DateTime NextCheckinTime { get; set; }

      [JsonProperty("node_id")]
      internal Int16 NodeID { get; set; }

      [JsonProperty("computer_name")]
      internal string HostName { get; set; }

      [JsonProperty("supports_isolation")]
      internal bool SupportsIso { get; set; }

      [JsonProperty("parity_host_id")]
      internal string ParityHostID { get; set; }

      [JsonProperty("network_adapters")]
      internal string NetworkAdapters { get; set; }

      [JsonProperty("sensor_health_status")]
      internal Int16 SensorHealthStatus { get; set; }

      [JsonProperty("restart_queued")]
      internal bool RestartQueued { get; set; }

      [JsonProperty("notes")]
      internal string Notes { get; set; }

      [JsonProperty("os_environment_id")]
      internal string OSEnvironmentID { get; set; }

      [JsonProperty("boot_id")]
      internal string BootID { get; set; }

      [JsonProperty("last_checkin_time")]
      internal DateTime LastCheckinTime { get; set; }

      [JsonProperty("group_id")]
      internal Int16 GroupdID { get; set; }

      [JsonProperty("display")]
      internal bool Display { get; set; }

      [JsonProperty("uninstall")]
      internal bool Uninstall { get; set; }
    }


  }
}
