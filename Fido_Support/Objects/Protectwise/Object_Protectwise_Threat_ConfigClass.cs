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

namespace Fido_Main.Fido_Support.Objects.ProtectWise
{
  internal class Object_ProtectWise_Threat_ConfigClass
  {

    public class ProtectWise_Events
    {
      [JsonProperty("events")]
      internal ProtectWise_Search_Event[] Events { get; set; }
    }

    public class ProtectWise_Search_Event
    {
      [JsonProperty("cid")]
      internal Int16 Cid { get; set; }

      [JsonProperty("agentId")]
      internal int AgentID { get; set; }

      [JsonProperty("id")]
      internal string Id { get; set; }

      [JsonProperty("type")]
      internal string Type { get; set; }

      [JsonProperty("message")]
      internal string Message { get; set; }

      [JsonProperty("observations")]
      internal ProtectWise_Observation[] Observations { get; set; }

      [JsonProperty("netflows")]
      internal ProtectWise_Netflow[] Netflow { get; set; }

      [JsonProperty("confidence")]
      internal Int16 Confidence { get; set; }

      [JsonProperty("threatScore")]
      internal Int16 ThreatScore { get; set; }

      [JsonProperty("threatLevel")]
      internal string ThreatLevel { get; set; }

      [JsonProperty("killChainStage")]
      internal string KillChainStage { get; set; }

      [JsonProperty("category")]
      internal string Category { get; set; }

      [JsonProperty("threatSubCategory")]
      internal string ThreatSubCategory { get; set; }

      [JsonProperty("observationCount")]
      internal Int16 ObservationCount { get; set; }

      [JsonProperty("netflowCount")]
      internal Int16 NetflowCount { get; set; }

    }
    public class ProtectWise_Observation
    {
      [JsonProperty("agentId")]
      internal string AgentID { get; set; }

      [JsonProperty("flowId")]
      internal ProtectWise_Flow_Detail Flow { get; set; }

      [JsonProperty("data")]
      internal ProtectWise_Data Data { get; set; }

      [JsonProperty("occurredAt")]
      internal string EventTime { get; set; }

      [JsonProperty("observedAt")]
      internal string ObservedTime { get; set; }

      [JsonProperty("threatLevel")]
      internal string ThreatLevel { get; set; }

      [JsonProperty("confidence")]
      internal Int16 Confidence { get; set; }

      [JsonProperty("killChainStage")]
      internal string KillChainStage { get; set; }

      [JsonProperty("severity")]
      internal Int16 Severity { get; set; }

      [JsonProperty("category")]
      internal string Category { get; set; }

      [JsonProperty("threatScore")]
      internal Int16 ThreatScore { get; set; }

      //[JsonProperty("cid")]

      [JsonProperty("observedStage")]
      internal string ObservedStage { get; set; }

      [JsonProperty("source")]
      internal string Source { get; set; }

      [JsonProperty("id")]
      internal string EventID { get; set; }

      [JsonProperty("threatSubCategory")]
      internal string ThreatSubCategory { get; set; }
    }

    internal class ProtectWise_Netflow
    {
      [JsonProperty("details")]
      internal ProtectWise_Flow_Details FlowDetails { get; set; }

      [JsonProperty("id")]
      internal ProtectWise_Flow_IP Id { get; set; }
      
      [JsonProperty("geo")]
      internal ProtectWise_GEO GEO { get; set; }
    }

    internal class ProtectWise_Flow_Details
    {
      [JsonProperty("startTime")]
      internal double StartTime { get; set; }

      [JsonProperty("isEncrypted")]
      internal bool isEncrypted { get; set; }

    }

    internal class ProtectWise_Flow_IP
    {
      [JsonProperty("srcMac")]
      internal string SrcMAC { get; set; }

      [JsonProperty("dstMac")]
      internal string DstMAC { get; set; }

      [JsonProperty("srcIP")]
      internal string SrcIP { get; set; }

      [JsonProperty("dstIP")]
      internal string DstIP { get; set; }

      [JsonProperty("srcPort")]
      internal string SrcPort { get; set; }

      [JsonProperty("dstPort")]
      internal string DstPort { get; set; }

    }

    public class ProtectWise_Flow_Detail
    {
      [JsonProperty("key")]
      internal String Key { get; set; }

      [JsonProperty("startTime")]
      internal String StartTime { get; set; }

      [JsonProperty("ip")]
      internal ProtectWise_IP IP { get; set; }

    }

    public class ProtectWise_IP
    {
      [JsonProperty("srcMac")]
      internal string SrcMAC { get; set; }

      [JsonProperty("dstMac")]
      internal string DstMAC { get; set; }

      [JsonProperty("srcIp")]
      internal string SrcIP { get; set; }

      [JsonProperty("dstIp")]
      internal string DstIP { get; set; }

      [JsonProperty("srcPort")]
      internal string SrcPort { get; set; }

      [JsonProperty("dstPort")]
      internal string DstPort { get; set; }

      [JsonProperty("proto")]
      internal string Protocol { get; set; }
      
    }

    public class ProtectWise_Data
    {
      [JsonProperty("idsEvent")]
      internal ProtectWise_IDS_Event IdsEvent { get; set; }

      [JsonProperty("protocol")]
      internal string Protocol { get; set; }
      
      [JsonProperty("ipReputation")]
      internal ProtectWise_IP_Reputation Ip_Reputation { get; set; }

      [JsonProperty("httpRequest")]
      internal string HttpReq { get; set; }

      [JsonProperty("urlReputation")]
      internal ProtectWise_URL_Reputation URL_Reputation { get; set; }

      [JsonProperty("fileReputation")]
      internal string File_Reputation { get; set; }

      [JsonProperty("file")]
      internal string File { get; set; }

      [JsonProperty("dns")]
      internal string DNS { get; set; }

      [JsonProperty("dnsReputation")]
      internal string DNS_Reputation { get; set; }
    }

    public class ProtectWise_IDS_Event
    {
      [JsonProperty("timestampSeconds")]
      internal string TimeStampSeconds { get; set; }

      [JsonProperty("classification")]
      internal string Classification { get; set; }

      [JsonProperty("description")]
      internal string Description { get; set; }
    }

    public class ProtectWise_URL_Reputation
    {
      [JsonProperty("url")]
      internal string Url { get; set; }

      [JsonProperty("category")]
      internal string Category { get; set; }

      [JsonProperty("partnerCategory")]
      internal string PartnerCategory { get; set; }

      [JsonProperty("urlData")]
      internal string UrlData { get; set; }

    }

    public class ProtectWise_IP_Reputation
    {
      [JsonProperty("ip")]
      internal string IP { get; set; }

      [JsonProperty("category")]
      internal string Category { get; set; }

      [JsonProperty("partnerCategory")]
      internal string PartnerCategory { get; set; }
    }

    public class ProtectWise_GEO
    {
      [JsonProperty("src")]
      internal ProtectWise_Destination Destination { get; set; }

    }

    public class ProtectWise_Destination
    {
      [JsonProperty("continent")]
      internal ProtectWise_Destination_Continent Continent { get; set; }

      [JsonProperty("country")]
      internal ProtectWise_Destination_Country Country { get; set; }

      [JsonProperty("postal")]
      internal ProtectWise_Destination_Postal Postal { get; set; }

      [JsonProperty("city")]
      internal ProtectWise_Destination_City City { get; set; }

      [JsonProperty("organization")]
      internal string Organization { get; set; }

    }

    public class ProtectWise_Destination_Continent
    {
      [JsonProperty("confidence")]
      internal string Confidence { get; set; }

      [JsonProperty("code")]
      internal string CountryCode { get; set; }

      [JsonProperty("name")]
      internal string Name { get; set; }
    }

    public class ProtectWise_Destination_Country
    {
      [JsonProperty("confidence")]
      internal string Confidence { get; set; }

      [JsonProperty("isoCode")]
      internal string IsoCode { get; set; }

      [JsonProperty("name")]
      internal string Name { get; set; }
    }

    public class ProtectWise_Destination_Postal
    {
      [JsonProperty("code")]
      internal string Code { get; set; }

      [JsonProperty("confidence")]
      internal string Confidence { get; set; }
    }

    public class ProtectWise_Destination_City
    {
      [JsonProperty("confidence")]
      internal string Confidence { get; set; }

      [JsonProperty("isoCode")]
      internal string IsoCode { get; set; }

      [JsonProperty("name")]
      internal string Name { get; set; }
    }
  }
}