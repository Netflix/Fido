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
using System.Data;
using Fido_Main.Fido_Support.Objects.Carbon_Black;
using Fido_Main.Fido_Support.Objects.Cyphort;
using Fido_Main.Fido_Support.Objects.ProtectWise;
using Fido_Main.Fido_Support.Objects.VirusTotal;
using Fido_Main.Fido_Support.Objects.ThreatGRID;
using VirusTotalNET.Objects;

namespace Fido_Main.Fido_Support.Objects.Fido
{
  //This is the primary object used throughout FIDO to support
  //the assembly line methodology.
  public class FidoReturnValues
  {
    internal LandeskReturnValues Landesk { get; set; }
    internal JamfReturnValues Jamf { get; set; }
    internal CarbonBlackReturnValues CB { get; set; }
    internal UserReturnValues UserInfo { get; set; }
    internal FireEyeReturnValues FireEye { get; set; }
    internal Bit9ReturnValues Bit9 { get; set; }
    internal AntivirusReturnValues Antivirus { get; set; }
    internal CyphortReturnValues Cyphort { get; set; }
    internal ProtectWiseReturnValues ProtectWise { get; set; }
    internal PaloAltoReturnValues PaloAlto { get; set; }
    internal EventAlerts PreviousAlerts { get; set; }
    internal HistoricalEvents HistoricalEvent { get; set; }
    internal bool isBinary { get; set; }
    internal bool IsHostKnown { get; set; }
    internal bool IsReboot { get; set; }
    internal bool IsPatch { get; set; }
    internal bool IsPreviousAlert { get; set; }
    internal bool IsMachSeenBefore { get; set; }
    internal bool IsUserSeenBefore { get; set; }
    internal bool IsUrlSeenBefore { get; set; }
    internal bool IsIPSeenBefore { get; set; }
    internal bool IsHashSeenBefore { get; set; }
    internal bool IsPCI { get; set; }
    internal bool IsSendAlert { get; set; }
    internal bool IsTargetOS { get; set; }
    internal bool IsTest { get; set; }
    internal string MalwareType { get; set; }
    internal string RemoteRegHostname { get; set; }
    internal string SSHHostname { get; set; }
    internal string NmapHostname { get; set; }
    internal string SrcIP { get; set; }
    internal string DstIP { get; set; }
    internal string DNSName { get; set; }
    internal List<string> Url { get; set; }
    internal List<string> Hash { get; set; }
    internal string TimeOccurred { get; set; }
    internal string Hostname { get; set; }
    internal string Username { get; set; }
    internal string SummaryEmail { get; set; }
    internal string MachineType { get; set; }
    internal string CurrentDetector { get; set; }
    internal string AlertID { get; set; }
    internal double TotalScore { get; set; }
    internal double ThreatScore { get; set; }
    internal double MachineScore { get; set; }
    internal double UserScore { get; set; }
    internal double BadUrLs { get; set; }
    internal double BadHashs { get; set; }
    internal double BadDetectedComms { get; set; }
    internal double BadDetectedDownloads { get; set; }
    internal double BadDetectedUrls { get; set; }
    internal List<string> Recommendation { get; set; }
    internal List<string> Actions { get; set; }
    internal List<string> Detectors { get; set; }
  }

  internal class FireEyeReturnValues
  {
    internal string EventTime { get; set; }
    internal string DstIP { get; set; }
    internal List<string> URL { get; set; }
    internal List<string> MD5Hash { get; set; }
    internal List<string> ChannelHost { get; set; }
    internal string Referer { get; set; }
    internal string Original { get; set; }
    internal string HttpHeader { get; set; }
    internal bool IsFireEye { get; set; }
    internal VirusTotalReturnValues VirusTotal { get; set; }
    internal ThreatGRIDReturnValues ThreatGRID { get; set; }
    internal AlienVaultReturnValues AlienVault { get; set; }
    internal Bit9ReturnValues Bit9 { get; set; }
  }

  internal class CyphortReturnValues
  {
    internal string EventTime { get; set; }
    internal string DstIP { get; set; }
    internal string EventID { get; set; }
    internal string IncidentID { get; set; }
    internal List<string> MD5Hash { get; set; }
    internal List<string> URL { get; set; }
    internal List<string> Domain { get; set; }
    internal VirusTotalReturnValues VirusTotal { get; set; }
    internal ThreatGRIDReturnValues ThreatGRID { get; set; }
    internal AlienVaultReturnValues AlienVault { get; set; }
    internal Bit9ReturnValues Bit9 { get; set; }
    internal Object_Cyphort_Class.CyphortIncident IncidentDetails { get; set; }
    internal string CyphortJson { get; set; }
  }

  internal class ProtectWiseReturnValues
  {
    internal string ProtectWiseType { get; set; }
    internal string EventTime { get; set; }
    internal string DstIP { get; set; }
    internal string EventID { get; set; }
    internal string MD5 { get; set; }
    internal string URL { get; set; }
    internal VirusTotalReturnValues VirusTotal { get; set; }
    internal ThreatGRIDReturnValues ThreatGRID { get; set; }
    internal AlienVaultReturnValues AlienVault { get; set; }
    internal Bit9ReturnValues Bit9 { get; set; }
    internal Object_ProtectWise_Threat_ConfigClass.ProtectWise_Observation IncidentDetails { get; set; }
    internal Object_ProtectWise_Threat_ConfigClass.ProtectWise_GEO GEO { get; set; }
    internal Object_ProtectWise_Threat_ConfigClass.ProtectWise_Search_Event EventDetails { get; set; }
    internal string ProtectWiseJson { get; set; }
  }

  internal class PaloAltoReturnValues
  {
    internal string EventTime { get; set; }
    internal string EventID { get; set; }
    internal string DstIp { get; set; }
    internal string Url { get; set; }
    internal string DstUser { get; set; }
    internal bool isDst { get; set; }
    internal VirusTotalReturnValues VirusTotal { get; set; }
    internal ThreatGRIDReturnValues ThreatGRID { get; set; }
    internal AlienVaultReturnValues AlienVault { get; set; }
    internal string PANJson { get; set; }
  }

  internal class AntivirusReturnValues
  {
    internal string ReceivedTime { get; set; }
    internal string EventTime { get; set; }
    internal string ActionTaken { get; set; }
    internal string Username { get; set; }
    internal string Status { get; set; }
    internal string ThreatType { get; set; }
    internal string FilePath { get; set; }
    internal string FileName { get; set; }
    internal string HostName { get; set; }
    internal string ThreatName { get; set; }
    internal Bit9ReturnValues Bit9 { get; set; }
  }

  internal class Bit9ReturnValues
  {
    internal bool IsBit9 { get; set; }
    internal string FileDeleted { get; set; }
    internal string FileExecuted { get; set; }
    internal string FileName { get; set; }
    internal string FilePath { get; set; }
    internal string HostName { get; set; }
    internal string FileTrust { get; set; }
    internal string FileThreat { get; set; }
    internal string[] Bit9Hashes { get; set; }
    //internal string[] HostNames { get; set; }
    internal List<FileReport> VTReport { get; set; }
    internal ThreatGRIDReturnValues ThreatGRID { get; set; }
    //internal VirusTotalReturnValues VirusTotal { get; set; }
    //internal ThreatGRIDReturnValues ThreatGRID { get; set; }
  }

  internal class VirusTotalReturnValues
  {
    internal List<FileReport> MD5HashReturn { get; set; }
    internal List<UrlReport> URLReturn { get; set; }
    internal List<Object_VirusTotal_IP.IPReport> IPReturn { get; set; }
    internal string IPUrl { get; set; }
    internal double VirusTotalScore { get; set; }
    internal string VTJson { get; set; }
  }

  internal class ThreatGRIDReturnValues
  {
    internal Object_ThreatGRID_IP_ConfigClass.ThreatGRID_IP_HLInfo IPInfo { get; set; }
    internal List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info> IPThreatInfo { get; set; }
    internal Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search IPSearch { get; set; }
    internal List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info> HashThreatInfo { get; set; }
    internal Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search HashSearch { get; set; }
    internal int ThreatScore { get; set; }
    internal int ThreatIndicators { get; set; }
    internal int ThreatConfidence { get; set; }
    internal int ThreatSeverity { get; set; }
    internal string ThreatGRIDJson { get; set; }
  }

  internal class AlienVaultReturnValues
  {
    internal int Reliability { get; set; }
    internal int Risk { get; set; }
    internal string Activity { get; set; }
    internal string Country { get; set; }
    internal string City { get; set; }
    internal string Latitude { get; set; }
    internal string Longitude { get; set; }
  }

  internal class EventAlerts
  {
    internal int PrimKey { get; set; }
    internal int Timer { get; set; }
    internal string IP { get; set; }
    internal string Hostname { get; set; }
    internal string TimeStamp { get; set; }
    internal int PreviousScore { get; set; }
    internal string AlertID { get; set; }
    internal DataTable Alerts { get; set; }
  }

  internal class HistoricalEvents
  {
    internal string UrlQuery { get; set; }
    internal string IpQuery { get; set; }
    internal string HashQuery { get; set; }
    internal int UrlCount { get; set; }
    internal int IpCount { get; set; }
    internal int HashCount { get; set; }
    internal int UrlScore { get; set; }
    internal int IpScore { get; set; }
    internal int HashScore { get; set; }
    internal int UrlWeight { get; set; }
    internal int IpWeight { get; set; }
    internal int HashWeight { get; set; }
    internal int UrlIncrement { get; set; }
    internal int IpIncrement { get; set; }
    internal int HashIncrement { get; set; }
    internal int UrlMultiplier { get; set; }
    internal int IpMultiplier { get; set; }
    internal int HashMultiplier { get; set; }
    internal DataTable HistAlerts { get; set; }
  }

  internal class LandeskReturnValues
  {
    internal string Hostname { get; set; }
    internal string Domain { get; set; }
    internal string LastUpdate { get; set; }
    internal string Product { get; set; }
    internal string ProductVersion { get; set; }
    internal string AgentRunning { get; set; }
    internal string AutoProtectOn { get; set; }
    internal string DefInstallDate { get; set; }
    internal string EngineVersion { get; set; }
    internal string OSName { get; set; }
    internal string ComputerIDN { get; set; }
    internal string Username { get; set; }
    internal string OSType { get; set; }
    internal string Type { get; set; }
    internal string Battery { get; set; }
    internal string ChassisType { get; set; }
    internal string OSVersion { get; set; }
    internal string OSBuild { get; set; }
    internal string Bit9Version { get; set; }
    internal string Bit9Running { get; set; }
    internal List<int> Patches { get; set; }
  }

  internal class CarbonBlackReturnValues
  {
    internal Object_CarbonBlack_Inventory_Class.CarbonBlackEntry Inventory { get; set; }
    internal CarbonBlackAlert Alert { get; set; }
  }

  internal class CarbonBlackAlert
  {
    internal string EventTime { get; set; }
    internal string EventID { get; set; }
    internal string MD5Hash { get; set; }
    internal string ProcessPath { get; set; }
    internal string HostCount { get; set; }
    internal string NetConn { get; set; }
    internal string AlertType { get; set;  }
    internal string WatchListName { get; set; }
    internal VirusTotalReturnValues VirusTotal { get; set; }
    internal ThreatGRIDReturnValues ThreatGRID { get; set; }
    internal AlienVaultReturnValues AlienVault { get; set; }
    internal Bit9ReturnValues Bit9 { get; set; }
  }

  internal class JamfReturnValues
  {
    internal string ComputerID { get; set; }
    internal string Hostname { get; set; }
    internal string OSName { get; set; }
    internal string LastUpdate { get; set; }
    internal string Product { get; set; }
    internal string ProductVersion { get; set; }
    internal string AgentRunning { get; set; }
    internal string Username { get; set; }
    internal string ReportID { get; set; }
    internal string Bit9Version { get; set; }
    internal List<int> Patches { get; set; }
  }

  internal class TempInventory
  {
    internal TempInventoryValue[] Entry { get; set; }
  }

  internal class TempInventoryValue
  {
    internal string Hostname { get; set; }
    internal string LastUpdate { get; set; }
    internal string SrcIP { get; set; }
    internal string DNSName { get; set; }
    internal string DHCPName { get; set; }
    internal string Source { get; set; }
  }

  internal class UserReturnValues
  {
    internal string UserEmail { get; set; }
    internal string UserID { get; set; }
    internal string Username { get; set; }
    internal string Department { get; set; }
    internal string Title { get; set; }
    internal string EmployeeType { get; set; }
    internal string ManagerID { get; set; }
    internal string ManagerName { get; set; }
    internal string ManagerMail { get; set; }
    internal string ManagerTitle { get; set; }
    internal string ManagerMobile { get; set; }
    internal string CubeLocation { get; set; }
    internal string City { get; set; }
    internal string State { get; set; }
    internal string StreetAddress { get; set; }
    internal string MobileNumber { get; set; }
  }

}