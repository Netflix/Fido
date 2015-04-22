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

namespace Fido_Main.Fido_Support.Objects.Cyphort
{
  static class Object_Cyphort_Class
  {
    public class CyphortEvent
    {
      [JsonProperty("first_dummy_value")]
      internal int first_dummy_value { get; set; }

      [JsonProperty("event_array")]
      internal CyphortEventDetails[] Event_Array { get; set; }
    }

    public class CyphortEventDetails
    {

      [JsonProperty("event_id")]
      internal string Event_id { get; set; }

      [JsonProperty("event_type")]
      internal string Event_type { get; set; }

      [JsonProperty("event_category")]
      internal string Event_category { get; set; }

      [JsonProperty("event_name")]
      internal string Event_name { get; set; }

      [JsonProperty("event_severity")]
      internal string Event_severity { get; set; }

      [JsonProperty("last_activity_time")]
      internal string Last_activity_time { get; set; }

      [JsonProperty("endpoint_ip")]
      internal string Endpoint_ip { get; set; }

      [JsonProperty("endpoint_name")]
      internal string Endpoint_name { get; set; }

      [JsonProperty("endpoint_os_type")]
      internal string Endpoint_os_type { get; set; }

      [JsonProperty("source_ip")]
      internal string Source_ip { get; set; }

      [JsonProperty("source_name")]
      internal string Source_name { get; set; }

      [JsonProperty("source_country_code")]
      internal string Source_country_code { get; set; }

      [JsonProperty("source_country_name")]
      internal string Source_country_name { get; set; }

      [JsonProperty("incident_id")]
      internal string Incident_id { get; set; }

      [JsonProperty("incident_risk")]
      internal string Incident_risk { get; set; }

      [JsonProperty("collector_id")]
      internal string Collector_id { get; set; }

      [JsonProperty("search_data")]
      internal string Search_data { get; set; }

    }

    public class CyphortIncident
    {
      [JsonProperty("incident_details")]
      internal CyphortIncidentDetails Incident { get; set; }
    }

    public class CyphortIncidentDetails
    {
      [JsonProperty("incident_id")]
      internal string Incident_id { get; set; }

      [JsonProperty("incident_risk")]
      internal string Incident_risk { get; set; }

      [JsonProperty("incident_category")]
      internal string Incident_category { get; set; }

      [JsonProperty("incident_name")]
      internal string Incident_name { get; set; }

      [JsonProperty("incident_severity")]
      internal string Incident_severity { get; set; }

      [JsonProperty("incident_relevance")]
      internal string Incident_relevance { get; set; }

      [JsonProperty("last_activity_time")]
      internal string Last_activity_time { get; set; }

      [JsonProperty("endpoint_ip")]
      internal string Endpoint_ip { get; set; }

      [JsonProperty("endpoint_name")]
      internal string Endpoint_name { get; set; }

      [JsonProperty("endpoint_value")]
      internal string Endpoint_value { get; set; }

      [JsonProperty("endpoint_os_type")]
      internal string Endpoint_os_type { get; set; }

      [JsonProperty("source_ip")]
      internal string Source_ip { get; set; }

      [JsonProperty("source_name")]
      internal string Source_name { get; set; }

      [JsonProperty("source_country_code")]
      internal string Source_country_code { get; set; }

      [JsonProperty("source_country_name")]
      internal string Source_country_name { get; set; }

      [JsonProperty("has_valid_av")]
      internal string Has_valid_av { get; set; }

      [JsonProperty("has_os_match")]
      internal string Has_os_match { get; set; }

      [JsonProperty("has_exploit")]
      internal string Has_exploit { get; set; }

      [JsonProperty("has_download")]
      internal string Has_download { get; set; }

      [JsonProperty("has_execution")]
      internal string Has_execution { get; set; }

      [JsonProperty("has_infection")]
      internal string Has_infection { get; set; }

      [JsonProperty("has_data_theft")]
      internal string Has_data_theft { get; set; }

      [JsonProperty("has_file_submission")]
      internal string Has_file_submission { get; set; }

      [JsonProperty("collector_id")]
      internal string Collector_id { get; set; }

      [JsonProperty("collector_type")]
      internal string Collector_type { get; set; }

      [JsonProperty("search_data")]
      internal string Search_data { get; set; }

      [JsonProperty("search_collector_id")]
      internal string Search_collector_id { get; set; }

      [JsonProperty("exploit_array")]
      internal CyphortExploitsArrayDetails[] ExploitsArray { get; set; }

      [JsonProperty("download_array")]
      internal CyphortDownloadArrayDetails[] DownloadArray { get; set; }

      [JsonProperty("infection_array")]
      internal CyphortInfectionArrayDetails[] InfectionArray { get; set; }

      [JsonProperty("second_order_array")]
      internal CyphortSecondOrderArrayDetails[] SecondOrderArray { get; set; }

      [JsonProperty("file_submission_array")]
      internal CyphortFileSubmissionArrayDetails[] FileSubmissionArray { get; set; }

      [JsonProperty("snort_event_array")]
      internal CyphortSnortEventArrayDetails[] SnortEventArray { get; set; }

    }

    public class CyphortExploitsArrayDetails
    {

    }

    public class CyphortDownloadArrayDetails
    {
      [JsonProperty("event_id")]
      internal string Event_id { get; set; }

      [JsonProperty("capture_time_string")]
      internal string Capture_time_string { get; set; }

      [JsonProperty("endpoint_ip")]
      internal string Endpoint_ip { get; set; }

      [JsonProperty("endpoint_name")]
      internal string Endpoint_name { get; set; }

      [JsonProperty("source_ip")]
      internal string Source_ip { get; set; }

      [JsonProperty("source_url")]
      internal string Source_url { get; set; }

      [JsonProperty("client_os")]
      internal string Client_os { get; set; }

      [JsonProperty("req_headers")]
      internal RequestHeader Req_headers { get; set; }

      [JsonProperty("appliance_id")]
      internal string Appliance_id { get; set; }

      [JsonProperty("req_referer")]
      internal string Req_referer { get; set; }

      [JsonProperty("country_code")]
      internal string Country_code { get; set; }

      [JsonProperty("country_name")]
      internal string Country_name { get; set; }

      [JsonProperty("local_path")]
      internal string Local_path { get; set; }

      [JsonProperty("file_md5_string")]
      internal string File_md5_string { get; set; }

      [JsonProperty("file_sha1_string")]
      internal string File_sha1_string { get; set; }

      [JsonProperty("file_sha256_string")]
      internal string File_sha256_string { get; set; }

      [JsonProperty("file_size")]
      internal string File_size { get; set; }

      [JsonProperty("file_type_string")]
      internal string File_type_string { get; set; }

      [JsonProperty("file_suffix")]
      internal string File_suffix { get; set; }

      [JsonProperty("mime_type_string")]
      internal string Mime_type_string { get; set; }

      [JsonProperty("packer_name")]
      internal string Packer_name { get; set; }

      [JsonProperty("malware_name")]
      internal string Malware_name { get; set; }

      [JsonProperty("malware_severity")]
      internal string Malware_severity { get; set; }

      [JsonProperty("malware_category")]
      internal string Malware_category { get; set; }

      [JsonProperty("malware_classname")]
      internal string Malware_classname { get; set; }

      [JsonProperty("has_static_detection")]
      internal string Has_static_detection { get; set; }

      [JsonProperty("has_behavioral_detection")]
      internal string Has_behavioral_detection { get; set; }

      [JsonProperty("user_whitelisted")]
      internal string User_whitelisted { get; set; }

      [JsonProperty("cyphort_whitelisted")]
      internal string Cyphort_whitelisted { get; set; }

      [JsonProperty("has_cnc")]
      internal string Has_cnc { get; set; }

      [JsonProperty("dig_cert_name")]
      internal string Dig_cert_name { get; set; }

      [JsonProperty("cooking_duration")]
      internal string Cooking_duration { get; set; }

      [JsonProperty("source_url_rank")]
      internal string Source_url_rank { get; set; }

      [JsonProperty("reputation_score")]
      internal string Reputation_score { get; set; }

      [JsonProperty("microsoft_name")]
      internal string Microsoft_name { get; set; }

      [JsonProperty("user_agent")]
      internal string User_agent { get; set; }
    }

    public class RequestHeader
    {
      [JsonProperty("connection")]
      internal string Connection { get; set; }

      [JsonProperty("accept_language")]
      internal string Accept_language { get; set; }

      [JsonProperty("accept_encoding")]
      internal string Accept_encoding { get; set; }

      [JsonProperty("referer")]
      internal string Referer { get; set; }

      [JsonProperty("host")]
      internal string Host { get; set; }

      [JsonProperty("accept")]
      internal string Accept { get; set; }

      [JsonProperty("user_agent")]
      internal string User_agent { get; set; }
    }

    public class CyphortInfectionArrayDetails
    {
      [JsonProperty("infection_id")]
      internal string Infection_id { get; set; }

      [JsonProperty("time_string")]
      internal string Time_string { get; set; }

      [JsonProperty("endpoint_ip")]
      internal string Endpoint_ip { get; set; }

      [JsonProperty("endpoint_name")]
      internal string Endpoint_name { get; set; }

      [JsonProperty("malware_name")]
      internal string Malware_name { get; set; }

      [JsonProperty("malware_severity")]
      internal string Malware_severity { get; set; }

      [JsonProperty("malware_category")]
      internal string Malware_category { get; set; }

      [JsonProperty("cnc_servers")]
      internal string Cnc_servers { get; set; }

      [JsonProperty("malware_classname")]
      internal string Malware_classname { get; set; }
    }

    public class CyphortSecondOrderArrayDetails
    {
    }

    public class CyphortFileSubmissionArrayDetails
    {
    }

    public class CyphortSnortEventArrayDetails
    {
      [JsonProperty("time")]
      internal string Time { get; set; }

      [JsonProperty("sig_name")]
      internal string Sig_name { get; set; }
      
      [JsonProperty("cnc")]
      internal string CNC { get; set; }
      
      [JsonProperty("data_payload")]
      internal string Data_payload { get; set; }
    }

  }
}
