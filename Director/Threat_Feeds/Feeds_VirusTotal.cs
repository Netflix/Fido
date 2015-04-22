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
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.VirusTotal;
using Fido_Main.Fido_Support.FidoDB;
using RestSharp;
using RestSharp.Deserializers;
using VirusTotalNET;
using VirusTotalNET.Exceptions;
using VirusTotalNET.Objects;

namespace Fido_Main.Director.Threat_Feeds
{
  public class Feeds_VirusTotal
  {
      static readonly RestClient _client = new RestClient();
      const int Retry = 3;
      static int _retryCounter = Retry;
      private string _apiKey;

    public static List<FileReport> VirusTotalHash(List<string> lHashes)
    {
      if (lHashes.Count == 0) return null;
      var sVTMD5Array = lHashes.ToArray();
      var lVTHashRet = ParseHash(sVTMD5Array);
      return lVTHashRet;
    }

    public Feeds_VirusTotal(string apiKey)
    {
        if (string.IsNullOrEmpty(apiKey))
            throw new ArgumentException(@"The API key must not be empty.", "apiKey");

        _apiKey = apiKey;
        _client.BaseUrl = new Uri("http://www.virustotal.com/vtapi/v2/");
        _client.Proxy = null;
        _client.FollowRedirects = false;
    }

    public static List<Object_VirusTotal_IP.IPReport> VirusTotalIP(List<String> lIP)
    {
      string[] sIPArray = null;
      if (lIP.Count != 0)
      {
        sIPArray = lIP.ToArray();
      }
      var lIPReturn = ParseIP(sIPArray);
      return lIPReturn;
    }

    public static List<UrlReport> VirusTotalUrl(List<string> lURL)
    {
      string[] sVTURLArray = null;

      if (lURL.Count != 0)
      {
        sVTURLArray = lURL.ToArray();
      }
      var lVTURLRet = ParseUrl(sVTURLArray);
      return lVTURLRet.Count != 0 ? lVTURLRet : null;
    }

    public static List<FileReport> ParseHash(string[] sMD5Hash)
    {
      //todo: The below is a placeholder for when this will be encrypted.
      //var sAcek = xfidoconf.getVarSet("securityfeed").getVarSet("virustotal").getString("acek", null);
      
      var sVTKey = Object_Fido_Configs.GetAsString("fido.securityfeed.virustotal.apikey", null);
      var vtLogin = new VirusTotal(sVTKey);
      var sVirusTotalHash = new List<FileReport>();
      var fidoDB = new SqLiteDB();
      var isPaidFeed = Convert.ToBoolean(fidoDB.ExecuteScalar("Select paid_feed from configs_threatfeed_virustotal"));

      //todo: remove all the sleeps with a configurable option of whether to sleep AND a
      //configurable integer value for the timer. Currently putting these in for the free
      //API, but need to account for someone having access to the paid API.
      try
      {
        if (sMD5Hash.Any())
        {
          if (sMD5Hash.Count() < 4)
          {
            if (!isPaidFeed) Thread.Sleep(1000);
            sVirusTotalHash.AddRange(sMD5Hash.Where(sHash => !string.IsNullOrEmpty(sHash)).Select(vtLogin.GetFileReport).Where(sVtmd5Return => sVtmd5Return != null));
          }
          else if (sMD5Hash.Count() >= 4)
          {
            if (!isPaidFeed) Thread.Sleep(1000);
            for (var i = 0; i < sMD5Hash.Count(); i++)
			      {
              Console.WriteLine(@"Processing hash #" + (i + 1) + @" of " + sMD5Hash.Count() + @" " + sMD5Hash[i] + @".");
			        sVirusTotalHash.Add(vtLogin.GetFileReport(sMD5Hash[i]));
              if (!isPaidFeed)
			        {
                Console.WriteLine(@"Pausing 17 seconds to not overload VT.");
                Thread.Sleep(17000);
			        }
			        
			      }
            
          }
          return sVirusTotalHash;
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in VT Hash area:" + e);
      }
      return sVirusTotalHash;
    }

    private static List<UrlReport> ParseUrl(IEnumerable<string> sURL)
    {

      //The below is a placeholder for when this will be encrypted.
      //var sAcek = xfidoconf.getVarSet("securityfeed").getVarSet("virustotal").getString("acek", null);
      var sVTKey = Object_Fido_Configs.GetAsString("fido.securityfeed.virustotal.apikey", null);
      var vtLogin = new VirusTotal(sVTKey);
      var isRateLimited = Object_Fido_Configs.GetAsBool("fido.securityfeed.virustotal.ratelimited", false);
      List<UrlReport> sVirusTotalUrl = null;
      var sVTURLreturn = new List<UrlReport>();
      var newurl = string.Empty;
      var url = sURL as IList<string> ?? sURL.ToList();
      var fidoDB = new SqLiteDB();
      var isPaidFeed = Convert.ToBoolean(fidoDB.ExecuteScalar("Select paid_feed from configs_threatfeed_virustotal"));

      try
      {
        if (sURL != null)
        {
          for (var i = 0; i < url.Count(); i++)
          {

            if (!url[i].Contains("http://"))
            {
              newurl = "http://" + url[i];
            }
            else
            {
              newurl = url[i];
            }

            if (!isPaidFeed) Thread.Sleep(15000); 
            var sVTURLtemp = new List<UrlReport> { vtLogin.GetUrlReport(newurl) };
            if (!isPaidFeed) Thread.Sleep(20000); 
            var icount = 1;
            if (sVTURLtemp[0].VerboseMsg == "Scan finished, scan information embedded in this object")
            {
              Console.WriteLine(sVTURLtemp[0].VerboseMsg);
              Console.WriteLine(newurl);
              sVTURLreturn.Add(sVTURLtemp[0]);
              continue;
            }
            while (sVTURLtemp[0].VerboseMsg == "The requested resource is not among the finished, queued or pending scans" && icount <= 3)
            {
              Console.WriteLine(sVTURLtemp[0].VerboseMsg);
              Console.WriteLine(newurl);
              sVTURLtemp.RemoveAt(0);
              vtLogin.ScanUrl(newurl);
              //todo: move sleep integer to db
              Thread.Sleep(120000);
              icount++;
              sVTURLtemp.Add(vtLogin.GetUrlReport(newurl));
              if (sVTURLtemp[0].VerboseMsg == "Scan finished, scan information embedded in this object")
              {
                Console.WriteLine(sVTURLtemp[0].VerboseMsg);
                Console.WriteLine(newurl);
                sVTURLreturn.Add(sVTURLtemp[0]);
              }
            }
            //if (icount == 1)
            //{
            //  sVTURLreturn.Add(sVTURLtemp[0]);
            //}
          }
          if (sVTURLreturn.Any())
          {
            sVirusTotalUrl = sVTURLreturn;
            return sVirusTotalUrl;
          }
        }
      }
      catch (Exception e)
      {
        if (e.Message == "You have reached the 5 requests pr. min. limit of VirusTotal")
        {
          if (!isPaidFeed) Thread.Sleep(60000);
          sVirusTotalUrl = ParseUrl(url);
          return sVirusTotalUrl;
        }

        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in VT URL area:" + e);
      }
      return sVirusTotalUrl;
    }

    private static List<Object_VirusTotal_IP.IPReport> ParseIP(string[] sIP)
    {

      //The below is a placeholder for when this will be encrypted.
      //var sAcek = xfidoconf.getVarSet("securityfeed").getVarSet("virustotal").getString("acek", null);
      var sVTKey = Object_Fido_Configs.GetAsString("fido.securityfeed.virustotal.apikey", null);
      var vtLogin = new VirusTotal(sVTKey);

      //test code to workaround rate limiting
      List<Object_VirusTotal_IP.IPReport> sVirusTotalIP = null;

      try
      {
        if (sIP != null)
        {
          var sVTIPreturn = GetIPReport(sIP, sVTKey);
          if (sVTIPreturn != null)
          {
            sVirusTotalIP = sVTIPreturn;
            
            return sVirusTotalIP;
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in VT URL area:" + e);
      }
      return sVirusTotalIP;
    }

    private static List<Object_VirusTotal_IP.IPReport> GetIPReport(string[] ip, string _apiKey)
    {
      if (ip.Length <= 0)
        throw new Exception("You have to supply an URL.");

      var request = new RestRequest("ip-address/report", Method.GET);

      //Required
      request.AddParameter("apikey", _apiKey);
      request.AddParameter("ip", string.Join(",", ip));

      //Output

      return GetResults<List<Object_VirusTotal_IP.IPReport>>(request, true);
    }

    private static T GetResults<T>(RestRequest request, bool applyHack = false)
    {

      _client.BaseUrl = new Uri("http://www.virustotal.com/vtapi/v2/", UriKind.Absolute);
      _client.Proxy = null;
      _client.FollowRedirects = false;
      T results;
      var fidoDB = new SqLiteDB();
      var isPaidFeed = Convert.ToBoolean(fidoDB.ExecuteScalar("Select paid_feed from configs_threatfeed_virustotal"));
      var response = (RestResponse)_client.Execute(request);

      if (applyHack)
      {
        //Warning: Huge hack... sorry :(
        response.Content = Regex.Replace(response.Content, "\"([\\w\\d -\\._]+)\": \\{\"detected\":", "{\"name\": \"$1\", \"detected\":", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        response.Content = response.Content.Replace("scans\": {", "scans\": [");
        response.Content = response.Content.Replace("}}", "}]");
      }

      IDeserializer deserializer = new JsonDeserializer();

      if (response.StatusCode == HttpStatusCode.NoContent)
      {
        //todo: move integer value to db
        if (!isPaidFeed) Thread.Sleep(30000);
        results = GetResults<T>(request, true);
        return results;
      }
        //throw new RateLimitException("You have reached the 5 requests pr. min. limit of VirusTotal");

      if (response.StatusCode == HttpStatusCode.Forbidden)
        throw new AccessDeniedException("You don't have access to the service. Make sure your API key is working correctly.");

      try
      {
        results = deserializer.Deserialize<T>(response);
      }
      catch (SerializationException)
      {
        //retry request.
        try
        {
          _retryCounter--;

          if (_retryCounter <= 0)
          {
            _retryCounter = Retry;
            return default(T);
          }
          results = GetResults<T>(request, applyHack);
        }
        catch (SerializationException ex)
        {
          throw new Exception("Failed to deserialize request.", ex);
        }
      }

      //reset retry counter
      _retryCounter = Retry;
      return results;
    }
  }
}
