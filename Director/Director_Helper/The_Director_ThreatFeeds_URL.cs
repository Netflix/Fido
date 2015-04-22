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
using Fido_Main.Director.Threat_Feeds;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.ThreatGRID;

namespace Fido_Main.Director.Director_Helper
{
  static class The_Director_ThreatFeeds_URL
  {

    public static FidoReturnValues DetectorsToThreatFeeds(FidoReturnValues lFidoReturnValues)
    {
      lFidoReturnValues = FireEyeURL(lFidoReturnValues);
      lFidoReturnValues = CyphortURL(lFidoReturnValues);
      lFidoReturnValues = ProtectWiseURL(lFidoReturnValues);
      lFidoReturnValues = PaloAltoURL(lFidoReturnValues);

      return lFidoReturnValues;
    }

    private static FidoReturnValues FireEyeURL(FidoReturnValues lFidoReturnValues)
    {

      if ((lFidoReturnValues.FireEye != null) && ((lFidoReturnValues.FireEye.URL.Count != 0) || (lFidoReturnValues.FireEye.ChannelHost.Count != 0)))
      {
        //initialize VT area if null
        if (lFidoReturnValues.FireEye.VirusTotal == null)
        {
          lFidoReturnValues.FireEye.VirusTotal = new VirusTotalReturnValues();
        }

        //convert return from FireEye to list
        var sURLToCheck = new List<string>();
        //if ((lFidoReturnValues.FireEye.URL != null) && (lFidoReturnValues.FireEye.URL.Count > 0))
        //{
        //  sURLToCheck.AddRange(lFidoReturnValues.FireEye.URL);
        //}
        if ((lFidoReturnValues.FireEye.ChannelHost != null) && (lFidoReturnValues.FireEye.ChannelHost.Count > 0))
        {
          sURLToCheck.AddRange(lFidoReturnValues.FireEye.ChannelHost);
        }
        //if (lFidoReturnValues.FireEye.DstIP != null)
        //{
        //  sURLToCheck.Add(lFidoReturnValues.FireEye.DstIP);
        //}

        sURLToCheck = sURLToCheck.Where(s => !string.IsNullOrEmpty(s)).Distinct().ToList();

        //send FireEye return to VT
        if ((sURLToCheck != null) && sURLToCheck.Any())
        {
          Console.WriteLine(@"Sending FireEye URLs to VirusTotal.");
          lFidoReturnValues.FireEye.VirusTotal.URLReturn = Feeds_VirusTotal.VirusTotalUrl(sURLToCheck);
        }

        var sIPToCheck = new List<string>();

        if (lFidoReturnValues.FireEye.DstIP != null)
        {
          sIPToCheck.Add(lFidoReturnValues.FireEye.DstIP);
        }

        sIPToCheck = sIPToCheck.Where(s => !string.IsNullOrEmpty(s)).Distinct().ToList();

        //send IP information to VT IP API
        if (sIPToCheck != null)
        {
          Console.WriteLine(@"Getting detailed IP information from VirusTotal.");
          lFidoReturnValues.FireEye.VirusTotal.IPReturn = Feeds_VirusTotal.VirusTotalIP(sIPToCheck);
          lFidoReturnValues.FireEye.VirusTotal.IPUrl = "http://www.virustotal.com/en/ip-address/" + lFidoReturnValues.FireEye.DstIP + "/information/";
        }

        //initialize AlienVault area if null
        if (lFidoReturnValues.FireEye.AlienVault == null)
        {
          lFidoReturnValues.FireEye.AlienVault = new AlienVaultReturnValues();
        }

        //next send FireEye return to AlienVault
        if ((lFidoReturnValues.FireEye != null) && (lFidoReturnValues.FireEye.DstIP != null))
        {
          Console.WriteLine(@"Getting IP information from AlienVault");
          lFidoReturnValues.FireEye.AlienVault = Feeds_AlientVault.AlienVaultIP(lFidoReturnValues.DstIP);
        }

      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues CyphortURL(FidoReturnValues lFidoReturnValues)
    {
      if ((lFidoReturnValues.Cyphort != null) && ((lFidoReturnValues.Cyphort.URL.Count != 0) || (lFidoReturnValues.Cyphort.Domain.Count != 0)))
      {
        lFidoReturnValues = SendCyphortToVirusTotal(lFidoReturnValues);

        lFidoReturnValues = SendCyphortToThreatGRID(lFidoReturnValues);

        lFidoReturnValues = SendCyphortToAlienVault(lFidoReturnValues);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues ProtectWiseURL(FidoReturnValues lFidoReturnValues)
    {
      if ((lFidoReturnValues.ProtectWise != null) && ((lFidoReturnValues.ProtectWise.URL != null) || (lFidoReturnValues.ProtectWise.DstIP != null)))
      {
        lFidoReturnValues = SendProtectWiseToVirusTotal(lFidoReturnValues);

        lFidoReturnValues = SendProtectWiseToThreatGRID(lFidoReturnValues);

        lFidoReturnValues = SendProtectWiseToAlienVault(lFidoReturnValues);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues PaloAltoURL(FidoReturnValues lFidoReturnValues)
    {
      if ((lFidoReturnValues.PaloAlto != null) && ((lFidoReturnValues.PaloAlto.DstIp != null)))
      {
        lFidoReturnValues = SendPaloAltoToVirusTotal(lFidoReturnValues);

        lFidoReturnValues = SendPaloAltoToThreatGRID(lFidoReturnValues);

        lFidoReturnValues = SendPaloAltoToAlienVault(lFidoReturnValues);
      }

      return lFidoReturnValues;

    }

    private static FidoReturnValues SendCyphortToVirusTotal(FidoReturnValues lFidoReturnValues)
    {
      if (Object_Fido_Configs.GetAsBool("fido.director.virustotal", false)) return lFidoReturnValues;

      //convert return from Cyphort to list
      var sURLToCheck = new List<string>();
      if ((lFidoReturnValues.Cyphort.URL.Any()) && (lFidoReturnValues.Cyphort.URL.Count > 0))
      {
        for (var i = 0; i < lFidoReturnValues.Cyphort.URL.Count(); i++)
        {
          if (string.IsNullOrEmpty(lFidoReturnValues.Cyphort.URL[i])) continue;
          if (lFidoReturnValues.Cyphort.URL[i].Contains(".exe")) continue;
          //if (!lFidoReturnValues.Cyphort.URL[i].Contains(".com"))
          //{
          //  lFidoReturnValues.Cyphort.URL[i] = lFidoReturnValues.Cyphort.URL[i] + @".com";
          //}
          sURLToCheck.Add(lFidoReturnValues.Cyphort.URL[i]);
        }
      }

      if ((lFidoReturnValues.Cyphort.Domain != null) && (lFidoReturnValues.Cyphort.Domain.Count > 0))
      {
        sURLToCheck.AddRange(lFidoReturnValues.Cyphort.Domain);
      }

      if (lFidoReturnValues.Cyphort.DstIP != null)
      {
        sURLToCheck.Add(lFidoReturnValues.Cyphort.DstIP);
      }

      sURLToCheck = sURLToCheck.Where(s => !string.IsNullOrEmpty(s)).Distinct().ToList();

      //send Cyphort return to VT URL API
      if (sURLToCheck.Any())
      {
        Console.WriteLine(@"Sending Cyport URLs to VirusTotal.");
        lFidoReturnValues.Cyphort.VirusTotal.URLReturn = Feeds_VirusTotal.VirusTotalUrl(sURLToCheck);
      }

      var sIPToCheck = new List<string>();

      if (lFidoReturnValues.Cyphort.DstIP != null)
      {
        sIPToCheck.Add(lFidoReturnValues.Cyphort.DstIP);
      }

      sIPToCheck = sIPToCheck.Where(s => !string.IsNullOrEmpty(s)).Distinct().ToList();

      //send Cyphort return to VT IP API
      if (sIPToCheck.Any())
      {
        Console.WriteLine(@"Getting detailed IP information from VirusTotal.");
        lFidoReturnValues.Cyphort.VirusTotal.IPReturn = Feeds_VirusTotal.VirusTotalIP(sIPToCheck);
        //todo: move the url to the database
        lFidoReturnValues.Cyphort.VirusTotal.IPUrl = "http://www.virustotal.com/en/ip-address/" + lFidoReturnValues.Cyphort.DstIP + "/information/";
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SendProtectWiseToVirusTotal(FidoReturnValues lFidoReturnValues)
    {
      if (Object_Fido_Configs.GetAsBool("fido.director.virustotal", false)) return lFidoReturnValues;

      var sIPToCheck = new List<string>();
      if (lFidoReturnValues.ProtectWise.VirusTotal == null)
      {
        lFidoReturnValues.ProtectWise.VirusTotal = new VirusTotalReturnValues();
      }
      //send ProtectWise return to VT URL API
      if (lFidoReturnValues.ProtectWise.IncidentDetails.Data != null)
      {
        if (lFidoReturnValues.ProtectWise.IncidentDetails.Data.URL_Reputation != null)
        {
          Console.WriteLine(@"Sending ProtectWise URLs to VirusTotal.");
          var URL = new List<string> { lFidoReturnValues.ProtectWise.IncidentDetails.Data.URL_Reputation.Url };
          var vtURLReturn = Feeds_VirusTotal.VirusTotalUrl(URL);
          if (vtURLReturn != null)
          {
            lFidoReturnValues.ProtectWise.VirusTotal.URLReturn = vtURLReturn;
          }
        }
        else if (lFidoReturnValues.ProtectWise.URL != null)
        {
          Console.WriteLine(@"Sending ProtectWise destination IP to VirusTotal.");
          var URL = new List<string> { lFidoReturnValues.ProtectWise.URL };
          var vtURLReturn = Feeds_VirusTotal.VirusTotalUrl(URL);
          if (vtURLReturn != null)
          {
            lFidoReturnValues.ProtectWise.VirusTotal.URLReturn = vtURLReturn;
          }
        }
      }

      if (lFidoReturnValues.ProtectWise.DstIP != null)
      {
        sIPToCheck.Add(lFidoReturnValues.ProtectWise.DstIP);
      }

      sIPToCheck = sIPToCheck.Where(s => !string.IsNullOrEmpty(s)).Distinct().ToList();
      //send ProtectWise return to VT IP API
      if (sIPToCheck.Any())
      {
        Console.WriteLine(@"Getting detailed IP information from VirusTotal.");
        lFidoReturnValues.ProtectWise.VirusTotal.IPReturn = Feeds_VirusTotal.VirusTotalIP(sIPToCheck);
        //todo: move the url to the database
        lFidoReturnValues.ProtectWise.VirusTotal.IPUrl = "http://www.virustotal.com/en/ip-address/" + lFidoReturnValues.ProtectWise.DstIP + "/information/";
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SendPaloAltoToVirusTotal(FidoReturnValues lFidoReturnValues)
    {
      if (Object_Fido_Configs.GetAsBool("fido.director.virustotal", false)) return lFidoReturnValues;

      var sIPToCheck = new List<string> {lFidoReturnValues.PaloAlto.DstIp};
      //send ProtectWise return to VT IP API
      if (lFidoReturnValues.PaloAlto.DstIp.Any())
      {
        if (lFidoReturnValues.PaloAlto.VirusTotal == null)
        {
          lFidoReturnValues.PaloAlto.VirusTotal = new VirusTotalReturnValues();
        }

        Console.WriteLine(@"Getting detailed IP information from VirusTotal.");
        try
        {
          var IPReturn = Feeds_VirusTotal.VirusTotalIP(sIPToCheck);
          if (IPReturn != null)
          {
            lFidoReturnValues.PaloAlto.VirusTotal.IPReturn = IPReturn;
          }
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving VT IP information:" + e);
        }
        
        //todo: move the url to the database
        lFidoReturnValues.PaloAlto.VirusTotal.IPUrl = "http://www.virustotal.com/en/ip-address/" + lFidoReturnValues.PaloAlto.DstIp + "/information/";
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SendCyphortToThreatGRID(FidoReturnValues lFidoReturnValues)
    {
      if (Object_Fido_Configs.GetAsBool("fido.director.threatgrid", false)) return lFidoReturnValues;

      Int16 iDays = -7;
      lFidoReturnValues.Cyphort.ThreatGRID.IPSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.DstIP, false, iDays);
      while (Convert.ToInt16(lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Data.CurrentItemCount) < 50)
      {
        if (iDays < -364) break;
        iDays = (Int16) (iDays*2);
        lFidoReturnValues.Cyphort.ThreatGRID.IPSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.DstIP, false, iDays);
      }

      Console.WriteLine(@"Successfully found ThreatGRID IP data (" + lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Data.CurrentItemCount + @" records)... storing in Fido.");

      if (Convert.ToDouble(lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Data.CurrentItemCount) == 0) return lFidoReturnValues;
      
      //todo: make the below integer values configurable by storing them in the DB
      var vTGItemCount = 0;
      if (Convert.ToInt16(lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Data.CurrentItemCount) < 25) vTGItemCount = Convert.ToInt16(lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Data.CurrentItemCount);
      if (Convert.ToInt16(lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Data.CurrentItemCount) >= 25)
      {
        vTGItemCount = 25;
      }
      
      for (var i = 0; i < vTGItemCount; i++)
      {
        if (i >= 50) continue;
        if (lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo == null)
        {
          lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo = new List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>();
        }
        lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Add(Feeds_ThreatGRID.ThreatInfo(lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Data.Items[i].HashID));
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues SendProtectWiseToThreatGRID(FidoReturnValues lFidoReturnValues)
    {
      if (Object_Fido_Configs.GetAsBool("fido.director.threatgrid", false)) return lFidoReturnValues;

      Int16 iDays = -7;
      lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.DstIP, false, iDays);
      while (Convert.ToInt16(lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.CurrentItemCount) < 50)
      {
        if (iDays < -364) break;
        iDays = (Int16)(iDays * 2);
        lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.DstIP, false, iDays);
      }

      Console.WriteLine(@"Successfully found ThreatGRID IP data (" + lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.CurrentItemCount + @" records)... storing in Fido.");

      for (var i = 0; i < Convert.ToInt16(lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.CurrentItemCount); i++)
      {
        if (i >= 50) continue;
        if (lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo == null)
        {
          lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo = new List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>();
        }
        lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Add(Feeds_ThreatGRID.ThreatInfo(lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.Items[i].HashID));
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues SendPaloAltoToThreatGRID(FidoReturnValues lFidoReturnValues)
    {
      if (Object_Fido_Configs.GetAsBool("fido.director.threatgrid", false)) return lFidoReturnValues;

      Int16 iDays = -7;
      lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.DstIP, false, iDays);
      while (Convert.ToInt16(lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.CurrentItemCount) < 50)
      {
        if (iDays < -364) break;
        iDays = (Int16)(iDays * 2);
        lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.DstIP, false, iDays);
      }

      Console.WriteLine(@"Successfully found ThreatGRID IP data (" + lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.CurrentItemCount + @" records)... storing in Fido.");

      for (var i = 0; i < Convert.ToInt16(lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.CurrentItemCount); i++)
      {
        if (i >= 50) continue;
        if (lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo == null)
        {
          lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo = new List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>();
        }
        lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Add(Feeds_ThreatGRID.ThreatInfo(lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.Items[i].HashID));
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues SendCyphortToAlienVault(FidoReturnValues lFidoReturnValues)
    {
      if (Object_Fido_Configs.GetAsBool("fido.director.alienvault", false)) return lFidoReturnValues;

      //initialize AlienVault area if null
      if (lFidoReturnValues.Cyphort.AlienVault == null)
      {
        lFidoReturnValues.Cyphort.AlienVault = new AlienVaultReturnValues();
      }

      //next send Cyphort return to AlienVault
      if ((lFidoReturnValues.Cyphort != null) && (lFidoReturnValues.Cyphort.DstIP != null))
      {
        Console.WriteLine(@"Getting IP informaiton from AlienVault.");
        lFidoReturnValues.Cyphort.AlienVault = Feeds_AlientVault.AlienVaultIP(lFidoReturnValues.DstIP);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues SendProtectWiseToAlienVault(FidoReturnValues lFidoReturnValues)
    {
      if (Object_Fido_Configs.GetAsBool("fido.director.alienvault", false)) return lFidoReturnValues;

      //initialize AlienVault area if null
      if (lFidoReturnValues.ProtectWise.AlienVault == null)
      {
        lFidoReturnValues.ProtectWise.AlienVault = new AlienVaultReturnValues();
      }

      //next send Cyphort return to AlienVault
      if ((lFidoReturnValues.ProtectWise != null) && (lFidoReturnValues.ProtectWise.DstIP != null))
      {
        Console.WriteLine(@"Getting IP informaiton from AlienVault.");
        lFidoReturnValues.ProtectWise.AlienVault = Feeds_AlientVault.AlienVaultIP(lFidoReturnValues.DstIP);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues SendPaloAltoToAlienVault(FidoReturnValues lFidoReturnValues)
    {
      if (Object_Fido_Configs.GetAsBool("fido.director.alienvault", false)) return lFidoReturnValues;

      //initialize AlienVault area if null
      if (lFidoReturnValues.PaloAlto.AlienVault == null)
      {
        lFidoReturnValues.PaloAlto.AlienVault = new AlienVaultReturnValues();
      }

      //next send PAN return to AlienVault
      if ((lFidoReturnValues.PaloAlto != null) && (lFidoReturnValues.PaloAlto.DstIp != null))
      {
        Console.WriteLine(@"Getting IP informaiton from AlienVault.");
        lFidoReturnValues.PaloAlto.AlienVault = Feeds_AlientVault.AlienVaultIP(lFidoReturnValues.PaloAlto.DstIp);
      }

      return lFidoReturnValues;
    }
    
    public static FidoReturnValues ThreatGRIDIPInfo(FidoReturnValues lFidoReturnValues)
    {
      if (Object_Fido_Configs.GetAsBool("fido.director.alienvault", false)) return lFidoReturnValues;

      if (!String.IsNullOrEmpty(lFidoReturnValues.DstIP))
      {
        if (lFidoReturnValues.FireEye != null)
        {
          if (lFidoReturnValues.FireEye.ThreatGRID == null)
          {
            lFidoReturnValues.FireEye.ThreatGRID = new ThreatGRIDReturnValues();
          }
          lFidoReturnValues.FireEye.ThreatGRID.IPInfo = Feeds_ThreatGRID.HlInfo(lFidoReturnValues.DstIP);
        }
        if (lFidoReturnValues.Cyphort != null)
        {
          if (lFidoReturnValues.Cyphort.ThreatGRID == null)
          {
            lFidoReturnValues.Cyphort.ThreatGRID = new ThreatGRIDReturnValues();
          }
          lFidoReturnValues.Cyphort.ThreatGRID.IPInfo = Feeds_ThreatGRID.HlInfo(lFidoReturnValues.DstIP);
        }
        if (lFidoReturnValues.ProtectWise != null)
        {
          if (lFidoReturnValues.ProtectWise.ThreatGRID == null)
          {
            lFidoReturnValues.ProtectWise.ThreatGRID = new ThreatGRIDReturnValues();
          }
          lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo = Feeds_ThreatGRID.HlInfo(lFidoReturnValues.DstIP);
        }
        if (lFidoReturnValues.PaloAlto != null)
        {
          if (lFidoReturnValues.PaloAlto.ThreatGRID == null)
          {
            lFidoReturnValues.PaloAlto.ThreatGRID = new ThreatGRIDReturnValues();
          }
          lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo = Feeds_ThreatGRID.HlInfo(lFidoReturnValues.DstIP);
        }
      }
      return lFidoReturnValues;
    }

  }
}