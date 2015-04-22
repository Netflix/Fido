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
using System.Globalization;
using System.Linq;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Notification.Notification_Helper
{
  static class Notfication_Helper
  {
    public static Dictionary<string, string> StartReplacements(FidoReturnValues lFidoReturnValues, string[] detectors, List<string> lBadMD5Hashes, List<string> lGoodMD5Hashes, List<string> lBadURLs, List<string> lGoodURLs, Dictionary<string, string> replacements)
    {
      try
      {
        //todo: put the following switch into its own function
        foreach (var detector in detectors)
        {
          switch (detector)
          {
            case "cyphortv2":
              if (lFidoReturnValues.Cyphort != null)
              {
                replacements = Notification_Cyphort_Helper.CyphortBadGuyReturn(lFidoReturnValues, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);
                replacements = VTReplacements(lFidoReturnValues, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);
              }

              break;

            case "cyphortv3":
              if (lFidoReturnValues.Cyphort != null)
              {
                replacements = Notification_Cyphort_Helper.CyphortBadGuyReturn(lFidoReturnValues, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);
                replacements = VTReplacements(lFidoReturnValues, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);
              }

              break;

            case "protectwisev1-event":
              if (lFidoReturnValues.ProtectWise != null)
              {
                replacements = Notfication_ProtectWise_Helper.ProtectWiseBadGuyReturn(lFidoReturnValues, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);
                replacements = VTReplacements(lFidoReturnValues, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);
              }

              break;

            case "carbonblackv1":
              if (lFidoReturnValues.CB.Alert != null)
              {
                replacements = Notification_CarbonBlack_Helper.CarbonBlackBadGuyReturn(lFidoReturnValues, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);
                replacements = VTReplacements(lFidoReturnValues, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);
              }
              break;

            case "panv1":
              if (lFidoReturnValues.PaloAlto != null)
              {
                replacements = Notification_PaloAlto_Helper.PaloAltoBadGuyReturn(lFidoReturnValues, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);
                replacements = VTReplacements(lFidoReturnValues, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);
              }
              break;


            case "mps":
              //Check Virustotal for values
              if (lFidoReturnValues.FireEye != null)
              {
                replacements = MPSBadGuyReturn(lFidoReturnValues, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);
                replacements = VTReplacements(lFidoReturnValues, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);
              }

              break;

            case "antivirus":
              break;

            case "ids":
              break;

            case "bit9":
              if (lFidoReturnValues.Bit9 != null)
              {
                if (lFidoReturnValues.Bit9.VTReport == null) continue;
                if (lFidoReturnValues.Bit9.VTReport[0].Positives > 0)
                {
                  lFidoReturnValues.BadHashs += 1;
                  lBadMD5Hashes.Add(lFidoReturnValues.Bit9.VTReport[0].Permalink);
                }
                else
                {
                  lGoodMD5Hashes.Add(lFidoReturnValues.Bit9.VTReport[0].Permalink);
                }

                //Check Bit9 for values
                replacements.Add("%bit9threat%", lFidoReturnValues.Bit9.FileThreat);
                replacements.Add("%bit9trust%", lFidoReturnValues.Bit9.FileTrust);
              }

              break;
          }
        }
        return replacements;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Notification Help:" + e); 
      }
      return replacements;
    }
    
    public static Dictionary<string, string> AntivirusReplacements(FidoReturnValues lFidoReturnValues)
    {
      var replacements = new Dictionary<string, string>();

      if (lFidoReturnValues.MalwareType != null)
      {
        replacements.Add("%threattype%", lFidoReturnValues.Antivirus.ThreatType);
      }
      if (lFidoReturnValues.Antivirus.ActionTaken != null)
      {
        replacements.Add("%actiontaken%", lFidoReturnValues.Antivirus.ActionTaken);
      }
      if (lFidoReturnValues.Antivirus.Status != null)
      {
        replacements.Add("%actionstatus%", lFidoReturnValues.Antivirus.Status);
      }
      if (lFidoReturnValues.Antivirus.FileName != null)
      {
        replacements.Add("%malwarefilename%", lFidoReturnValues.Antivirus.FileName);
      }

      return replacements;
    }

    private static Dictionary<string, string> MPSBadGuyReturn(FidoReturnValues lFidoReturnValues, List<string> lBadMD5Hashes, List<string> lGoodMD5Hashes, List<string> lBadURLs, List<string> lGoodURLs, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.FireEye.VirusTotal != null)
      {
        if (lFidoReturnValues.FireEye.VirusTotal.MD5HashReturn != null)
        {
          for (var i = 0; i < lFidoReturnValues.FireEye.VirusTotal.MD5HashReturn.Count(); i++)
          {
            if (lFidoReturnValues.FireEye.VirusTotal.MD5HashReturn[i].Positives > 0)
            {
              lFidoReturnValues.BadHashs += 1;
              lBadMD5Hashes.Add(lFidoReturnValues.FireEye.VirusTotal.MD5HashReturn[i].Permalink);
            }
            else
            {
              lGoodMD5Hashes.Add(lFidoReturnValues.FireEye.VirusTotal.MD5HashReturn[i].Permalink);
            }
          }
        }

        if (lFidoReturnValues.FireEye.VirusTotal.URLReturn == null) return replacements;
        for (var i = 0; i < lFidoReturnValues.FireEye.VirusTotal.URLReturn.Count(); i++)
        {
          if (lFidoReturnValues.FireEye.VirusTotal.URLReturn[i].Positives > 0)
          {
            lFidoReturnValues.BadUrLs += 1;
            lBadURLs.Add(lFidoReturnValues.FireEye.VirusTotal.URLReturn[i].Permalink);
          }
          else
          {
            lGoodURLs.Add(lFidoReturnValues.FireEye.VirusTotal.URLReturn[i].Permalink);
          }
        }
      }

      if (lFidoReturnValues.FireEye.VirusTotal.IPReturn != null)
      {
        if (lFidoReturnValues.FireEye.VirusTotal.IPReturn[0].DetectedCommunicatingSamples != null)
        {
          for (var i = 0;
            i < lFidoReturnValues.FireEye.VirusTotal.IPReturn[0].DetectedCommunicatingSamples.Count();
            i++)
          {
            if (lFidoReturnValues.FireEye.VirusTotal.IPReturn[0].DetectedCommunicatingSamples[i].Positives > 0)
            {
              lFidoReturnValues.BadDetectedComms += 1;
            }
          }
        }
        if (lFidoReturnValues.FireEye.VirusTotal.IPReturn[0].DetectedDownloadedSamples != null)
        {
          for (var i = 0;
            i < lFidoReturnValues.FireEye.VirusTotal.IPReturn[0].DetectedDownloadedSamples.Count();
            i++)
          {
            if (lFidoReturnValues.FireEye.VirusTotal.IPReturn[0].DetectedDownloadedSamples[i].Positives > 0)
            {
              lFidoReturnValues.BadDetectedDownloads += 1;
            }
          }
        }
        if (lFidoReturnValues.FireEye.VirusTotal.IPReturn[0].DetectedUrls != null)
        {
          for (var i = 0; i < lFidoReturnValues.FireEye.VirusTotal.IPReturn[0].DetectedUrls.Count(); i++)
          {
            if (lFidoReturnValues.FireEye.VirusTotal.IPReturn[0].DetectedUrls[i].Positives > 0)
            {
              lFidoReturnValues.BadDetectedUrls += 1;
            }
          }
        }
      }
      //Check AlienVault for values
      if (lFidoReturnValues.FireEye.AlienVault != null)
      {
        replacements.Add("%alienrisk%", lFidoReturnValues.FireEye.AlienVault.Risk != null ? lFidoReturnValues.FireEye.AlienVault.Risk.ToString(CultureInfo.InvariantCulture) : "Not Found");
        replacements.Add("%alienreliable%", lFidoReturnValues.FireEye.AlienVault.Reliability != null ? lFidoReturnValues.FireEye.AlienVault.Reliability.ToString(CultureInfo.InvariantCulture) : "Not Found");
        replacements.Add("%alienactivity%", lFidoReturnValues.FireEye.AlienVault.Activity ?? string.Empty);
      }
      else
      {
        replacements.Add("%alienrisk%", "Not Found");
        replacements.Add("%alienreliable%", "Not Found");
        replacements.Add("%alienactivity%", string.Empty);
      }

      //Check Bit9 for values
      replacements.Add("%bit9threat%", "Not Configured");
      replacements.Add("%bit9trust%", "Not Configured");
      replacements = MPSBadGuyReplacements(lFidoReturnValues, replacements);
      return replacements;
    }

    private static Dictionary<string, string> MPSBadGuyReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements )
    {

      //todo: need to filter this section based on detector (ie., not just lfidoreturnvalues.cyphort.virustotal, ldfidoreturnvalues.fireeye.virustotal, etc)
      if (lFidoReturnValues.CurrentDetector == "mps")
      {
        if (lFidoReturnValues.BadDetectedComms > 0)
        {
          replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.FireEye.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedComms + " Detected!</a>");
        }
        else
        {
          replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.FireEye.VirusTotal.IPUrl + "'>None Detected</a>");
        }

        if (lFidoReturnValues.BadDetectedDownloads > 0)
        {
          replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.FireEye.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedDownloads + " Detected!</a>");
        }
        else
        {
          replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.FireEye.VirusTotal.IPUrl + "'>None Detected</a>");
        }

        if (lFidoReturnValues.BadDetectedUrls > 0)
        {
          replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.FireEye.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedUrls + " Detected!</a>");
        }
        else
        {
          replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.FireEye.VirusTotal.IPUrl + "'>None Detected</a>");
        }
      }

      return replacements;
    }

    private static Dictionary<string, string> VTReplacements(FidoReturnValues lFidoReturnValues, List<string> lBadMD5Hashes, List<string> lGoodMD5Hashes, List<string> lBadURLs, List<string> lGoodURLs, Dictionary<string, string> replacements)
    {

      if (lBadMD5Hashes.Count() == 1)
      {
        replacements.Add("%totalbadfiles%", "<a href='" + lBadMD5Hashes[0] + "'>" + lFidoReturnValues.BadHashs.ToString(CultureInfo.InvariantCulture) + "</a>");
      }
      else if (lFidoReturnValues.BadHashs > 1)
      {
        var sBadReplacement = string.Empty;
        for (var i = 0; i < lFidoReturnValues.BadHashs; i++)
        {
          if (i == (lFidoReturnValues.BadHashs - 1))
          {
            sBadReplacement += "<a href='" + lBadMD5Hashes[i] + "'>" + (i + 1).ToString(CultureInfo.InvariantCulture) + "</a>";
          }
          else
          {
            sBadReplacement += "<a href='" + lBadMD5Hashes[i] + "'>" + (i + 1).ToString(CultureInfo.InvariantCulture) + "</a>, ";
          }
        }
        replacements.Add("%totalbadfiles%", sBadReplacement);
      }
      else
      {
        replacements.Add("%totalbadfiles%", "0");
      }

      if (lGoodMD5Hashes.Count() == 1)
      {
        replacements.Add("%totalgoodfiles%", "<a href='" + lGoodMD5Hashes[0] + "'>1</a>");
      }
      else if (lGoodMD5Hashes.Count() > 1)
      {
        string sGoodReplacement;
        sGoodReplacement = "<a href=''>1.." + lGoodMD5Hashes.Count + "</a>";
        replacements.Add("%totalgoodfiles%", sGoodReplacement);
      }
      else
      {
        replacements.Add("%totalgoodfiles%", "0");
      }

      if (lBadURLs.Count() == 1)
      {
        replacements.Add("%totalbadurls%", "<a href='" + lBadURLs[0] + "'>1</a>");
      }
      else if (lFidoReturnValues.BadUrLs > 1)
      {
        var sNewReplacement = string.Empty;
        for (var i = 0; i < lFidoReturnValues.BadUrLs -1; i++)
        {
          if (i == (lBadURLs.Count() - 1))
          {
            sNewReplacement += "<a href='" + lBadURLs[i] + "'>" + (i + 1).ToString(CultureInfo.InvariantCulture) + "</a>";
          }
          else
          {
            sNewReplacement += "<a href='" + lBadURLs[i] + "'>" + (i + 1).ToString(CultureInfo.InvariantCulture) + "</a>, ";
          }
        }
        replacements.Add("%totalbadurls%", sNewReplacement);
      }
      else
      {
        replacements.Add("%totalbadurls%", "0");
      }

      if (lGoodURLs.Count() == 1)
      {
        replacements.Add("%totalgoodurls%", "<a href='" + lGoodURLs[0] + "'>1</a>");
      }
      else if (lGoodURLs.Count() > 1)
      {
        var sGoodReplacement = string.Empty;
        sGoodReplacement += "<a href=''>1.." + lGoodURLs.Count + "</a>";
        replacements.Add("%totalgoodurls%", sGoodReplacement);
      }
      else
      {
        replacements.Add("%totalgoodurls%", "0");
      }

      return replacements;
    }

  }
}
