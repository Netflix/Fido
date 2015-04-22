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
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Notification.Notification_Helper
{
  class Notification_CarbonBlack_Helper
  {

    public static Dictionary<string, string> CarbonBlackBadGuyReturn(FidoReturnValues lFidoReturnValues, List<string> lBadMD5Hashes, List<string> lGoodMD5Hashes, List<string> lBadURLs, List<string> lGoodURLs, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.CB.Alert.VirusTotal != null)
      {
        if (lFidoReturnValues.CB.Alert.VirusTotal.MD5HashReturn != null)
        {
          for (var i = 0; i < lFidoReturnValues.CB.Alert.VirusTotal.MD5HashReturn.Count(); i++)
          {
            if (lFidoReturnValues.CB.Alert.VirusTotal.MD5HashReturn[i].Positives > 0)
            {
              lFidoReturnValues.BadHashs += 1;
              lBadMD5Hashes.Add(lFidoReturnValues.CB.Alert.VirusTotal.MD5HashReturn[i].Permalink);
            }
            else
            {
              lGoodMD5Hashes.Add(lFidoReturnValues.CB.Alert.VirusTotal.MD5HashReturn[i].Permalink);
            }
          }
        }

        if (lFidoReturnValues.CB.Alert.VirusTotal.URLReturn != null)
        {
          for (var i = 0; i < lFidoReturnValues.CB.Alert.VirusTotal.URLReturn.Count(); i++)
          {
            if (lFidoReturnValues.CB.Alert.VirusTotal.URLReturn[i].Positives > 0)
            {
              lFidoReturnValues.BadUrLs += 1;
              lBadURLs.Add(lFidoReturnValues.CB.Alert.VirusTotal.URLReturn[i].Permalink);
            }
            else
            {
              lGoodURLs.Add(lFidoReturnValues.CB.Alert.VirusTotal.URLReturn[i].Permalink);
            }
          }
        }
        if (lFidoReturnValues.CB.Alert.VirusTotal.IPReturn != null)
        {
          if (lFidoReturnValues.CB.Alert.VirusTotal.IPReturn[0].DetectedCommunicatingSamples != null)
          {
            for (var i = 0;
              i < lFidoReturnValues.CB.Alert.VirusTotal.IPReturn[0].DetectedCommunicatingSamples.Count();
              i++)
            {
              if (lFidoReturnValues.CB.Alert.VirusTotal.IPReturn[0].DetectedCommunicatingSamples[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedComms += 1;
              }
            }
          }
          if (lFidoReturnValues.CB.Alert.VirusTotal.IPReturn[0].DetectedDownloadedSamples != null)
          {
            for (var i = 0;
              i < lFidoReturnValues.CB.Alert.VirusTotal.IPReturn[0].DetectedDownloadedSamples.Count();
              i++)
            {
              if (lFidoReturnValues.CB.Alert.VirusTotal.IPReturn[0].DetectedDownloadedSamples[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedDownloads += 1;
              }
            }
          }
          if (lFidoReturnValues.CB.Alert.VirusTotal.IPReturn[0].DetectedUrls != null)
          {
            for (var i = 0; i < lFidoReturnValues.CB.Alert.VirusTotal.IPReturn[0].DetectedUrls.Count(); i++)
            {
              if (lFidoReturnValues.CB.Alert.VirusTotal.IPReturn[0].DetectedUrls[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedUrls += 1;
              }
            }
          }
        }
      }

      //Check AlienVault for values
      if (lFidoReturnValues.CB.Alert.AlienVault != null)
      {
        replacements.Add("%alienrisk%", lFidoReturnValues.CB.Alert.AlienVault.Risk.ToString(CultureInfo.InvariantCulture));
        replacements.Add("%alienreliable%", lFidoReturnValues.CB.Alert.AlienVault.Reliability.ToString(CultureInfo.InvariantCulture));
        replacements.Add("%alienactivity%", lFidoReturnValues.CB.Alert.AlienVault.Activity ?? string.Empty);
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
      replacements = CarbonBlackBadGuyReplacements(lFidoReturnValues, replacements);
      return replacements;
    }

    private static Dictionary<string, string> CarbonBlackBadGuyReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      try
      {
        if (Object_Fido_Configs.GetAsBool("fido.director.virustotal", false)) replacements = CarbonBlackVTReplacements(lFidoReturnValues, replacements);

        if (Object_Fido_Configs.GetAsBool("fido.director.threatgrid", false)) replacements = CarbonBlackGeoReplacements(lFidoReturnValues, replacements);

        if (Object_Fido_Configs.GetAsBool("fido.director.threatgrid", false)) replacements = CarbonBlackThreatGRIDReplacements(lFidoReturnValues, replacements);

        return replacements;

      }
      catch (Exception e)
      {
        throw e;
      }
    }

    private static Dictionary<string, string> CarbonBlackGeoReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.CB.Alert != null)
      {
        replacements.Add("%asninfo%", "Location and ASN unknown");
        replacements.Add("%city%", string.Empty);
        replacements.Add("%country%", string.Empty);
        replacements.Add("%region%", string.Empty);
        return replacements;
      }
      return replacements;
    }

    private static Dictionary<string, string> CarbonBlackVTReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.CB.Alert.VirusTotal.VirusTotalScore > 0)
      {
        replacements.Add("%virustotalscore%", lFidoReturnValues.CB.Alert.VirusTotal.VirusTotalScore.ToString(CultureInfo.InvariantCulture));
      }
      else
      {
        replacements.Add("%virustotalscore%", "0");
      }
      if (lFidoReturnValues.BadDetectedComms > 0)
      {
        replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.CB.Alert.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedComms + " Detected!</a>");
      }
      else
      {
        replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.CB.Alert.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      if (lFidoReturnValues.BadDetectedDownloads > 0)
      {
        replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.CB.Alert.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedDownloads + " Detected!</a>");
      }
      else
      {
        replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.CB.Alert.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      if (lFidoReturnValues.BadDetectedUrls > 0)
      {
        replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.CB.Alert.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedUrls + " Detected!</a>");
      }
      else
      {
        replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.CB.Alert.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      return replacements;
    }

    private static Dictionary<string, string> CarbonBlackThreatGRIDReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.CB.Alert.ThreatGRID.ThreatScore > 0)
      {
        replacements.Add("%threatgridscore%", lFidoReturnValues.CB.Alert.ThreatGRID.ThreatScore.ToString(CultureInfo.InvariantCulture));
      }
      else
      {
        replacements.Add("%threatgridscore%", "0");
      }
      if (lFidoReturnValues.CB.Alert.ThreatGRID.ThreatSeverity > 0)
      {
        if ((lFidoReturnValues.CB.Alert.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.CB.Alert.ThreatGRID.IPThreatInfo.Count > 0) && (lFidoReturnValues.CB.Alert.ThreatGRID.IPSearch.Data.Items.Any()))
        {
          replacements.Add("%threatgridseverity%", "<a href='%url_location%'>" + lFidoReturnValues.CB.Alert.ThreatGRID.ThreatSeverity.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridseverity%", lFidoReturnValues.CB.Alert.ThreatGRID.ThreatSeverity.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridseverity%", "0");
      }
      if (lFidoReturnValues.CB.Alert.ThreatGRID.ThreatConfidence > 0)
      {
        if ((lFidoReturnValues.CB.Alert.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.CB.Alert.ThreatGRID.IPThreatInfo.Count > 0) && (lFidoReturnValues.CB.Alert.ThreatGRID.IPSearch.Data.Items.Any()))
        {
          replacements.Add("%threatgridconfidence%", "<a href='%url_location%'>" + lFidoReturnValues.CB.Alert.ThreatGRID.ThreatConfidence.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridconfidence%", lFidoReturnValues.CB.Alert.ThreatGRID.ThreatConfidence.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridconfidence%", "0");
      }
      if (lFidoReturnValues.CB.Alert.ThreatGRID.ThreatIndicators > 0)
      {
        if ((lFidoReturnValues.CB.Alert.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.CB.Alert.ThreatGRID.IPThreatInfo.Count > 0) && (lFidoReturnValues.CB.Alert.ThreatGRID.IPSearch.Data.Items.Any()))
        {
          replacements.Add("%threatgridindicators%", "<a href='%url_location%'>" + lFidoReturnValues.CB.Alert.ThreatGRID.ThreatIndicators.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridindicators%", lFidoReturnValues.CB.Alert.ThreatGRID.ThreatIndicators.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridindicators%", "0");
      }

      return replacements;
    }

  }
}
