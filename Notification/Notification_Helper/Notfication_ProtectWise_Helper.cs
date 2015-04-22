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
using System.Globalization;
using System.Linq;
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Notification.Notification_Helper
{
  static class Notfication_ProtectWise_Helper
  {

    public static Dictionary<string, string> ProtectWiseBadGuyReturn(FidoReturnValues lFidoReturnValues, List<string> lBadMD5Hashes, List<string> lGoodMD5Hashes, List<string> lBadURLs, List<string> lGoodURLs, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.ProtectWise.VirusTotal != null)
      {
        if (lFidoReturnValues.ProtectWise.VirusTotal.MD5HashReturn != null)
        {
          for (var i = 0; i < lFidoReturnValues.ProtectWise.VirusTotal.MD5HashReturn.Count(); i++)
          {
            if (lFidoReturnValues.ProtectWise.VirusTotal.MD5HashReturn[i].Positives > 0)
            {
              lFidoReturnValues.BadHashs += 1;
              lBadMD5Hashes.Add(lFidoReturnValues.ProtectWise.VirusTotal.MD5HashReturn[i].Permalink);
            }
            else
            {
              lGoodMD5Hashes.Add(lFidoReturnValues.ProtectWise.VirusTotal.MD5HashReturn[i].Permalink);
            }
          }
        }

        if (lFidoReturnValues.ProtectWise.VirusTotal.URLReturn != null)
        {
          for (var i = 0; i < lFidoReturnValues.ProtectWise.VirusTotal.URLReturn.Count(); i++)
          {
            if (lFidoReturnValues.ProtectWise.VirusTotal.URLReturn[i].Positives > 0)
            {
              lFidoReturnValues.BadUrLs += 1;
              lBadURLs.Add(lFidoReturnValues.ProtectWise.VirusTotal.URLReturn[i].Permalink);
            }
            else
            {
              lGoodURLs.Add(lFidoReturnValues.ProtectWise.VirusTotal.URLReturn[i].Permalink);
            }
          }
        }
        if (lFidoReturnValues.ProtectWise.VirusTotal.IPReturn != null)
        {
          if (lFidoReturnValues.ProtectWise.VirusTotal.IPReturn[0].DetectedCommunicatingSamples != null)
          {
            for (var i = 0;
              i < lFidoReturnValues.ProtectWise.VirusTotal.IPReturn[0].DetectedCommunicatingSamples.Count();
              i++)
            {
              if (lFidoReturnValues.ProtectWise.VirusTotal.IPReturn[0].DetectedCommunicatingSamples[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedComms += 1;
              }
            }
          }
          if (lFidoReturnValues.ProtectWise.VirusTotal.IPReturn[0].DetectedDownloadedSamples != null)
          {
            for (var i = 0;
              i < lFidoReturnValues.ProtectWise.VirusTotal.IPReturn[0].DetectedDownloadedSamples.Count();
              i++)
            {
              if (lFidoReturnValues.ProtectWise.VirusTotal.IPReturn[0].DetectedDownloadedSamples[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedDownloads += 1;
              }
            }
          }
          if (lFidoReturnValues.ProtectWise.VirusTotal.IPReturn[0].DetectedUrls != null)
          {
            for (var i = 0; i < lFidoReturnValues.ProtectWise.VirusTotal.IPReturn[0].DetectedUrls.Count(); i++)
            {
              if (lFidoReturnValues.ProtectWise.VirusTotal.IPReturn[0].DetectedUrls[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedUrls += 1;
              }
            }
          }
        }
      }

      //Check AlienVault for values
      if (lFidoReturnValues.ProtectWise.AlienVault != null)
      {
        replacements.Add("%alienrisk%", lFidoReturnValues.ProtectWise.AlienVault.Risk.ToString(CultureInfo.InvariantCulture));
        replacements.Add("%alienreliable%", lFidoReturnValues.ProtectWise.AlienVault.Reliability.ToString(CultureInfo.InvariantCulture));
        replacements.Add("%alienactivity%", lFidoReturnValues.ProtectWise.AlienVault.Activity ?? string.Empty);
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
      replacements = ProtectWiseBadGuyReplacements(lFidoReturnValues, replacements);
      return replacements;
    }

    private static Dictionary<string, string> ProtectWiseBadGuyReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      replacements = ProtectWiseVTReplacements(lFidoReturnValues, replacements);

      replacements = ProtectWiseGeoReplacements(lFidoReturnValues, replacements);

      replacements = ProtectWiseThreatGRIDReplacements(lFidoReturnValues, replacements);

      return replacements;
    }

    private static Dictionary<string, string> ProtectWiseGeoReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.ProtectWise.GEO == null)
      {
        replacements.Add("%asninfo%", "Location and ASN unknown");
        replacements.Add("%city%", string.Empty);
        replacements.Add("%country%", string.Empty);
        replacements.Add("%region%", string.Empty);
        return replacements;
      }
      if (lFidoReturnValues.ProtectWise.GEO.Destination != null)
      {
        if (lFidoReturnValues.ProtectWise.GEO.Destination.City != null)
        {
          replacements.Add("%city%", lFidoReturnValues.ProtectWise.GEO.Destination.City.Name);
        }
        else
        {
          replacements.Add("%city%", string.Empty);
        }
        if (lFidoReturnValues.ProtectWise.GEO.Destination.Country != null)
        {
          replacements.Add("%country%", lFidoReturnValues.ProtectWise.GEO.Destination.Country.Name);
        }
        else
        {
          replacements.Add("%country%", string.Empty);
        }
        if (lFidoReturnValues.ProtectWise.GEO.Destination.Continent != null)
        {
          replacements.Add("%region%", lFidoReturnValues.ProtectWise.GEO.Destination.Continent.Name);
        }
        else
        {
          replacements.Add("%region%", string.Empty);
        }
        if (lFidoReturnValues.ProtectWise.GEO.Destination.Organization != null)
        {
          replacements.Add("%asninfo%", lFidoReturnValues.ProtectWise.GEO.Destination.Organization);
        }
        else
        {
          replacements.Add("%asninfo%", string.Empty);
        }
      }
      else if (lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo != null)
      {
        if (lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo.Data_Array.ASN_Array.ASN == null)
        {
          replacements.Add("%asninfo%", "No ASN Found");
        }
        else
        {
          replacements.Add("%asninfo%", lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo.Data_Array.ASN_Array.ASN + ":" + lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo.Data_Array.ASN_Array.Org);
        }
        if (lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo.Data_Array.Location_Array != null)
        {
          if (lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo.Data_Array.Location_Array.City != null)
          {
            replacements.Add("%city%", lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo.Data_Array.Location_Array.City);
          }
          if (lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo.Data_Array.Location_Array.Country != null)
          {
            replacements.Add("%country%", lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo.Data_Array.Location_Array.Country);
          }
          if (lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo.Data_Array.Location_Array.Region != null)
          {
            replacements.Add("%region%", lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo.Data_Array.Location_Array.Region);
          }
        }
      }

      return replacements;
    }

    private static Dictionary<string, string> ProtectWiseVTReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.ProtectWise.VirusTotal.VirusTotalScore > 0)
      {
        replacements.Add("%virustotalscore%", lFidoReturnValues.ProtectWise.VirusTotal.VirusTotalScore.ToString(CultureInfo.InvariantCulture));
      }
      else
      {
        replacements.Add("%virustotalscore%", "0");
      }
      if (lFidoReturnValues.BadDetectedComms > 0)
      {
        replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.ProtectWise.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedComms + " Detected!</a>");
      }
      else
      {
        replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.ProtectWise.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      if (lFidoReturnValues.BadDetectedDownloads > 0)
      {
        replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.ProtectWise.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedDownloads + " Detected!</a>");
      }
      else
      {
        replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.ProtectWise.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      if (lFidoReturnValues.BadDetectedUrls > 0)
      {
        replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.ProtectWise.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedUrls + " Detected!</a>");
      }
      else
      {
        replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.ProtectWise.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      return replacements;
    }

    private static Dictionary<string, string> ProtectWiseThreatGRIDReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.ProtectWise.ThreatGRID.ThreatScore > 0)
      {
        replacements.Add("%threatgridscore%", lFidoReturnValues.ProtectWise.ThreatGRID.ThreatScore.ToString(CultureInfo.InvariantCulture));
      }
      else
      {
        replacements.Add("%threatgridscore%", "0");
      }
      if (lFidoReturnValues.ProtectWise.ThreatGRID.ThreatSeverity > 0)
      {
        if ((lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count > 0) && (lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.Items.Any()))
        {
          replacements.Add("%threatgridseverity%", "<a href='%url_location%'>" + lFidoReturnValues.ProtectWise.ThreatGRID.ThreatSeverity.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridseverity%", lFidoReturnValues.ProtectWise.ThreatGRID.ThreatSeverity.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridseverity%", "0");
      }
      if (lFidoReturnValues.ProtectWise.ThreatGRID.ThreatConfidence > 0)
      {
        if ((lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count > 0) && (lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.Items.Any()))
        {
          replacements.Add("%threatgridconfidence%", "<a href='%url_location%'>" + lFidoReturnValues.ProtectWise.ThreatGRID.ThreatConfidence.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridconfidence%", lFidoReturnValues.ProtectWise.ThreatGRID.ThreatConfidence.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridconfidence%", "0");
      }
      if (lFidoReturnValues.ProtectWise.ThreatGRID.ThreatIndicators > 0)
      {
        if ((lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count > 0) && (lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.Items.Any()))
        {
          replacements.Add("%threatgridindicators%", "<a href='%url_location%'>" + lFidoReturnValues.ProtectWise.ThreatGRID.ThreatIndicators.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridindicators%", lFidoReturnValues.ProtectWise.ThreatGRID.ThreatIndicators.ToString(CultureInfo.InvariantCulture));
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
