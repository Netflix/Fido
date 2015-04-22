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
  class Notification_PaloAlto_Helper
  {

    public static Dictionary<string, string> PaloAltoBadGuyReturn(FidoReturnValues lFidoReturnValues, List<string> lBadMD5Hashes, List<string> lGoodMD5Hashes, List<string> lBadURLs, List<string> lGoodURLs, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.PaloAlto.VirusTotal != null)
      {
        if (lFidoReturnValues.PaloAlto.VirusTotal.MD5HashReturn != null)
        {
          for (var i = 0; i < lFidoReturnValues.PaloAlto.VirusTotal.MD5HashReturn.Count(); i++)
          {
            if (lFidoReturnValues.PaloAlto.VirusTotal.MD5HashReturn[i].Positives > 0)
            {
              lFidoReturnValues.BadHashs += 1;
              lBadMD5Hashes.Add(lFidoReturnValues.PaloAlto.VirusTotal.MD5HashReturn[i].Permalink);
            }
            else
            {
              lGoodMD5Hashes.Add(lFidoReturnValues.PaloAlto.VirusTotal.MD5HashReturn[i].Permalink);
            }
          }
        }

        if (lFidoReturnValues.PaloAlto.VirusTotal.URLReturn != null)
        {
          for (var i = 0; i < lFidoReturnValues.PaloAlto.VirusTotal.URLReturn.Count(); i++)
          {
            if (lFidoReturnValues.PaloAlto.VirusTotal.URLReturn[i].Positives > 0)
            {
              lFidoReturnValues.BadUrLs += 1;
              lBadURLs.Add(lFidoReturnValues.PaloAlto.VirusTotal.URLReturn[i].Permalink);
            }
            else
            {
              lGoodURLs.Add(lFidoReturnValues.PaloAlto.VirusTotal.URLReturn[i].Permalink);
            }
          }
        }
        if (lFidoReturnValues.PaloAlto.VirusTotal.IPReturn != null)
        {
          if (lFidoReturnValues.PaloAlto.VirusTotal.IPReturn[0].DetectedCommunicatingSamples != null)
          {
            for (var i = 0;
              i < lFidoReturnValues.PaloAlto.VirusTotal.IPReturn[0].DetectedCommunicatingSamples.Count();
              i++)
            {
              if (lFidoReturnValues.PaloAlto.VirusTotal.IPReturn[0].DetectedCommunicatingSamples[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedComms += 1;
              }
            }
          }
          if (lFidoReturnValues.PaloAlto.VirusTotal.IPReturn[0].DetectedDownloadedSamples != null)
          {
            for (var i = 0;
              i < lFidoReturnValues.PaloAlto.VirusTotal.IPReturn[0].DetectedDownloadedSamples.Count();
              i++)
            {
              if (lFidoReturnValues.PaloAlto.VirusTotal.IPReturn[0].DetectedDownloadedSamples[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedDownloads += 1;
              }
            }
          }
          if (lFidoReturnValues.PaloAlto.VirusTotal.IPReturn[0].DetectedUrls != null)
          {
            for (var i = 0; i < lFidoReturnValues.PaloAlto.VirusTotal.IPReturn[0].DetectedUrls.Count(); i++)
            {
              if (lFidoReturnValues.PaloAlto.VirusTotal.IPReturn[0].DetectedUrls[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedUrls += 1;
              }
            }
          }
        }
      }

      //Check Bit9 for values
      replacements.Add("%bit9threat%", "Not Configured");
      replacements.Add("%bit9trust%", "Not Configured");
      replacements = PaloAltoBadGuyReplacements(lFidoReturnValues, replacements);
      return replacements;
    }

    private static Dictionary<string, string> PaloAltoBadGuyReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      replacements = PaloAltoVTReplacements(lFidoReturnValues, replacements);

      replacements = PaloAltoGeoReplacements(lFidoReturnValues, replacements);

      replacements = PaloAltoThreatGRIDReplacements(lFidoReturnValues, replacements);

      return replacements;
    }

    private static Dictionary<string, string> PaloAltoGeoReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo != null)
      {
        if (lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo.Data_Array.ASN_Array.ASN == null)
        {
          replacements.Add("%asninfo%", "No ASN Found");
        }
        else
        {
          replacements.Add("%asninfo%", lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo.Data_Array.ASN_Array.ASN + ":" + lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo.Data_Array.ASN_Array.Org);
        }
        if (lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo.Data_Array.Location_Array != null)
        {
          if (lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo.Data_Array.Location_Array.City != null)
          {
            replacements.Add("%city%", lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo.Data_Array.Location_Array.City);
          }
          if (lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo.Data_Array.Location_Array.Country != null)
          {
            replacements.Add("%country%", lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo.Data_Array.Location_Array.Country);
          }
          if (lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo.Data_Array.Location_Array.Region != null)
          {
            replacements.Add("%region%", lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo.Data_Array.Location_Array.Region);
          }
        }
      }

      return replacements;
    }

    private static Dictionary<string, string> PaloAltoVTReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.PaloAlto.VirusTotal.VirusTotalScore > 0)
      {
        replacements.Add("%virustotalscore%", lFidoReturnValues.PaloAlto.VirusTotal.VirusTotalScore.ToString(CultureInfo.InvariantCulture));
      }
      else
      {
        replacements.Add("%virustotalscore%", "0");
      }
      if (lFidoReturnValues.BadDetectedComms > 0)
      {
        replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.PaloAlto.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedComms + " Detected!</a>");
      }
      else
      {
        replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.PaloAlto.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      if (lFidoReturnValues.BadDetectedDownloads > 0)
      {
        replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.PaloAlto.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedDownloads + " Detected!</a>");
      }
      else
      {
        replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.PaloAlto.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      if (lFidoReturnValues.BadDetectedUrls > 0)
      {
        replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.PaloAlto.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedUrls + " Detected!</a>");
      }
      else
      {
        replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.PaloAlto.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      return replacements;
    }

    private static Dictionary<string, string> PaloAltoThreatGRIDReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.PaloAlto.ThreatGRID.ThreatScore > 0)
      {
        replacements.Add("%threatgridscore%", lFidoReturnValues.PaloAlto.ThreatGRID.ThreatScore.ToString(CultureInfo.InvariantCulture));
      }
      else
      {
        replacements.Add("%threatgridscore%", "0");
      }
      if (lFidoReturnValues.PaloAlto.ThreatGRID.ThreatSeverity > 0)
      {
        if ((lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count > 0) && (lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.Items.Any()))
        {
          replacements.Add("%threatgridseverity%", "<a href='%url_location%'>" + lFidoReturnValues.PaloAlto.ThreatGRID.ThreatSeverity.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridseverity%", lFidoReturnValues.PaloAlto.ThreatGRID.ThreatSeverity.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridseverity%", "0");
      }
      if (lFidoReturnValues.PaloAlto.ThreatGRID.ThreatConfidence > 0)
      {
        if ((lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count > 0) && (lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.Items.Any()))
        {
          replacements.Add("%threatgridconfidence%", "<a href='%url_location%'>" + lFidoReturnValues.PaloAlto.ThreatGRID.ThreatConfidence.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridconfidence%", lFidoReturnValues.PaloAlto.ThreatGRID.ThreatConfidence.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridconfidence%", "0");
      }
      if (lFidoReturnValues.PaloAlto.ThreatGRID.ThreatIndicators > 0)
      {
        if ((lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count > 0) && (lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.Items.Any()))
        {
          replacements.Add("%threatgridindicators%", "<a href='%url_location%'>" + lFidoReturnValues.PaloAlto.ThreatGRID.ThreatIndicators.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridindicators%", lFidoReturnValues.PaloAlto.ThreatGRID.ThreatIndicators.ToString(CultureInfo.InvariantCulture));
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
