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
  static class Notification_Cyphort_Helper
  {

    public static Dictionary<string, string> CyphortBadGuyReturn(FidoReturnValues lFidoReturnValues, List<string> lBadMD5Hashes, List<string> lGoodMD5Hashes, List<string> lBadURLs, List<string> lGoodURLs, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.Cyphort.VirusTotal != null)
      {
        if (lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn != null)
        {
          for (var i = 0; i < lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn.Count(); i++)
          {
            if (lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn[i].Positives > 0)
            {
              lFidoReturnValues.BadHashs += 1;
              lBadMD5Hashes.Add(lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn[i].Permalink);
            }
            else
            {
              lGoodMD5Hashes.Add(lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn[i].Permalink);
            }
          }
        }

        if (lFidoReturnValues.Cyphort.VirusTotal.URLReturn != null)
        {
          for (var i = 0; i < lFidoReturnValues.Cyphort.VirusTotal.URLReturn.Count(); i++)
          {
            if (lFidoReturnValues.Cyphort.VirusTotal.URLReturn[i].Positives > 0)
            {
              lFidoReturnValues.BadUrLs += 1;
              lBadURLs.Add(lFidoReturnValues.Cyphort.VirusTotal.URLReturn[i].Permalink);
            }
            else
            {
              lGoodURLs.Add(lFidoReturnValues.Cyphort.VirusTotal.URLReturn[i].Permalink);
            }
          }
        }
        if (lFidoReturnValues.Cyphort.VirusTotal.IPReturn != null)
        {
          if (lFidoReturnValues.Cyphort.VirusTotal.IPReturn[0].DetectedCommunicatingSamples != null)
          {
            for (var i = 0;
              i < lFidoReturnValues.Cyphort.VirusTotal.IPReturn[0].DetectedCommunicatingSamples.Count();
              i++)
            {
              if (lFidoReturnValues.Cyphort.VirusTotal.IPReturn[0].DetectedCommunicatingSamples[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedComms += 1;
              }
            }
          }
          if (lFidoReturnValues.Cyphort.VirusTotal.IPReturn[0].DetectedDownloadedSamples != null)
          {
            for (var i = 0;
              i < lFidoReturnValues.Cyphort.VirusTotal.IPReturn[0].DetectedDownloadedSamples.Count();
              i++)
            {
              if (lFidoReturnValues.Cyphort.VirusTotal.IPReturn[0].DetectedDownloadedSamples[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedDownloads += 1;
              }
            }
          }
          if (lFidoReturnValues.Cyphort.VirusTotal.IPReturn[0].DetectedUrls != null)
          {
            for (var i = 0; i < lFidoReturnValues.Cyphort.VirusTotal.IPReturn[0].DetectedUrls.Count(); i++)
            {
              if (lFidoReturnValues.Cyphort.VirusTotal.IPReturn[0].DetectedUrls[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedUrls += 1;
              }
            }
          }
        }
      }
      replacements = CyphortBadGuyReplacements(lFidoReturnValues, replacements);
      return replacements;
    }

    private static Dictionary<string, string> CyphortBadGuyReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      //todo: need to filter this section based on detector (ie., not just lfidoreturnvalues.cyphort.virustotal, ldfidoreturnvalues.fireeye.virustotal, etc)
      if (lFidoReturnValues.CurrentDetector.Contains("cyphort"))
      {
        replacements = CyphortVTReplacements(lFidoReturnValues, replacements);
        replacements = CyphortGEOReplacements(lFidoReturnValues, replacements);
        replacements = CyphortThreatGRIDReplacements(lFidoReturnValues, replacements);
      }

      return replacements;
    }

    private static Dictionary<string, string> CyphortThreatGRIDReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.Cyphort.ThreatGRID.ThreatScore > 0)
      {
        replacements.Add("%threatgridscore%", lFidoReturnValues.Cyphort.ThreatGRID.ThreatScore.ToString(CultureInfo.InvariantCulture));
      }
      else
      {
        replacements.Add("%threatgridscore%", "0");
      }
      if (lFidoReturnValues.Cyphort.ThreatGRID.ThreatSeverity > 0)
      {
        if ((lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count > 0) && (lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Data.Items.Any()))
        {
          //todo: move this to the DB
          replacements.Add("%threatgridseverity%", "<a href='%url_location%'>" + lFidoReturnValues.Cyphort.ThreatGRID.ThreatSeverity.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridseverity%", lFidoReturnValues.Cyphort.ThreatGRID.ThreatSeverity.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridseverity%", "0");
      }
      if (lFidoReturnValues.Cyphort.ThreatGRID.ThreatConfidence > 0)
      {
        if ((lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count > 0) && (lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Data.Items.Any()))
        {
          //todo: move this to the DB
          replacements.Add("%threatgridconfidence%", "<a href='%url_location%'>" + lFidoReturnValues.Cyphort.ThreatGRID.ThreatConfidence.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridconfidence%", lFidoReturnValues.Cyphort.ThreatGRID.ThreatConfidence.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridconfidence%", "0");
      }
      if (lFidoReturnValues.Cyphort.ThreatGRID.ThreatIndicators > 0)
      {
        if ((lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count > 0) && (lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Data.Items.Any()))
        {
          //todo: move this to the DB
          replacements.Add("%threatgridindicators%", "<a href='%url_location%'>" + lFidoReturnValues.Cyphort.ThreatGRID.ThreatIndicators.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridindicators%", lFidoReturnValues.Cyphort.ThreatGRID.ThreatIndicators.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridindicators%", "0");
      }

      return replacements;
    }

    private static Dictionary<string, string> CyphortVTReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.Cyphort.VirusTotal.VirusTotalScore > 0)
      {
        replacements.Add("%virustotalscore%", lFidoReturnValues.Cyphort.VirusTotal.VirusTotalScore.ToString(CultureInfo.InvariantCulture));
      }
      else
      {
        replacements.Add("%virustotalscore%", "0");
      }
      if (lFidoReturnValues.BadDetectedComms > 0)
      {
        replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.Cyphort.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedComms + " Detected!</a>");
      }
      else
      {
        replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.Cyphort.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      if (lFidoReturnValues.BadDetectedDownloads > 0)
      {
        replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.Cyphort.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedDownloads + " Detected!</a>");
      }
      else
      {
        replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.Cyphort.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      if (lFidoReturnValues.BadDetectedUrls > 0)
      {
        replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.Cyphort.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedUrls + " Detected!</a>");
      }
      else
      {
        replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.Cyphort.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      return replacements;
    }

    private static Dictionary<string, string> CyphortGEOReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.Cyphort.ThreatGRID.IPInfo != null)
      {
        if (lFidoReturnValues.Cyphort.ThreatGRID.IPInfo.Data_Array.ASN_Array.ASN == null)
        {
          replacements.Add("%asninfo%", string.Empty);
          replacements.Add("%city%", string.Empty);
          replacements.Add("%region%", string.Empty);
          replacements.Add("%country%", string.Empty);
        }
        else
        {
          replacements.Add("%asninfo%", lFidoReturnValues.Cyphort.ThreatGRID.IPInfo.Data_Array.ASN_Array.ASN + ":" + lFidoReturnValues.Cyphort.ThreatGRID.IPInfo.Data_Array.ASN_Array.Org);
          replacements.Add("%city%", lFidoReturnValues.Cyphort.ThreatGRID.IPInfo.Data_Array.Location_Array.City);
          replacements.Add("%region%", lFidoReturnValues.Cyphort.ThreatGRID.IPInfo.Data_Array.Location_Array.Region);
          replacements.Add("%country%", lFidoReturnValues.Cyphort.ThreatGRID.IPInfo.Data_Array.Location_Array.Country);
        }
      }
      else if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_country_code != null)
      {
        replacements.Add("%city%", string.Empty);
        replacements.Add("%region%", lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_country_code);
        if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_country_name != null)
        {
          replacements.Add("%country%", lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_country_name);
        }
      }

      return replacements;
    }

  }
}
