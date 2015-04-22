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
using Fido_Main.Fido_Support.FidoDB;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.VirusTotal;
using VirusTotalNET.Objects;

namespace Fido_Main.Director.Scoring
{
  static class Matrix_Scoring
  {
    public static FidoReturnValues GetDetectorsScore(FidoReturnValues lFidoReturnValues)
    {
      //This section will iterate through each detector and then score each threatfeed.
      //todo: refractor each threatfeed so it's not done inside this area.

      var sDetector = lFidoReturnValues.CurrentDetector;

      switch (sDetector)
      {
        case "antivirus":
          if (lFidoReturnValues.CurrentDetector == "antivirus")
          {
            Console.WriteLine(@"Scoring AV detector information.");
            lFidoReturnValues.ThreatScore += AntiVirusScore(lFidoReturnValues);
          }
          break;

        case "bit9":
          if ((lFidoReturnValues.Bit9 != null) && (lFidoReturnValues.Bit9.VTReport != null) &&
              (lFidoReturnValues.CurrentDetector == "bit9"))
          {
            Console.WriteLine(@"Scoring Bit9 detector information.");
            var iBit9PositiveReturns = BitTotalPosReturn(lFidoReturnValues.Bit9.VTReport);
            if ((iBit9PositiveReturns[0] > 0) || (iBit9PositiveReturns[1] > 0))
            {
              lFidoReturnValues.ThreatScore += VirusTotalScore(iBit9PositiveReturns, true);
            }
          }
          break;

        case "ids":
          break;

        case "mas":
          break;

        case "mps":

          //score VirusTotal hash
          lFidoReturnValues.ThreatScore += GetMpsVTHashThreatScore(lFidoReturnValues);

          //score VirusTotal URL
          if ((lFidoReturnValues.FireEye.VirusTotal != null) &&
              (lFidoReturnValues.FireEye.VirusTotal.URLReturn != null) &&
              (lFidoReturnValues.FireEye.VirusTotal.URLReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring FireEye/VirusTotal detector URL information.");
            var iVTPositiveUrlReturns = VirusTotalPosReturnURL(lFidoReturnValues.FireEye.VirusTotal);
            if ((iVTPositiveUrlReturns[0] > 0) || (iVTPositiveUrlReturns[1] > 0))
            {
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveUrlReturns, false);
            }
          }

          //score VirusTotal IP
          if ((lFidoReturnValues.FireEye.VirusTotal != null) &&
              (lFidoReturnValues.FireEye.VirusTotal.IPReturn != null) &&
              (lFidoReturnValues.FireEye.VirusTotal.IPReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector IP information.");
            var iVTPositiveIPReturns = VirusTotalPosIPReturn(lFidoReturnValues.FireEye.VirusTotal);
            if ((iVTPositiveIPReturns[0] > 0) || (iVTPositiveIPReturns[1] > 0) || (iVTPositiveIPReturns[2] > 0))
            {
              lFidoReturnValues.ThreatScore += VirusTotalIPScore(iVTPositiveIPReturns);
            }
          }

          //score Alienvault threat feed
          if ((lFidoReturnValues.FireEye.AlienVault != null) &&
              (lFidoReturnValues.FireEye.AlienVault.Activity != null))
          {
            Console.WriteLine(@"Scoring FireEye/AlienVault IP information.");
            lFidoReturnValues.ThreatScore += AlienVaultScore(lFidoReturnValues.FireEye.AlienVault);
          }
          break;

        case "cyphortv2":
          //score VirusTotal hash
          if ((lFidoReturnValues.Cyphort.VirusTotal != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector hash information.");
            var iVTPositiveHashReturns = VirusTotalPosReturnHash(lFidoReturnValues.Cyphort.VirusTotal);
            if ((iVTPositiveHashReturns[0] > 0) || (iVTPositiveHashReturns[1] > 0))
            {
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveHashReturns, true);
            }
          }

          //score VirusTotal URL
          if ((lFidoReturnValues.Cyphort.VirusTotal != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.URLReturn != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.URLReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector URL information.");
            var iVTPositiveUrlReturns = VirusTotalPosReturnURL(lFidoReturnValues.Cyphort.VirusTotal);
            if ((iVTPositiveUrlReturns[0] > 0) || (iVTPositiveUrlReturns[1] > 0))
            {
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveUrlReturns, false);
            }
          }

          //score VirusTotal IP
          if ((lFidoReturnValues.Cyphort.VirusTotal != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.IPReturn != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.IPReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector IP information.");
            var iVTPositiveIPReturns = VirusTotalPosIPReturn(lFidoReturnValues.Cyphort.VirusTotal);
            if ((iVTPositiveIPReturns[0] > 0) || (iVTPositiveIPReturns[1] > 0) || (iVTPositiveIPReturns[2] > 0))
            {
              lFidoReturnValues.ThreatScore += VirusTotalIPScore(iVTPositiveIPReturns);
            }
          }

          //score Alienvault threat feed
          if ((lFidoReturnValues.Cyphort.AlienVault != null) &&
              (lFidoReturnValues.Cyphort.AlienVault.Activity != null))
          {
            Console.WriteLine(@"Scoring Cyphort/AlienVault detector IP information.");
            lFidoReturnValues.ThreatScore += AlienVaultScore(lFidoReturnValues.Cyphort.AlienVault);
          }
          break;

        case "cyphortv3":
          //score VirusTotal hash
          if ((lFidoReturnValues.Cyphort.VirusTotal != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector hash information.");
            var iVTPositiveHashReturns = VirusTotalPosReturnHash(lFidoReturnValues.Cyphort.VirusTotal);
            if ((iVTPositiveHashReturns[0] > 0) || (iVTPositiveHashReturns[1] > 0))
            {
              lFidoReturnValues.Cyphort.VirusTotal.VirusTotalScore += Math.Round(VirusTotalScore(iVTPositiveHashReturns, true))/10;
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveHashReturns, true);
            }
          }

          //score VirusTotal URL
          if ((lFidoReturnValues.Cyphort.VirusTotal != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.URLReturn != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.URLReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector URL information.");
            var iVTPositiveUrlReturns = VirusTotalPosReturnURL(lFidoReturnValues.Cyphort.VirusTotal);
            if ((iVTPositiveUrlReturns[0] > 0) || (iVTPositiveUrlReturns[1] > 0))
            {
              lFidoReturnValues.Cyphort.VirusTotal.VirusTotalScore += Math.Round(VirusTotalScore(iVTPositiveUrlReturns, false))/10;
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveUrlReturns, false);
            }
          }

          //score VirusTotal IP
          if ((lFidoReturnValues.Cyphort.VirusTotal != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.IPReturn != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.IPReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector IP information.");
            var iVTPositiveIPReturns = VirusTotalPosIPReturn(lFidoReturnValues.Cyphort.VirusTotal);
            if ((iVTPositiveIPReturns[0] > 0) || (iVTPositiveIPReturns[1] > 0) || (iVTPositiveIPReturns[2] > 0))
            {
              lFidoReturnValues.Cyphort.VirusTotal.VirusTotalScore += Math.Round(VirusTotalIPScore(iVTPositiveIPReturns))/10;
              lFidoReturnValues.ThreatScore += VirusTotalIPScore(iVTPositiveIPReturns);
            }
          }

          //score ThreatGRID IP
          if ((lFidoReturnValues.Cyphort.ThreatGRID != null) && (lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID IP data, downloading report.");

            if (lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Data.Items.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring Cyphort/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.Cyphort.ThreatGRID.ThreatScore = aggregateScore/lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.Cyphort.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.Cyphort.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count();
            
            var aggregateSeverity = lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.Cyphort.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count();

            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");
            
            lFidoReturnValues.ThreatScore += (lFidoReturnValues.Cyphort.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          }

          if ((lFidoReturnValues.Cyphort.ThreatGRID != null) && (lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo != null) && (lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID hash data, downloading report.");

            if (lFidoReturnValues.Cyphort.ThreatGRID.HashSearch.Data.Items.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.Cyphort.ThreatGRID.HashSearch.Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring Cyphort/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.Cyphort.ThreatGRID.ThreatScore = aggregateScore / lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.Cyphort.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.Cyphort.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Count();

            var aggregateSeverity = lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.Cyphort.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Count();

            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");

            lFidoReturnValues.ThreatScore += (lFidoReturnValues.Cyphort.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          } 

          //score Alienvault threat feed
          if ((lFidoReturnValues.Cyphort.AlienVault != null) && (lFidoReturnValues.Cyphort.AlienVault.Activity != null))
          {
            Console.WriteLine(@"Scoring Cyphort/AlienVault detector IP information.");
            lFidoReturnValues.ThreatScore += AlienVaultScore(lFidoReturnValues.Cyphort.AlienVault);
          }
          break;
        case "protectwisev1-event":
          //score VirusTotal hash
          if ((lFidoReturnValues.ProtectWise.VirusTotal != null) &&
              (lFidoReturnValues.ProtectWise.VirusTotal.MD5HashReturn != null) &&
              (lFidoReturnValues.ProtectWise.VirusTotal.MD5HashReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring ProtectWise/VirusTotal detector hash information.");
            var iVTPositiveHashReturns = VirusTotalPosReturnHash(lFidoReturnValues.ProtectWise.VirusTotal);
            if ((iVTPositiveHashReturns[0] > 0) || (iVTPositiveHashReturns[1] > 0))
            {
              lFidoReturnValues.ProtectWise.VirusTotal.VirusTotalScore += Math.Round(VirusTotalScore(iVTPositiveHashReturns, true)) / 10;
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveHashReturns, true);
            }
          }

          //score VirusTotal URL
          if ((lFidoReturnValues.ProtectWise.VirusTotal != null) &&
              (lFidoReturnValues.ProtectWise.VirusTotal.URLReturn != null) &&
              (lFidoReturnValues.ProtectWise.VirusTotal.URLReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring ProtectWise/VirusTotal detector URL information.");
            var iVTPositiveUrlReturns = VirusTotalPosReturnURL(lFidoReturnValues.ProtectWise.VirusTotal);
            if ((iVTPositiveUrlReturns[0] > 0) || (iVTPositiveUrlReturns[1] > 0))
            {
              lFidoReturnValues.ProtectWise.VirusTotal.VirusTotalScore += Math.Round(VirusTotalScore(iVTPositiveUrlReturns, false)) / 10;
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveUrlReturns, false);
            }
          }

          //score VirusTotal IP
          if ((lFidoReturnValues.ProtectWise.VirusTotal != null) &&
              (lFidoReturnValues.ProtectWise.VirusTotal.IPReturn != null) &&
              (lFidoReturnValues.ProtectWise.VirusTotal.IPReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring ProtectWise/VirusTotal detector IP information.");
            var iVTPositiveIPReturns = VirusTotalPosIPReturn(lFidoReturnValues.ProtectWise.VirusTotal);
            if ((iVTPositiveIPReturns[0] > 0) || (iVTPositiveIPReturns[1] > 0) || (iVTPositiveIPReturns[2] > 0))
            {
              lFidoReturnValues.ProtectWise.VirusTotal.VirusTotalScore += Math.Round(VirusTotalIPScore(iVTPositiveIPReturns)) / 10;
              lFidoReturnValues.ThreatScore += VirusTotalIPScore(iVTPositiveIPReturns);
            }
          }

          //score ThreatGRID IP
          if ((lFidoReturnValues.ProtectWise.ThreatGRID != null) && (lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID IP data, downloading report.");

            if (lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.Items.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring ProtectWise/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatScore = aggregateScore / lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count();

            var aggregateSeverity = lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count();

            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");

            lFidoReturnValues.ThreatScore += (lFidoReturnValues.ProtectWise.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          }

          if ((lFidoReturnValues.ProtectWise.ThreatGRID != null) && (lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo != null) && (lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID hash data, downloading report.");

            if (lFidoReturnValues.ProtectWise.ThreatGRID.HashSearch.Data.Items.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.ProtectWise.ThreatGRID.HashSearch.Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring ProtectWise/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatScore = aggregateScore / lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Count();

            var aggregateSeverity = lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Count();

            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");

            lFidoReturnValues.ThreatScore += (lFidoReturnValues.ProtectWise.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          }

          //score Alienvault threat feed
          if ((lFidoReturnValues.ProtectWise.AlienVault != null) && (lFidoReturnValues.ProtectWise.AlienVault.Activity != null))
          {
            Console.WriteLine(@"Scoring ProtectWise/AlienVault detector IP information.");
            lFidoReturnValues.ThreatScore += AlienVaultScore(lFidoReturnValues.ProtectWise.AlienVault);
          }
          break;

        case "carbonblackv1":
          //score VirusTotal hash
          if ((lFidoReturnValues.CB.Alert.VirusTotal != null) &&
              (lFidoReturnValues.CB.Alert.VirusTotal.MD5HashReturn != null) &&
              (lFidoReturnValues.CB.Alert.VirusTotal.MD5HashReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Carbon Black/VirusTotal detector hash information.");
            var iVTPositiveHashReturns = VirusTotalPosReturnHash(lFidoReturnValues.CB.Alert.VirusTotal);
            if ((iVTPositiveHashReturns[0] > 0) || (iVTPositiveHashReturns[1] > 0))
            {
              lFidoReturnValues.CB.Alert.VirusTotal.VirusTotalScore += Math.Round(VirusTotalScore(iVTPositiveHashReturns, true)) / 10;
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveHashReturns, true);
            }
          }

          if ((lFidoReturnValues.CB.Alert.ThreatGRID != null) && (lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo != null) && (lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID hash data, downloading report.");

            if (lFidoReturnValues.CB.Alert.ThreatGRID.HashSearch.Data.Items.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.CB.Alert.ThreatGRID.HashSearch.Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring Carbon Black/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.CB.Alert.ThreatGRID.ThreatScore = aggregateScore / lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.CB.Alert.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.CB.Alert.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Count();

            var aggregateSeverity = lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.CB.Alert.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Count();

            //todo: move this SQL to the DB
            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");

            lFidoReturnValues.ThreatScore += (lFidoReturnValues.CB.Alert.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          }

          //score Alienvault threat feed
          if ((lFidoReturnValues.CB.Alert.AlienVault != null) && (lFidoReturnValues.CB.Alert.AlienVault.Activity != null))
          {
            Console.WriteLine(@"Scoring Carbon Black/AlienVault detector IP information.");
            lFidoReturnValues.ThreatScore += AlienVaultScore(lFidoReturnValues.CB.Alert.AlienVault);
          }
          break;

        case "panv1":

          //score VirusTotal URL
          //if ((lFidoReturnValues.PaloAlto.VirusTotal != null) &&
          //    (lFidoReturnValues.PaloAlto.VirusTotal.URLReturn != null) &&
          //    (lFidoReturnValues.PaloAlto.VirusTotal.URLReturn.Count > 0))
          //{
          //  Console.WriteLine(@"Scoring PaloAlto/VirusTotal detector URL information.");
          //  var iVTPositiveUrlReturns = VirusTotalPosReturn(lFidoReturnValues.PaloAlto.VirusTotal, false);
          //  if ((iVTPositiveUrlReturns[0] > 0) || (iVTPositiveUrlReturns[1] > 0))
          //  {
          //    lFidoReturnValues.PaloAlto.VirusTotal.VirusTotalScore += Math.Round(VirusTotalScore(iVTPositiveUrlReturns, false)) / 10;
          //    lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveUrlReturns, false);
          //  }
          //}

          //score VirusTotal IP
          if ((lFidoReturnValues.PaloAlto.VirusTotal != null) &&
              (lFidoReturnValues.PaloAlto.VirusTotal.IPReturn != null) &&
              (lFidoReturnValues.PaloAlto.VirusTotal.IPReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring PaloAlto/VirusTotal detector IP information.");
            var iVTPositiveIPReturns = VirusTotalPosIPReturn(lFidoReturnValues.PaloAlto.VirusTotal);
            if ((iVTPositiveIPReturns[0] > 0) || (iVTPositiveIPReturns[1] > 0) || (iVTPositiveIPReturns[2] > 0))
            {
              lFidoReturnValues.PaloAlto.VirusTotal.VirusTotalScore += Math.Round(VirusTotalIPScore(iVTPositiveIPReturns)) / 10;
              lFidoReturnValues.ThreatScore += VirusTotalIPScore(iVTPositiveIPReturns);
            }
          }

          //score ThreatGRID IP
          if ((lFidoReturnValues.PaloAlto.ThreatGRID != null) && (lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID IP data, downloading report.");

            if (lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.Items.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring PaloAlto/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.PaloAlto.ThreatGRID.ThreatScore = aggregateScore / lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.PaloAlto.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.PaloAlto.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count();

            var aggregateSeverity = lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.PaloAlto.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count();

            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");

            lFidoReturnValues.ThreatScore += (lFidoReturnValues.PaloAlto.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          }
          break;
      }

      return lFidoReturnValues;
    }

    private static double GetMpsVTHashThreatScore(FidoReturnValues lFidoReturnValues)
    {
      double iThreatScore = 0;
      if ((lFidoReturnValues.FireEye.VirusTotal == null) || (lFidoReturnValues.FireEye.VirusTotal.MD5HashReturn == null) || (lFidoReturnValues.FireEye.VirusTotal.MD5HashReturn.Count <= 0)) return iThreatScore;
      Console.WriteLine(@"Scoring FireEye/VirusTotal detector hash information.");
        
      var iVTPositiveHashReturns = VirusTotalPosReturnHash(lFidoReturnValues.FireEye.VirusTotal);
      if ((iVTPositiveHashReturns[0] > 0) || (iVTPositiveHashReturns[1] > 0))
      {
        iThreatScore += VirusTotalScore(iVTPositiveHashReturns, true);
      }
      return iThreatScore;
    }

    //private static int[] ThreatGRIDPosReturn(ThreatGRIDReturnValues threatGridReturnValues)
    //{

    //  return ;
    //}

    private static int[] BitTotalPosReturn(IList<FileReport> vtEntry)
    {
      var iPosReturns = 0;
      var iPostTrojReturns = 0;

      if (vtEntry[0].Positives > 0)
      {
        iPostTrojReturns +=
          (from t in vtEntry[0].Scans
            where t.Result != null
            select t.Result.ToLower()
            into sResult
            select sResult.Contains("troj")).Count(isTrojan => isTrojan);
        iPosReturns += vtEntry[0].Positives;
      }
      var iReturn = new[] { iPosReturns, iPostTrojReturns };
      return iReturn;
    }

    private static int[] VirusTotalPosReturnHash(VirusTotalReturnValues virusTotalReturnValues)
    {
      var iPosReturns = 0;
      var iPostTrojReturns = 0;
      var lVTReport = virusTotalReturnValues.MD5HashReturn;
      foreach (var vtEntry in lVTReport.Where(vtEntry => vtEntry.Positives > 0))
      {
        iPostTrojReturns += (from t in vtEntry.Scans
                             where t.Result != null
                             select t.Result.ToLower()
                               into sResult
                               let isTrojan = false
                               select sResult.Contains("troj")).Count(isTrojan => isTrojan);
        iPosReturns += vtEntry.Positives;
      }
      var iReturn = new[] { iPosReturns, iPostTrojReturns };
      return iReturn;
    }

    private static int[] VirusTotalPosReturnURL(VirusTotalReturnValues virusTotalReturnValues)
    {
      var iPosReturns = 0;
      var iPostTrojReturns = 0;
      var lVTReport = virusTotalReturnValues.URLReturn;
      foreach (var vtEntry in lVTReport.Where(vtEntry => vtEntry.Positives > 0))
      {
        iPostTrojReturns += (from t in vtEntry.Scans
                             where t.Result != null
                             select t.Result.ToLower()
                               into sResult
                               let isTrojan = false
                               select sResult.Contains("malicious site")).Count(isTrojan => isTrojan);
        iPosReturns += vtEntry.Positives;
      }
      var iReturn = new[] { iPosReturns, iPostTrojReturns };
      return iReturn;
    }

    private static List<double> VirusTotalPosIPReturn(VirusTotalReturnValues virusTotalReturnValues)
    {

      List<Object_VirusTotal_IP.IPReport> lVTReport = virusTotalReturnValues.IPReturn;
      double countDetectedUrls = 0;
      double countDetectedDownloads = 0;
      double countDetectedComms = 0;

      foreach (var vtEntry in lVTReport)
      {
        if (vtEntry.DetectedUrls != null && vtEntry.DetectedUrls.Any())
        {
          for (var i = 0; i < vtEntry.DetectedUrls.Count(); i++)
          {
            if (vtEntry.DetectedUrls[i].Positives != null & vtEntry.DetectedUrls[i].Positives > 0)
            {
              //todo: move the below integer values to database configuration
              if (vtEntry.DetectedUrls[i].Positives >= 20)
              {
                countDetectedUrls = countDetectedUrls + (vtEntry.DetectedUrls[i].Positives * .5);
              }
              else if ((vtEntry.DetectedUrls[i].Positives >= 5) && (vtEntry.DetectedUrls[i].Positives < 20))
              {
                countDetectedUrls = countDetectedUrls + (vtEntry.DetectedUrls[i].Positives * .6);
              }
              else if (vtEntry.DetectedUrls[i].Positives >= 3)
              {
                countDetectedUrls = countDetectedUrls + (vtEntry.DetectedUrls[i].Positives * .75);
              }

            }
          }
        }
        if (vtEntry.DetectedCommunicatingSamples != null && vtEntry.DetectedCommunicatingSamples.Any())
        {
          for (var i = 0; i < vtEntry.DetectedCommunicatingSamples.Count(); i++)
          {
            if (vtEntry.DetectedCommunicatingSamples[i].Positives != null & vtEntry.DetectedCommunicatingSamples[i].Positives >= 3)
            {
              if (vtEntry.DetectedCommunicatingSamples[i].Positives >= 20)
              {
                countDetectedComms = countDetectedComms + (vtEntry.DetectedCommunicatingSamples[i].Positives * .65);
              }
              else if ((vtEntry.DetectedCommunicatingSamples[i].Positives >= 10) && (vtEntry.DetectedCommunicatingSamples[i].Positives < 20))
              {
                countDetectedComms = countDetectedComms + (vtEntry.DetectedCommunicatingSamples[i].Positives * .75);
              }
              else if (vtEntry.DetectedCommunicatingSamples[i].Positives < 10)
              {
                countDetectedComms = countDetectedComms + (vtEntry.DetectedCommunicatingSamples[i].Positives * 1);
              }
            }
          }
        }
        if (vtEntry.DetectedDownloadedSamples != null && vtEntry.DetectedDownloadedSamples.Any())
        {
          for (var i = 0; i < vtEntry.DetectedDownloadedSamples.Count(); i++)
          {
            if (vtEntry.DetectedDownloadedSamples[i].Positives != null & vtEntry.DetectedDownloadedSamples[i].Positives >= 3)
            {
              if (vtEntry.DetectedDownloadedSamples[i].Positives >= 20)
              {
                countDetectedDownloads = countDetectedDownloads + (vtEntry.DetectedDownloadedSamples[i].Positives * .50);
              }
              else if ((vtEntry.DetectedDownloadedSamples[i].Positives < 20) && (vtEntry.DetectedDownloadedSamples[i].Positives >= 10))
              {
                countDetectedDownloads = countDetectedDownloads + (vtEntry.DetectedDownloadedSamples[i].Positives * .65);
              }
              else if (vtEntry.DetectedDownloadedSamples[i].Positives < 10)
              {
                countDetectedDownloads = countDetectedDownloads + (vtEntry.DetectedDownloadedSamples[i].Positives * .75);
              }
            }
          }
        }
      }

      var lReturn = new List<double> { countDetectedComms, countDetectedDownloads, countDetectedUrls };
      return lReturn;

    }

    private static double VirusTotalScore(IList<int> iVTPositiveReturns, bool isHash)
    {

      var iTrojanScore = Object_Fido_Configs.GetAsInt("fido.securityfeed.virustotal.trojanscore", 0);
      var iTrojanWeight = Object_Fido_Configs.GetAsInt("fido.securityfeed.virustotal.trojanweight", 0);
      var iRegularScore = Object_Fido_Configs.GetAsInt("fido.securityfeed.virustotal.regularscore", 0);
      var iRegularWeight = Object_Fido_Configs.GetAsInt("fido.securityfeed.virustotal.regularweight", 0);
      var iUrlRegularScore = Object_Fido_Configs.GetAsInt("fido.securityfeed.virustotal.urlregularscore", 0);
      var iUrlRegularWeight = Object_Fido_Configs.GetAsInt("fido.securityfeed.virustotal.urlregularweight", 0);
      double iTotalReturn = 0;

      if ((iVTPositiveReturns[1] >= iTrojanScore) & (isHash))
      {
        iTotalReturn = iTrojanWeight * iVTPositiveReturns[1];
      }
      if ((iVTPositiveReturns[1] >= iUrlRegularScore) & (!isHash))
      {
        iTotalReturn = iUrlRegularWeight * iVTPositiveReturns[1];
      }
      if ((iVTPositiveReturns[0] >= iRegularScore) & (isHash))
      {
        iTotalReturn = iRegularWeight * iVTPositiveReturns[0];
      }
      return iTotalReturn;
    }

    private static double VirusTotalIPScore(IList<double> iVTPositiveReturns)
    {

      var iDetectedDownload = Object_Fido_Configs.GetAsInt("fido.securityfeed.virustotal.detecteddownloadscore", 0);
      var iDetectedDownloadWeight = Object_Fido_Configs.GetAsInt("fido.securityfeed.virustotal.detecteddownloadweight", 0);
      var iDetectedDownloadMultiplier = Object_Fido_Configs.GetAsDouble("fido.securityfeed.virustotal.detecteddownloadmultiplier", 0.0);
      var iDetectedComm = Object_Fido_Configs.GetAsInt("fido.securityfeed.virustotal.etectedcommScore", 0);
      var iDetectedCommWeight = Object_Fido_Configs.GetAsInt("fido.securityfeed.virustotal.detectedcommweight", 0);
      var iDetectedCommMultiplier = Object_Fido_Configs.GetAsDouble("fido.securityfeed.virustotal.detectedcommmultiplier", 0.0);
      var iDetectedURLs = Object_Fido_Configs.GetAsInt("fido.securityfeed.virustotal.detectedurlscore", 0);
      var iDetectedURLsWeight = Object_Fido_Configs.GetAsInt("fido.securityfeed.virustotal.detectedurlweight", 0);
      var iDetectedURLMultiplier = Object_Fido_Configs.GetAsDouble("fido.securityfeed.virustotal.detectedurlmultiplier", 0.0);
      var iFeedWeight = Object_Fido_Configs.GetAsDouble("fido.securityfeed.virustotal.feedweight", 0.0);
      double iTotalReturn = 0;

      if (iVTPositiveReturns[1] >= iDetectedDownload)
      {
        iTotalReturn += (iDetectedDownloadWeight * iDetectedDownloadMultiplier) * iVTPositiveReturns[1];
      }
      if (iVTPositiveReturns[0] >= iDetectedComm)
      {
        iTotalReturn += (iDetectedCommWeight * iDetectedCommMultiplier) * iVTPositiveReturns[0];
      }
      if (iVTPositiveReturns[2] >= iDetectedURLs)
      {
        iTotalReturn += (iDetectedURLsWeight * iDetectedURLMultiplier) * iVTPositiveReturns[2];
      }

      iTotalReturn = iTotalReturn / iFeedWeight;
      return iTotalReturn;
    }

    public static FidoReturnValues GetHistoricalHashCount(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.HistoricalEvent.HashCount >= lFidoReturnValues.HistoricalEvent.HashScore)
      {
        Console.WriteLine(@"Hash seen before and is above threshold, scoring historical information.");
        lFidoReturnValues.IsHashSeenBefore = true;
        if (lFidoReturnValues.HistoricalEvent.HashCount >= lFidoReturnValues.HistoricalEvent.HashIncrement)
        {
          lFidoReturnValues.ThreatScore += lFidoReturnValues.HistoricalEvent.HashWeight * lFidoReturnValues.HistoricalEvent.HashMultiplier;
        }
        else
        {
          lFidoReturnValues.ThreatScore += lFidoReturnValues.HistoricalEvent.HashWeight;
        }
      }
      return lFidoReturnValues;
    }

    public static FidoReturnValues GetHistoricalURLCount(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.HistoricalEvent.UrlCount >= lFidoReturnValues.HistoricalEvent.UrlScore)
      {
        Console.WriteLine(@"URL seen before and is above threshold, scoring historical information.");
        lFidoReturnValues.IsUrlSeenBefore = true;
        if (lFidoReturnValues.HistoricalEvent.UrlCount >= lFidoReturnValues.HistoricalEvent.UrlIncrement)
        {
          lFidoReturnValues.ThreatScore += lFidoReturnValues.HistoricalEvent.UrlWeight * lFidoReturnValues.HistoricalEvent.UrlMultiplier;
        }
        else
        {
          lFidoReturnValues.ThreatScore += lFidoReturnValues.HistoricalEvent.UrlWeight;
        }
      }
      return lFidoReturnValues;
    }

    public static FidoReturnValues GetHistoricalIPCount(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.HistoricalEvent.IpCount > lFidoReturnValues.HistoricalEvent.IpScore)
      {
        Console.WriteLine(@"IP address seen before and is above threshold, scoring historical information.");
        lFidoReturnValues.IsIPSeenBefore = true;
        if (lFidoReturnValues.HistoricalEvent.IpCount >= lFidoReturnValues.HistoricalEvent.IpIncrement)
        {
          lFidoReturnValues.ThreatScore += lFidoReturnValues.HistoricalEvent.IpWeight * lFidoReturnValues.HistoricalEvent.IpMultiplier;
        }
        else
        {
          lFidoReturnValues.ThreatScore += lFidoReturnValues.HistoricalEvent.IpWeight;
        }
      }
      return lFidoReturnValues;
    }

    public static int AlienVaultScore(AlienVaultReturnValues lAlienVaultReturnValues)
    {
      var lMalwareTypes = Object_Fido_Configs.GetAsString("fido.securityfeed.alienvault.malwarevalues", String.Empty).Split(',').ToList();

      var iRiskScoreHigh = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.riskscorehigh", 0);
      var iRiskScoreMedium = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.riskscoremedium", 0);
      var iRiskScoreLow = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.riskscorelow", 0);
      var iRiskWeightHigh = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.riskweighthigh", 0);
      var iRiskWeightMedium = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.riskweightmedium", 0);
      var iRiskWeightLow = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.riskweightlow", 0);
      var iReliabilityScoreHigh = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.reliabilityscorehigh", 0);
      var iReliabilityScoreMedium = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.reliabilityscoremedium", 0);
      var iReliabilityScoreLow = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.reliabilityscorelow", 0);
      var iReliabilityWeightHigh = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.reliabilityweighthigh", 0);
      var iReliabilityWeightMedium = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.reliabilityweightmedium", 0);
      var iReliabilityWeightLow = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.reliabilityweightlow", 0);
      var iScore = 0;

      // ReSharper disable once UnusedVariable for used variable in foreach loop
      foreach (var sNewType in lMalwareTypes.Select(sType => sType.ToLower() == "c and c" ? "c&c" : sType).Where(sNewType => String.Equals(sNewType, lAlienVaultReturnValues.Activity, StringComparison.CurrentCultureIgnoreCase)))
      {
        if (lAlienVaultReturnValues.Reliability > iReliabilityScoreHigh)
        {
          if (lAlienVaultReturnValues.Risk > iRiskScoreHigh)
          {
            iScore = iRiskWeightHigh * iReliabilityWeightHigh;
          }
          else if (lAlienVaultReturnValues.Risk > iRiskScoreMedium)
          {
            iScore = iRiskWeightMedium * iReliabilityWeightHigh;
          }
          else if (lAlienVaultReturnValues.Risk < iRiskScoreLow)
          {
            iScore = iRiskWeightLow * iReliabilityWeightHigh;
          }
        }
        else if (lAlienVaultReturnValues.Reliability > iReliabilityScoreMedium)
        {
          if (lAlienVaultReturnValues.Risk > iRiskScoreHigh)
          {
            iScore = iRiskWeightHigh * iReliabilityWeightMedium;
          }
          else if (lAlienVaultReturnValues.Risk > iRiskScoreMedium)
          {
            iScore = iRiskWeightMedium * iReliabilityWeightMedium;
          }
          else if (lAlienVaultReturnValues.Risk < iRiskScoreLow)
          {
            iScore = iRiskWeightLow * iReliabilityWeightMedium;
          }
        }
        else if (lAlienVaultReturnValues.Reliability < iReliabilityScoreLow)
        {
          if (lAlienVaultReturnValues.Risk > iRiskScoreHigh)
          {
            iScore = iRiskWeightHigh * iReliabilityWeightLow;
          }
          else if (lAlienVaultReturnValues.Risk > iRiskScoreMedium)
          {
            iScore = iRiskWeightMedium * iReliabilityWeightLow;
          }
          else if (lAlienVaultReturnValues.Risk < iRiskScoreLow)
          {
            iScore = iRiskWeightLow * iReliabilityWeightLow;
          }
        }
      }
      return iScore;
    }

    public static FidoReturnValues GetUserScore(FidoReturnValues lFidoReturnValues)
    {
      var sUserTitles = Object_Fido_Configs.GetAsString("fido.posture.user.titles", null);
      var sUserDepartment = Object_Fido_Configs.GetAsString("fido.posture.user.department", null);
      var sUserTitlesArray = sUserTitles.Split(',');
      var sUserDepartmentArray = sUserDepartment.Split(',');
      var sTitleScoreWeight = Object_Fido_Configs.GetAsInt("fido.posture.user.titlescoreweight", 0);
      var sDepartmentScoreWeight = Object_Fido_Configs.GetAsInt("fido.posture.user.departmentscoreweight", 0);

      //user title section
      if ((sUserTitlesArray.Any()) && (sUserTitlesArray[0] != String.Empty) &&
          (lFidoReturnValues.UserInfo.Title != null))
      {
        Console.WriteLine(@"Scoring user title information.");
        foreach (var sTitle in sUserTitlesArray.Where(sTitle => sTitle.ToLower() == lFidoReturnValues.UserInfo.Title.ToLower()))
        {
          lFidoReturnValues.UserScore += Convert.ToInt16(sTitleScoreWeight);
        }
      }

      //user department section
      if ((sUserDepartmentArray.Any()) && (sUserDepartmentArray[0] != String.Empty) && (lFidoReturnValues.UserInfo.Department != null))
      {
        Console.WriteLine(@"Scoring user department information.");
        foreach (var sDepartment in sUserDepartmentArray.Where(sDepartment => String.Equals(sDepartment, lFidoReturnValues.UserInfo.Department, StringComparison.CurrentCultureIgnoreCase)))
        {
          lFidoReturnValues.UserScore += Convert.ToInt16(sDepartmentScoreWeight);
        }
      }

      return lFidoReturnValues;
    }

    public static FidoReturnValues GetPatchScore(FidoReturnValues lFidoReturnValues)
    {
      if ((lFidoReturnValues.Landesk != null) && (lFidoReturnValues.Landesk.Patches != null))
      {
        Console.WriteLine(@"Scoring Windows physical system patch status.");
        var iCriticalPaches = Object_Fido_Configs.GetAsInt("fido.posture.machine.criticalpatches", 0);
        var iCriticalPachesWeight = Object_Fido_Configs.GetAsInt("fido.posture.machine.criticalpatchesweight", 0);
        var iHighPatches = Object_Fido_Configs.GetAsInt("fido.posture.machine.highpatches", 0);
        var iHighPatchesWeight = Object_Fido_Configs.GetAsInt("fido.posture.machine.highpatchesweight", 0);
        var iLowPatches = Object_Fido_Configs.GetAsInt("fido.posture.machine.lowpatches", 0);
        var iLowPatchesWeight = Object_Fido_Configs.GetAsInt("fido.posture.machine.lowpatchesweight", 0);
        var lPatches = lFidoReturnValues.Landesk.Patches;
        var iCrit = lPatches[1];
        var iHigh = lPatches[2];
        var iLow = lPatches[3];

        if (iCrit >= iCriticalPaches)
        {
          lFidoReturnValues.MachineScore += iCriticalPachesWeight;
          lFidoReturnValues.IsPatch = true;
        }
        if (iHigh >= iHighPatches)
        {
          lFidoReturnValues.MachineScore += iHighPatchesWeight;
          lFidoReturnValues.IsPatch = true;
        }
        if (iLow >= iLowPatches)
        {
          lFidoReturnValues.MachineScore += iLowPatchesWeight;
        }
      }
      else if ((lFidoReturnValues.Jamf != null) && (lFidoReturnValues.Jamf.Patches != null))
      {
        //todo: reserved to get jamf patch values
        Console.WriteLine(@"Scoring Mac physical system patch status.");
      }

      return lFidoReturnValues;
    }

    public static FidoReturnValues GetAVScore(FidoReturnValues lFidoReturnValues)
    {
      var avNotInstalled = Object_Fido_Configs.GetAsInt("fido.posture.machine.avnotinstalled", 0);
      var avNotRunning = Object_Fido_Configs.GetAsInt("fido.posture.machine.avnotruning", 0);
      Console.WriteLine(@"Scoring detected security software stack status.");
      if ((lFidoReturnValues.Landesk != null) && (lFidoReturnValues.Landesk.Product != null))
      {
        if (lFidoReturnValues.Landesk.AgentRunning == null)
        {
          lFidoReturnValues.MachineScore += avNotRunning;
        }
      }
      else if ((lFidoReturnValues.Jamf != null))
      {
        //todo: reserved for getting AV Jamf values
      }
      else if ((lFidoReturnValues.Hostname != null) && (lFidoReturnValues.Hostname != "unknown") && (lFidoReturnValues.CurrentDetector != "antivirus"))
      {
        lFidoReturnValues.MachineScore += avNotInstalled;
      }

      return lFidoReturnValues;
    }

    public static FidoReturnValues GetAssetScore(FidoReturnValues lFidoReturnValues, bool isPaired)
    {
      //check if hostname is in PCI affected zone
      if (lFidoReturnValues.Hostname == null) return lFidoReturnValues;
      var sHostname = Object_Fido_Configs.GetAsString("fido.posture.asset.hostname", String.Empty);
      var sHostnameAry = sHostname.Split(',');
      var isContainsHost = false;

      if (!sHostnameAry.Any()) return lFidoReturnValues;
      Console.WriteLine(@"Scoring physical asset.");
      foreach (var name in sHostnameAry)
      {
        if ((lFidoReturnValues.Hostname.ToLower().Contains(name) && name != String.Empty))
        {
          isContainsHost = true;
        }
        if ((isPaired == false) && (isContainsHost))
        {
          lFidoReturnValues.IsPCI = true;
        }
      }

      //check if subnet is in PCI affect zone
      var isContainsSubnet = false;
      if (lFidoReturnValues.SrcIP != null)
      {
        Console.WriteLine(@"Scoring physical PCI asset.");
        var sSubnet = Object_Fido_Configs.GetAsString("fido.posture.asset.subnet", String.Empty);
        var sSubnetAry = sSubnet.Split(',');

        if (sSubnetAry.Any())
        {
          foreach (var subnet in sSubnetAry)
          {
            if ((lFidoReturnValues.SrcIP.Contains(subnet)) && subnet != String.Empty)
            {
              isContainsSubnet = true;
            }
            if ((isPaired == false) && (isContainsSubnet))
            {
              lFidoReturnValues.IsPCI = true;
            }
          }
        }
      }

      if ((isPaired) && (isContainsSubnet) && (isContainsHost))
      {
        lFidoReturnValues.IsPCI = true;
      }

      return lFidoReturnValues;
    }

    public static double AntiVirusScore(FidoReturnValues lFidoReturnValues)
    {
      var iTrojanMultiplier = Object_Fido_Configs.GetAsInt("fido.detectors.antivirus.trojanmultiplier", 0);
      var iTrojanWeight = Object_Fido_Configs.GetAsInt("fido.detectors.antivirus.trojanweight", 0);
      var iRegularMultiplier = Object_Fido_Configs.GetAsInt("fido.detectors.antivirus.regularmultiplier", 0);
      var iRegularWeight = Object_Fido_Configs.GetAsInt("fido.detectors.antivirus.regularweight", 0);
      var sNewThreatName = lFidoReturnValues.Antivirus.ThreatName.Split('/');
      if ((sNewThreatName != null) && (sNewThreatName[0].ToLower() == "troj"))
      {
        lFidoReturnValues = AntiVirusTrojanReturnScore(lFidoReturnValues, iTrojanWeight, iTrojanMultiplier, iRegularWeight, iRegularMultiplier);
      }
      else
      {
        lFidoReturnValues = AntiVirusGenericReturnScore(lFidoReturnValues, iTrojanWeight, iTrojanMultiplier, iRegularWeight, iRegularMultiplier);
      }

      return lFidoReturnValues.ThreatScore;
    }

    private static FidoReturnValues AntiVirusGenericReturnScore(FidoReturnValues lFidoReturnValues, int iTrojanWeight, int iTrojanMultiplier, int iRegularWeight, int iRegularMultiplier)
    {
      switch (lFidoReturnValues.Antivirus.ActionTaken.ToLower())
      {
        case "none":
          switch (lFidoReturnValues.Antivirus.Status.ToLower())
          {
            case "cleanable":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier;
              break;
            case "cleanup failed":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier + 5;
              break;
            case "restart required":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier;
              break;
            case "not cleanable":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier + 20;
              break;
          }
          break;
        case "partially removed":
          switch (lFidoReturnValues.Antivirus.Status.ToLower())
          {
            case "cleanable":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier;
              break;
            case "cleanup failed":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier;
              break;
            case "restart required":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier - 15;
              break;
            case "not cleanable":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier + 10;
              break;
          }
          break;
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues AntiVirusTrojanReturnScore(FidoReturnValues lFidoReturnValues, int iTrojanWeight, int iTrojanMultiplier, int iRegularWeight, int iRegularMultiplier)
    {
      switch (lFidoReturnValues.Antivirus.ActionTaken.ToLower())
      {
        case "none":
          switch (lFidoReturnValues.Antivirus.Status.ToLower())
          {
            case "cleanable":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier;
              break;
            case "cleanup failed":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier + 20;
              break;
            case "restart required":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier - 10;
              break;
            case "not cleanable":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier + 40;
              break;
          }
          break;
        case "partially removed":
          switch (lFidoReturnValues.Antivirus.Status.ToLower())
          {
            case "cleanable":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier;
              break;
            case "cleanup failed":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier + 10;
              break;
            case "restart required":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier - 5;
              break;
            case "not cleanable":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier + 30;
              break;
          }
          break;
      }
      return lFidoReturnValues;
    }

    public static FidoReturnValues SetScoreValues(FidoReturnValues lFidoReturnValues)
    {
      lFidoReturnValues = SetThreatScore(lFidoReturnValues);
      lFidoReturnValues = SetUserScore(lFidoReturnValues);
      lFidoReturnValues = SetMachineScore(lFidoReturnValues);
      lFidoReturnValues.TotalScore = lFidoReturnValues.ThreatScore + lFidoReturnValues.MachineScore + lFidoReturnValues.UserScore;

      if (lFidoReturnValues.TotalScore > 100)
      {
        lFidoReturnValues.TotalScore = 100;
      }
      else
      {
        lFidoReturnValues.TotalScore = Math.Round(lFidoReturnValues.TotalScore / 5) * 5;
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SetMachineScore(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.MachineScore > 100)
      {
        lFidoReturnValues.MachineScore = 100;
      }
      else
      {
        lFidoReturnValues.MachineScore = Math.Round(lFidoReturnValues.MachineScore/5)*5;
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SetUserScore(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.UserScore > 100)
      {
        lFidoReturnValues.UserScore = 100;
      }
      else
      {
        lFidoReturnValues.UserScore = Math.Round(lFidoReturnValues.UserScore/5)*5;
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SetThreatScore(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.ThreatScore > 100)
      {
        lFidoReturnValues.ThreatScore = 100;
      }
      else
      {
        lFidoReturnValues.ThreatScore = Math.Round(lFidoReturnValues.ThreatScore/5)*5;
      }
      return lFidoReturnValues;
    }
  }
}
