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
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.ThreatGRID;

namespace Fido_Main.Director.Director_Helper
{
  static class The_Director_ThreatFeeds_Hash
  {

    public static FidoReturnValues DetectorsToThreatFeeds(FidoReturnValues lFidoReturnValues)
    {
      lFidoReturnValues = FireEyeHash(lFidoReturnValues);

      lFidoReturnValues = CyphortHash(lFidoReturnValues);

      lFidoReturnValues = ProtectWiseHash(lFidoReturnValues);

      lFidoReturnValues = CarbonBlackHash(lFidoReturnValues);

      return lFidoReturnValues;
    }

    private static FidoReturnValues FireEyeHash(FidoReturnValues lFidoReturnValues)
    {
      //if FireEye has hashes send to threat feeds
      if (Object_Fido_Configs.GetAsBool("fido.director.virustotal", false))
      {
        if ((lFidoReturnValues.FireEye != null) && (lFidoReturnValues.FireEye.MD5Hash.Any()))
        {
          if (lFidoReturnValues.FireEye.VirusTotal == null)
          {
            lFidoReturnValues.FireEye.VirusTotal = new VirusTotalReturnValues();
          }
          Console.WriteLine(@"Sending FireEye hashes to VirusTotal.");
          lFidoReturnValues.FireEye.VirusTotal.MD5HashReturn = Feeds_VirusTotal.VirusTotalHash(lFidoReturnValues.FireEye.MD5Hash);
        }
      }

      //todo: decide if FireEye should go to ThreatGRID
      //if (Object_Fido_Configs.GetAsBool("fido.director.threatgrid", false))
      //{
      //  Console.WriteLine(@"Sending FireEye hashes to ThreatGRID.");
      //  lFidoReturnValues = SendFireEyeToThreatGRID(lFidoReturnValues);
      //}

      return lFidoReturnValues;
    }

    private static FidoReturnValues CyphortHash(FidoReturnValues lFidoReturnValues)
    {
      //if Cyphort has hashes send to threat feeds
      if (Object_Fido_Configs.GetAsBool("fido.director.virustotal", false))
      {
        if ((lFidoReturnValues.Cyphort != null) && (lFidoReturnValues.Cyphort.MD5Hash != null) && (lFidoReturnValues.Cyphort.MD5Hash.Any()))
        {
          if (lFidoReturnValues.Cyphort.VirusTotal == null)
          {
            lFidoReturnValues.Cyphort.VirusTotal = new VirusTotalReturnValues();
          }
          Console.WriteLine(@"Sending Cyphort hashes to VirusTotal.");
          lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn = Feeds_VirusTotal.VirusTotalHash(lFidoReturnValues.Cyphort.MD5Hash);
        }
      }

      if (Object_Fido_Configs.GetAsBool("fido.director.threatgrid", false))
      {
        Console.WriteLine(@"Sending Cyphort hashes to ThreatGRID.");
        lFidoReturnValues = SendCyphortToThreatGRID(lFidoReturnValues);
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues ProtectWiseHash(FidoReturnValues lFidoReturnValues)
    {
      //if ProtectWise has hashes send to threat feeds
      if (Object_Fido_Configs.GetAsBool("fido.director.virustotal", false))
      {
        if ((lFidoReturnValues.ProtectWise != null) && (lFidoReturnValues.ProtectWise.MD5 != null) && (lFidoReturnValues.ProtectWise.MD5.Any()))
        {
          if (lFidoReturnValues.ProtectWise.VirusTotal == null)
          {
            lFidoReturnValues.ProtectWise.VirusTotal = new VirusTotalReturnValues();
          }
          Console.WriteLine(@"Sending ProtectWise hashes to VirusTotal.");
          var MD5Hash = new List<string> {lFidoReturnValues.ProtectWise.MD5};
          lFidoReturnValues.ProtectWise.VirusTotal.MD5HashReturn = Feeds_VirusTotal.VirusTotalHash(MD5Hash);
        }
      }

      if (Object_Fido_Configs.GetAsBool("fido.director.threatgrid", false))
      {
        Console.WriteLine(@"Sending ProtectWise hashes to ThreatGRID.");
        lFidoReturnValues = SendProtectWiseToThreatGRID(lFidoReturnValues);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues CarbonBlackHash(FidoReturnValues lFidoReturnValues)
    {
      //if Carbon Black has hashes send to threat feeds
      if (Object_Fido_Configs.GetAsBool("fido.director.virustotal", false))
      {
        if ((lFidoReturnValues.CB != null) && (lFidoReturnValues.CB.Alert.MD5Hash != null))
        {
          if (lFidoReturnValues.CB.Alert.VirusTotal == null)
          {
            lFidoReturnValues.CB.Alert.VirusTotal = new VirusTotalReturnValues();
          }
          Console.WriteLine(@"Sending Carbon Black hashes to VirusTotal.");
          lFidoReturnValues.CB.Alert.VirusTotal.MD5HashReturn = Feeds_VirusTotal.VirusTotalHash(lFidoReturnValues.Hash);
        }
      }
      if (Object_Fido_Configs.GetAsBool("fido.director.threatgrid", false))
      {
        Console.WriteLine(@"Sending Carbon Black hashes to ThreatGRID.");
        lFidoReturnValues = SendCarbonBlackToThreatGrid(lFidoReturnValues);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues SendCyphortToThreatGRID(FidoReturnValues lFidoReturnValues)
    {
      Int16 iDays = -7;
      if (lFidoReturnValues.Cyphort == null) return lFidoReturnValues;
      foreach (var md5 in lFidoReturnValues.Cyphort.MD5Hash)
      {
        if (string.IsNullOrEmpty(md5)) continue;
        lFidoReturnValues.Cyphort.ThreatGRID.HashSearch = Feeds_ThreatGRID.SearchInfo(md5, true, iDays);
        while (Convert.ToInt16(lFidoReturnValues.Cyphort.ThreatGRID.HashSearch.Data.CurrentItemCount) < 50)
        {
          if (iDays < -364) break;
          iDays = (Int16)(iDays * 2);
          lFidoReturnValues.Cyphort.ThreatGRID.HashSearch = Feeds_ThreatGRID.SearchInfo(md5, true, iDays);
        }
        
        if (Convert.ToInt16(lFidoReturnValues.Cyphort.ThreatGRID.HashSearch.Data.CurrentItemCount) > 0)
        {
          Console.WriteLine(@"Successfully found ThreatGRID hash data (" + lFidoReturnValues.Cyphort.ThreatGRID.HashSearch.Data.CurrentItemCount + @" records)... storing in Fido."); 
        }

        for (var i = 0; i < Convert.ToInt16(lFidoReturnValues.Cyphort.ThreatGRID.HashSearch.Data.CurrentItemCount); i++)
        {
          if (i >= 50) continue;
          if (lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo == null)
          {
            lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo = new List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>();
          }
          lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Add(Feeds_ThreatGRID.ThreatInfo(lFidoReturnValues.Cyphort.ThreatGRID.HashSearch.Data.Items[i].HashID));
        }
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SendProtectWiseToThreatGRID(FidoReturnValues lFidoReturnValues)
    {
      //todo: move this integer value to the DB
      Int16 iDays = -7;
      if (lFidoReturnValues.ProtectWise == null) return lFidoReturnValues;
      lFidoReturnValues.ProtectWise.ThreatGRID.HashSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.ProtectWise.MD5, true, iDays);
      while (Convert.ToInt16(lFidoReturnValues.ProtectWise.ThreatGRID.HashSearch.Data.CurrentItemCount) < 50)
      {
        if (iDays < -364) break;
        iDays = (Int16)(iDays * 2);
        lFidoReturnValues.ProtectWise.ThreatGRID.HashSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.ProtectWise.MD5, true, iDays);
      }

      if (Convert.ToInt16(lFidoReturnValues.ProtectWise.ThreatGRID.HashSearch.Data.CurrentItemCount) > 0)
      {
        Console.WriteLine(@"Successfully found ThreatGRID hash data (" + lFidoReturnValues.ProtectWise.ThreatGRID.HashSearch.Data.CurrentItemCount + @" records)... storing in Fido.");
      }

      for (var i = 0; i < Convert.ToInt16(lFidoReturnValues.ProtectWise.ThreatGRID.HashSearch.Data.CurrentItemCount); i++)
      {
        if (i >= 50) continue;
        if (lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo == null)
        {
          lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo = new List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>();
        }
        lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Add(Feeds_ThreatGRID.ThreatInfo(lFidoReturnValues.ProtectWise.ThreatGRID.HashSearch.Data.Items[i].HashID));
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues SendCarbonBlackToThreatGrid(FidoReturnValues lFidoReturnValues)
    {
      Int16 iDays = -7;
      if (lFidoReturnValues.CB == null) return lFidoReturnValues;
      if (lFidoReturnValues.CB.Alert.ThreatGRID == null)
      {
        lFidoReturnValues.CB.Alert.ThreatGRID = new ThreatGRIDReturnValues();
      }
      lFidoReturnValues.CB.Alert.ThreatGRID.HashSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.CB.Alert.MD5Hash, true, iDays);
      while (Convert.ToInt16(lFidoReturnValues.CB.Alert.ThreatGRID.HashSearch.Data.CurrentItemCount) < 50)
      {
        if (iDays < -364) break;
        iDays = (Int16)(iDays * 2);
        lFidoReturnValues.CB.Alert.ThreatGRID.HashSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.CB.Alert.MD5Hash, true, iDays);
      }

      if (Convert.ToInt16(lFidoReturnValues.CB.Alert.ThreatGRID.HashSearch.Data.CurrentItemCount) > 0)
      {
        Console.WriteLine(@"Successfully found ThreatGRID hash data (" + lFidoReturnValues.CB.Alert.ThreatGRID.HashSearch.Data.CurrentItemCount + @" records)... storing in Fido.");
      }

      for (var i = 0; i < Convert.ToInt16(lFidoReturnValues.CB.Alert.ThreatGRID.HashSearch.Data.CurrentItemCount); i++)
      {
        if (i >= 50) continue;
        if (lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo == null)
        {
          lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo = new List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>();
        }
        lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Add(Feeds_ThreatGRID.ThreatInfo(lFidoReturnValues.CB.Alert.ThreatGRID.HashSearch.Data.Items[i].HashID));
      }

      return lFidoReturnValues;
    }

  }
}
