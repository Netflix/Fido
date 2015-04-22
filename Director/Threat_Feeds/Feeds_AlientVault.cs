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
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Windows.Forms;
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Director.Threat_Feeds
{
  class Feeds_AlientVault
  {
    public  static AlienVaultReturnValues AlienVaultIP(string sDstIP)
    {
      var AlienVaultReturnValues = new AlienVaultReturnValues();

      var lLoadedFeed = LoadReputationFeed(Application.StartupPath + "\\threat feeds\\reputation.data");
      foreach (var sLoadFeedAry in from sLoadedFeed in lLoadedFeed where sLoadedFeed.Contains(sDstIP) select sLoadedFeed.Split('#'))
      {
        if (sLoadFeedAry[3] != null) {AlienVaultReturnValues.Activity = sLoadFeedAry[3];}
        if (sLoadFeedAry[1] != null) { AlienVaultReturnValues.Reliability = Convert.ToInt16(sLoadFeedAry[1]); }
        if (sLoadFeedAry[2] != null) { AlienVaultReturnValues.Risk = Convert.ToInt16(sLoadFeedAry[2]); }
        return AlienVaultReturnValues;
      }
      return AlienVaultReturnValues;
    }

    private static IEnumerable<string> LoadReputationFeed(string sFileLocation)
    {
      var lFeedValues = new List<string>();

      if (File.Exists(sFileLocation))
      {
        lFeedValues.AddRange(File.ReadAllLines(@sFileLocation));
      }

      return lFeedValues;
    }

    public static void DownloadReputationFeed()
    {
      ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate { return true; });
      var sDownloadUrl = Object_Fido_Configs.GetAsString("fido.securityfeed.alienvault.url", null);
      if (sDownloadUrl == null) return;
      var wcAlientVaultWebClient = new WebClient();
      wcAlientVaultWebClient.DownloadFile("http://reputation.alienvault.com/reputation.data", Application.StartupPath + "\\threat feeds\\reputation.data");
    }
  }
}
