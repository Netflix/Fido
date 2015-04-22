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
using Fido_Main.Director;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Logging;
using Fido_Main.Fido_Support.Network;
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Main.Detectors
{
  static class Detect_FireeyeMPS
  {
    //function for FireEye MPS to parse each email to get source, destination, MAC addr, type of 
    //attack, time it occured and important URLs
    public static void FireEyeEmailReceive(string sEmailBody, string sSubject)
    {

      try
      {
        Console.WriteLine(@"Running FireEye MPS detector.");
        var sSubjectArray = sSubject.Split(':');
        var malwareType = sSubjectArray[0];
        FidoReturnValues lFidoReturnValues;

        //the below code is hacky and needs to be optimized. I couldn't
        //think of a better way to write it and it works... so fix it or shut up.

        //get additional information from the alert such as hashes, URLs, etc
        if (string.IsNullOrEmpty(malwareType) && (String.Compare(malwareType, "malware-callback detected", StringComparison.Ordinal) == 0) || (String.Compare(malwareType, "malware-object detected", StringComparison.Ordinal) == 0))
        {
          Console.WriteLine(@"Malware-callback detected");
          Logging_Fido.RunLogging(malwareType + "!");
          lFidoReturnValues = FireEyeParse(sEmailBody, false);
          if (!Fido_NetSegments.isEmptySrcIP(lFidoReturnValues.SrcIP)) return;
          lFidoReturnValues.IsTargetOS = true;
          //hand of process to get more information about the host
          lFidoReturnValues.MalwareType = sSubjectArray[0];
          lFidoReturnValues.CurrentDetector = "mps";
          TheDirector.Direct(lFidoReturnValues);
          //consider do an else in case srcip comes back empty
          //else
          //{ 
          //}
        }
        else if (malwareType != null && String.Compare(malwareType, "web-infection detected", StringComparison.Ordinal) == 0)
        {
          Console.WriteLine(@"Web-infection detected.");
          Logging_Fido.RunLogging(malwareType + "!");
          lFidoReturnValues = FireEyeParse(sEmailBody, true);
          if (!Fido_NetSegments.isEmptySrcIP(lFidoReturnValues.SrcIP)) return;
          lFidoReturnValues.IsTargetOS = true;
          //hand of process to get more information about the host
          lFidoReturnValues.MalwareType = sSubjectArray[0];
          lFidoReturnValues.CurrentDetector = "mps";
          TheDirector.Direct(lFidoReturnValues);
          //consider do an else in case srcip comes back empty
          //else
          //{ 
          //}
        }
        else if (malwareType != null && String.Compare(malwareType, "infection-match detected", StringComparison.Ordinal) == 0)
        {
          Console.WriteLine(@"Infection-match detected.");
          Logging_Fido.RunLogging(malwareType + "!");
          lFidoReturnValues = FireEyeParse(sEmailBody, false);
          if (!Fido_NetSegments.isEmptySrcIP(lFidoReturnValues.SrcIP)) return;
          lFidoReturnValues.IsTargetOS = true;
          //hand of process to get more information about the host
          lFidoReturnValues.MalwareType = sSubjectArray[0];
          lFidoReturnValues.CurrentDetector = "mps";
          TheDirector.Direct(lFidoReturnValues);
          //consider do an else in case srcip comes back empty
          //else
          //{ 
          //}
        }
        Console.WriteLine(@"Exiting FireEye detector.");
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught receiving FireEye email:" + e);
      }
    }

    public static void FireEyeSyslogReceive(string sSyslog)
    {
    }

    private static FidoReturnValues FireEyeParse(string sEmailBody, bool isWebInfection)
    {

      //yes, I know this should be using xml deserialization and not a string parser.
      //if you knew my history with FireEye, you'd understand.
      var sSrcIP = "0.0.0.0";
      var sDstIP = "0.0.0.0";
      var lMd5 = new List<string>();
      var lChannelHost = new List<string>();
      var lURL = new List<string>();
      var sReferer = string.Empty;
      var sOccurred = string.Empty;
      var sOriginal = string.Empty;
      var sHttpHeader = string.Empty;
      var isSrc = false;
      var isOccured = false;
      var lFidoReturnValues = new FidoReturnValues();
      var lFireEyeReturn = new FireEyeReturnValues();

      try
      {
        sEmailBody = sEmailBody.Trim();
        var sFilter = new[] { "\r", "\n" };
        var sParse = sEmailBody.Split(sFilter, StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < sParse.Count(); i++)
        {
          var sItem = sParse[i];
          if (sItem == "") continue;
          var sLineInput = sItem.Split(':');
          var sLineTitle = sLineInput[0].Trim();
          var sTempSrc = string.Empty;
          if ((sLineTitle.ToLower() == "src") && (isSrc == false))
          {
            isSrc = true;
            for (var x = 1; x < 4; x++)
            {
              sTempSrc = sParse[i + x].Trim();
              if (sTempSrc == string.Empty) continue;
              var sTempSrc2 = sTempSrc.Split(':');
              if (sTempSrc2[0].Trim().ToLower() != "ip") continue;
              sSrcIP = sTempSrc2[1].Trim();
            }
          }
          else switch (sLineTitle.ToLower())
          {
            case "address":
              if (sParse[i - 3].Contains("cnc-service"))
              { 
                lChannelHost.Add(sLineInput[1].Trim());
              }
              break;
            case "dst":
            {
              sDstIP = sParse[i + 1].Trim();
              var sTempSrc2 = sDstIP.Split(':');
              sDstIP = sTempSrc2[1].Trim();
            }
              break;
            case "md5sum":
              if (lMd5.Contains(sLineInput[1].Trim()) == false)
              {
                lMd5.Add(sLineInput[1].Trim());              
              }
              break;
            case "channel":
            {
              if (sItem.IndexOf("FireEye-TestEvent Channel 1", StringComparison.Ordinal) > -1)
              {
                lFireEyeReturn.EventTime = "Test Email";
                lFidoReturnValues.FireEye = lFireEyeReturn;
                return lFidoReturnValues;
              }
              var sChannel = sItem;
              var sRemove = new[] { "::~~" };
              var sChannelArray = sChannel.Split(sRemove, StringSplitOptions.RemoveEmptyEntries);
              foreach (var sReturn in sChannelArray.Select(sChanItem => sChanItem.Split(':')))
              {
                if (sReturn[0].ToLower() == "host")
                {
                  lURL.Add(sReturn[1].Trim());
                }
                if (sReturn[0].ToLower().TrimStart() != "channel") continue;
                var sNewReturn = sReturn[1].ToLower().Split(' ');
                if (sNewReturn.Count() <= 2) continue;
                var iTotalChannel = lChannelHost.Count - 1;
                lChannelHost[iTotalChannel] = lChannelHost[iTotalChannel] + sNewReturn[2];
              }
            }
              break;
            case "referer":
              sReferer = sLineInput[2].Trim();
              lURL.Add(sReferer.Remove(0, 2));
              break;
            case "original":
              sOriginal = sLineInput[1].Trim();
              break;
            //case "host":
            //  lURL.Add(sLineInput[1].Trim());
            //  break;
            case "http-header":
              sHttpHeader = sLineInput[1].Trim();
              break;
            case "url":
              lURL.Add(sLineInput[1].Trim());
              break;
            default:
              if ((sLineTitle.ToLower() == "occurred") && (isOccured == false))
              {
                isOccured = true;
                var sArray = new[] { "occurred: " };
                var sTempStupidArray = sParse[i].Trim().Split(sArray, StringSplitOptions.RemoveEmptyEntries);
                sOccurred = sTempStupidArray[0];
              }
              break;
          }

        }

        if (isWebInfection)
        {
          //string[] sOut = new string[] {sOccurred, sSrcIP, sURL, sMD5 };
          lFireEyeReturn.EventTime = sOccurred;
          lFidoReturnValues.SrcIP = sSrcIP;
          lFireEyeReturn.URL = lURL;
          lFireEyeReturn.MD5Hash = lMd5;
          lFidoReturnValues.Hash = lMd5;
          lFidoReturnValues.Url = lURL;
        }
        else
        {
          //string[] sOut = new string[] { sOccurred, sSrcIP, sURL, sMD5, sDstIP, sChannelHost, sReferer, sOriginal, sHttpHeader };
          lFireEyeReturn.EventTime = sOccurred;
          lFidoReturnValues.SrcIP = sSrcIP;
          lFidoReturnValues.DstIP = sDstIP;
          lFidoReturnValues.TimeOccurred = sOccurred;
          lFireEyeReturn.URL = lURL;
          lFireEyeReturn.MD5Hash = lMd5;
          lFidoReturnValues.Hash = lMd5;
          lFidoReturnValues.Url = lURL;
          lFireEyeReturn.DstIP = sDstIP;
          lFireEyeReturn.ChannelHost = lChannelHost;
          lFireEyeReturn.Referer = sReferer;
          lFireEyeReturn.Original = sOriginal;
          lFireEyeReturn.HttpHeader = sHttpHeader;
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught parsing FireEye email:" + e);
      }
      lFidoReturnValues.FireEye = lFireEyeReturn;
      return lFidoReturnValues;
    }
  }
}
