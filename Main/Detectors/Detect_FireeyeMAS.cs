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
using Fido_Main.Fido_Support.ErrorHandling;

namespace Fido_Main.Main.Detectors
{
  //Note: the FireEye MPS and MAS put out what appears to be the same
  //alert format with only minor differences. It should be possible,
  //once the string parser is replaced with XML deserialization, to
  //condense into use only one detector module.
  static class Detect_FireEyeMas
  {
    //function for FireEye MPS to parse each email to get source, destination, MAC addr, type of 
    //attack, time it occured and important URLs
    public static void ParseFireEyeMas(string sEmailBody)
    {
      string sSrcIP = "0.0.0.0";
      string sDstIP = "0.0.0.0";
      string sMD5 = null;
      string sChannelHost = null;
      string sURL = null;
      string sReferer = null;
      string sOccurred = null;
      string sOriginal = null;
      string sHttpHeader = null;
      bool isSRC = false;
      bool isOccured = false;
      //bool bMD5 = false;
      int iTotalUrl = 0;
      List<string> lReturn = null;

      try
      {
        sEmailBody = sEmailBody.Trim();
        var sFilter = new[] { "\r", "\n" };
        string[] sParse = sEmailBody.Split(sFilter, StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < sParse.Count(); i++)
        {
          string sItem = sParse[i];
          if (sItem != "")
          {
            var sLineInput = sItem.Split(':');
            var sLineTitle = sLineInput[0].Trim();
            if ((sLineTitle.ToLower() == "src") && (isSRC == false))
            {
              isSRC = true;
              for (int x = 1; x < 4; x++)
              {
                var sTempSrc = sParse[i + x].Trim();
                if (sTempSrc == null) continue;
                string[] sTempSrc2 = sTempSrc.Split(':');
                if (sTempSrc2[0].Trim().ToLower() != "ip") continue;
                sSrcIP = sTempSrc2[1].Trim();
              }
            }
            else if (sLineTitle.ToLower() == "dst")
            {
              sDstIP = sParse[i + 1].Trim();
              var sTempSrc2 = sDstIP.Split(':');
              sDstIP = sTempSrc2[1].Trim();
            }
            else if ((sLineTitle.ToLower() == "occurred") && (isOccured == false))
            {
              isOccured = true;
              sOccurred = sParse[i].Trim();
            }
            else if (sLineTitle.ToLower() == "md5sum")
            {
              if (sMD5 == null) sMD5 = sLineInput[1].Trim();
              else sMD5 = sMD5 + ",";
            }
            else if (sLineTitle.ToLower() == "channel")
            {
              if (sItem.IndexOf("FireEye-TestEvent Channel 1", StringComparison.Ordinal) > -1)
              {
                lReturn.Add("Test Email");
                //return lReturn;
              }
              string sChannel = sItem;
              var sRemove = new[] { "::~~" };
              string[] sChannelArray = sChannel.Split(sRemove, StringSplitOptions.RemoveEmptyEntries);
              bool isHost = false;
              foreach (string sChanItem in sChannelArray)
              {
                string[] sReturn = sChanItem.Split(':');
                if (sReturn[0].ToLower() == "Host")
                {
                  if (string.IsNullOrEmpty(sChannelHost))
                  {
                    sChannelHost = sReturn[1] + ",";
                  }
                  else
                  {
                    var sRemove2 = new[] { "," };
                    string[] sURLArray = sChannelHost.Split(sRemove2, StringSplitOptions.RemoveEmptyEntries);
                    foreach (string sTempURL in sURLArray)
                    {
                      if (String.Compare(sTempURL, sReturn[1], StringComparison.Ordinal) == 0)
                      {
                        isHost = true;
                      }
                    }
                    if (isHost == false)
                    {
                      sChannelHost += sReturn[1];
                    }
                  }
                }
              }
            }
            else if (sLineTitle.ToLower() == "Referer")
            {
              sReferer = sLineInput[2].Trim();
              sURL = sReferer.Remove(0, 2);
            }
            else if (sLineTitle.ToLower() == "original")
            {
              sOriginal = sLineInput[1].Trim();
            }
            else if (sLineTitle.ToLower() == "http-header")
            {
              sHttpHeader = sLineInput[1].Trim();
            }
            else if (sLineTitle.ToLower() == "url")
            {
              iTotalUrl++;
              if (iTotalUrl < 50)
              {
                if (string.IsNullOrEmpty(sURL))
                {
                  sURL += sLineInput[1].Trim() + ",";
                }
                else
                {
                  sURL += sLineInput[1].Trim() + ",";
                }
              }
            }
          }
        }

        var sOut = new[] { sOccurred, sSrcIP, sDstIP, sMD5, sURL, sChannelHost, sReferer, sOriginal, sHttpHeader };
        lReturn = sOut.ToList();
        //return lReturn;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught parsing email:" + e);
      }
    }
  }
}
