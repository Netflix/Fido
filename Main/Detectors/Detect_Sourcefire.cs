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

namespace Fido_Main.Main.Detectors
{
  public class SourceFire
  {
    //Sourcefire doesn't provide great interfaces to retrieve alerts
    //and currently on email is available. With this function I'm just
    //doing a string parser.
    public string ParseSourceFire(string sEmailBody, bool isWebInfection)
    {
      //var MalwareType = "Malicious attacked detected by Sourcefire";
      //sMsgRet = null;// eParser.ParseSourceFire(sBody, bWebInfection);

      string sInternalAddress = null;
      string sExternalAddress = null;
      string sURL = null;
      //bool bSRC = false;
      //bool bOccured = false;


      string sSourceFireDirection = "";
      var sFilter = new[] { "[", "]" };
      var sIPFilter = new[] { " {tcp} ", " {udp} ", "->", ":", "\r\n" };
      string[] sSourceFire = sEmailBody.Split(sFilter, StringSplitOptions.None);
      var sHostSource = sSourceFire[8].Split(sIPFilter, StringSplitOptions.RemoveEmptyEntries);
      var sHostIPOne = sHostSource[0].Split('.');
      var sHostIPTwo = sHostSource[2].Split('.');
      if (sHostIPOne[0] == "10")
      {
        sSourceFireDirection = "external";
        sInternalAddress = sHostSource[0];
        sExternalAddress = sHostSource[2];
        sURL = sHostSource[2];
      }
      else if (sHostIPTwo[0] == "10")
      {
        sSourceFireDirection = "internal";
        sExternalAddress = sHostSource[0];
        sInternalAddress = sHostSource[2];
        sURL = sHostSource[0];
      }
      string sSrcIP = sInternalAddress;
      string sDstIP = sExternalAddress;
      sEmailBody = sSrcIP + "\\" + sDstIP + "\\" + sURL + "\\" + sSourceFireDirection;
      return sEmailBody;
    }

  }
}
