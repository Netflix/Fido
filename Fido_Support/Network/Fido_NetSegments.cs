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

namespace Fido_Main.Fido_Support.Network
{
  class Fido_NetSegments
  {
    public static string Responsegroup(string sIP)
    {
      //Code to decide who owns the system based on IP
      bool isServer = false;
      bool isWorkstation = false;
      bool isHub = false;

      string[] lsIP = sIP.Split('.');
      if ((lsIP[0] == "10") && ((lsIP[1] == "1") || (lsIP[1] == "1") || (lsIP[1] == "1") || (lsIP[1] == "1") || (lsIP[1] == "1") || (lsIP[1] == "1") || (lsIP[1] == "1")))
      {
        if ((lsIP[1] == "1") && ((lsIP[2] == "1") || (lsIP[2] == "1") || (lsIP[2] == "1") || (lsIP[2] == "1")))
        {
          isWorkstation = true;
        }
        else
        {
          isServer = true;
        }
      }
      else if ((lsIP[0] == "10") && (Convert.ToInt16(lsIP[1]) >= 2) && (Convert.ToInt16(lsIP[1]) <= 10) && (Convert.ToInt16(lsIP[3]) != 128) && (Convert.ToInt16(lsIP[3]) != 135))
      {
        isWorkstation = true;
      }
      else if ((lsIP[0] == "10") && (Convert.ToInt16(lsIP[1]) == 62) && (Convert.ToInt16(lsIP[1]) == 253))
      {
        isHub = true;
      }
      else
      {
        isWorkstation = true;
      }
      if (isServer) { return "Server team:"; }
      if (isWorkstation) { return "Desktop team:"; }
      return "Other team:";
    }

    public static bool isEmptySrcIP(string sSrcIP)
    {
      //used to filter out empty results or bad FireEye alerts
      //write sub-routine to email on these results
      if ((sSrcIP == "0.0.0.0") | (sSrcIP == null))
      {
        return false;
      }
      return true;
    }
  }
}
