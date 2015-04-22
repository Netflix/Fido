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
using Fido_Main.Fido_Support.FidoDB;

namespace Fido_Main.Director.Director_Helper
{
  class The_Director_Whitelist
  {
    public bool CheckFidoWhitelist(string sDstIP, List<string> sHash, string sDomain, List<string> sUrl)
    {
      var isFound = false;
      var sqlQuery = new SqLiteDB();

      if (!string.IsNullOrEmpty(sDstIP))
      {
        var qDstIPReturn = sqlQuery.ExecuteScalar("Select * from event_whitelist where artifact = '" + sDstIP + "'");
        if (!string.IsNullOrEmpty(qDstIPReturn))
        {
          isFound = true;
        }
      }

      if (sHash != null)
      {
        foreach (var hash in sHash)
        {
          var qHashReturn = sqlQuery.ExecuteScalar("Select * from event_whitelist where artifact = '" + hash + "'");
          if (!string.IsNullOrEmpty(qHashReturn))
          {
            isFound = true;
          }
        }
      }

      if (!string.IsNullOrEmpty(sDomain))
      {
        var qDomainReturn = sqlQuery.ExecuteScalar("Select * from event_whitelist where artifact = '" + sDomain + "'");
        if (!string.IsNullOrEmpty(qDomainReturn))
        {
          isFound = true;
        }
      }

      if (sUrl != null)
      {
        foreach (var url in sUrl)
        {
          var qUrlReturn = sqlQuery.ExecuteScalar("Select * from event_whitelist where artifact = '" + url + "'");
          if (!string.IsNullOrEmpty(qUrlReturn))
          {
            isFound = true;
          }
        }
      }

      return isFound;
    }
  }
}
