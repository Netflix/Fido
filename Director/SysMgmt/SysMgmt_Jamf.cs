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
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Director.SysMgmt
{
  static class SysMgmtJamf
  {
    //public static FidoReturnValues GetAdditionalInfo(FidoReturnValues lFidoReturnValues, List<string> lQuery, List<string> lHostInfo, string sReportID)
    //{ 
    //  var sQueries = new List<string>();
    //  var sConnectionString = lQuery[0];
    //  //todo: move these to the database
    //  sQueries.Add("select value_on_client from extension_attribute_values where report_id = '" + sReportID + "';");
    //  sQueries.Add("Select * from operating_systems where report_id = '" + sReportID + "';");
    //  var sqlConnect = new MySqlConnection(sConnectionString);
    //  sqlConnect.Open();

    //  try
    //  {
    //    foreach (var tmpQuery in sQueries)
    //    {
    //      var sqlCmd = new MySqlCommand(tmpQuery, sqlConnect);
    //      MySqlDataReader sqlReader = sqlCmd.ExecuteReader();

    //      if (sqlReader.HasRows)
    //      {
    //        var oHostInfoReturn = new object[sqlReader.FieldCount];
    //        while (sqlReader.Read())
    //        {
    //          sqlReader.GetValues(oHostInfoReturn);
    //          var q = oHostInfoReturn.Count();
    //          for (var i = 0; i < q; i++)
    //          {
    //            lHostInfo.Add(oHostInfoReturn[i].ToString());
    //          }
    //        }
    //      }
    //      sqlReader.Dispose();
    //    }

    //  if (lHostInfo.Count > 0)
    //  {
    //    lFidoReturnValues = Jamf2FidoValues.Convert(lFidoReturnValues, lHostInfo);
    //  }
    //    return lFidoReturnValues;
    //  }

    //  catch (Exception e)
    //  {
    //    Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in getting additional values from Jamf:" + e);
    //  }
    //  finally
    //  {
    //    sqlConnect.Close();
    //  }

    //  return lFidoReturnValues;
    //}
  }


  static class Jamf2FidoValues
  {

    public static JamfReturnValues Convert(FidoReturnValues lFidoReturnValues, List<string> lHostInfo)
    {

      var lJamfReturnValues = new JamfReturnValues
      {
        ComputerID = lHostInfo[0] ?? string.Empty, Hostname = lHostInfo[1] ?? string.Empty, ReportID = lHostInfo[2] ?? string.Empty, Username = lHostInfo[11], OSName = "OSX " + lHostInfo[9], LastUpdate = FromEpochTime(lHostInfo[3]).ToString()
      };
      return lJamfReturnValues;

    }

    private static DateTime? FromEpochTime(string unixTime)
    {
      return new DateTime(1970, 1, 1, 0, 0, 0).AddMilliseconds(System.Convert.ToDouble(unixTime)).ToLocalTime();
    }
  }
}
