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
using System.Data;
using Fido_Main.Fido_Support.ErrorHandling;

namespace Fido_Main.Fido_Support.Objects.Fido
{
  public class Object_Fido_ConfigClass
  {
    internal class ParseConfigs
    {
      internal int Primkey { get; set; }
      internal string DetectorType { get; set; }
      internal string Detector { get; set; }
      internal string Vendor { get; set; }
      internal string Server { get; set; }
      internal string Folder { get; set; }
      internal string FolderTest { get; set; }
      internal string File { get; set; }
      internal string EmailFrom { get; set; }
      internal string Lastevent { get; set; }
      internal string UserID { get; set; }
      internal string Pwd { get; set; }
      internal string Acek { get; set; }
      internal string DB { get; set; }
      internal string ConnString { get; set; }
      internal string Query { get; set; }
      internal string Query3 { get; set; }
      internal string Query2 { get; set; }
      internal string APIKey { get; set; }
    }

    internal static ParseConfigs FormatParse(DataTable dbReturn)
    {
      try
      {
        var reformat = new ParseConfigs
        {
          DetectorType = Convert.ToString(dbReturn.Rows[0].ItemArray[1]),
          Detector = Convert.ToString(dbReturn.Rows[0].ItemArray[2]),
          Vendor = Convert.ToString(dbReturn.Rows[0].ItemArray[3]),
          Server = Convert.ToString(dbReturn.Rows[0].ItemArray[4]),
          Folder = Convert.ToString(dbReturn.Rows[0].ItemArray[5]),
          FolderTest = Convert.ToString(dbReturn.Rows[0].ItemArray[6]),
          File = Convert.ToString(dbReturn.Rows[0].ItemArray[7]),
          EmailFrom = Convert.ToString(dbReturn.Rows[0].ItemArray[8]),
          Lastevent = Convert.ToString(dbReturn.Rows[0].ItemArray[9]),
          UserID = Convert.ToString(dbReturn.Rows[0].ItemArray[10]),
          Pwd = Convert.ToString(dbReturn.Rows[0].ItemArray[11]),
          Acek = Convert.ToString(dbReturn.Rows[0].ItemArray[12]),
          DB = Convert.ToString(dbReturn.Rows[0].ItemArray[13]),
          ConnString = Convert.ToString(dbReturn.Rows[0].ItemArray[14]),
          Query = Convert.ToString(dbReturn.Rows[0].ItemArray[15]),
          Query2 = Convert.ToString(dbReturn.Rows[0].ItemArray[16]),
          Query3 = Convert.ToString(dbReturn.Rows[0].ItemArray[17]),
          APIKey = Convert.ToString(dbReturn.Rows[0].ItemArray[18])
        };

        return reformat;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to format datatable return." + e);
      }
      return null;
    }
  }
}
