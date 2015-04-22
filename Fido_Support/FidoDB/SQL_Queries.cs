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
using System.Data.SqlClient;
using System.Globalization;
using System.Linq;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using MySql.Data.MySqlClient;

namespace Fido_Main.Fido_Support.FidoDB
{
  class SQL_Queries
  {
    //get sql sources from fido XML
    public static IEnumerable<string> GetSqlSources()
    {
      string[] sSQLSources = null;
      try
      {
        sSQLSources = Object_Fido_Configs.GetAsString("fido.sysmgmt.params.types", null).Split(',');
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception in getsqlsources area:" + e);
      }
      return sSQLSources;
    }

    //get sql connection string and sql query
    public static List<string> GetSqlConfigs(string sSource)
    {
      var lQueryConfig = new List<string>();

      try
      {
        lQueryConfig.Add(Object_Fido_Configs.GetAsString("fido.sysmgmt." + sSource + ".sqlconnstring", null));
        lQueryConfig.Add(Object_Fido_Configs.GetAsString("fido.sysmgmt." + sSource + ".sqlqueryip", null));
        lQueryConfig.Add(Object_Fido_Configs.GetAsString("fido.sysmgmt." + sSource + ".sqlqueryhostname", null));

        if (sSource == "jamf")
        {
            lQueryConfig.Add(Object_Fido_Configs.GetAsString("fido.sysmgmt." + sSource + ".sqlqueryextattrib", null));
            lQueryConfig.Add(Object_Fido_Configs.GetAsString("fido.sysmgmt." + sSource + ".sqlqueryos", null));
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in getsqlconfigs area:" + e);
      }
      return lQueryConfig;
    }

    //run microsoft sql query and return data
    public static IEnumerable<string> RunMSsqlQuery(List<string> lSQLInput, string sSrcIP, string sHostname)
    {
      var lHostInfoReturn = new List<string>();
      var sqlConnect = new SqlConnection(lSQLInput[0]);

      try
      {
        sqlConnect.Open();
        var sqlCmd = new SqlCommand();
        string sQuery = null;
        if (sSrcIP != null)
        {
          sQuery = lSQLInput[1].Replace(" + sIP + ", sSrcIP);
          sqlCmd = new SqlCommand(sQuery, sqlConnect);
        }
        else if (sHostname != null)
        {
          sQuery = lSQLInput[2].Replace(" + sHostname + ", sHostname);
          sqlCmd = new SqlCommand(sQuery, sqlConnect);
        }

        SqlDataReader sqlReader = sqlCmd.ExecuteReader();
        var oHostInfoReturn = new object[sqlReader.FieldCount];
        if (sqlReader.HasRows)
        {
          while (sqlReader.Read())
          {
            //ReSharper disable once ReturnValueOfPureMethodIsNotUsed
            //GetValues is used and is assigning values to oHostInfoReturn
            sqlReader.GetValues(oHostInfoReturn);
            var q = oHostInfoReturn.Count();
            for (var i = 0; i < q; i++)
            {
              lHostInfoReturn.Add(oHostInfoReturn[i].ToString());
            }
            sqlReader.Dispose();
            return lHostInfoReturn;
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught running MSSQL query:" + e);
      }
      finally
      {
        sqlConnect.Close();
      }
      lHostInfoReturn.Add("unknown");
      return lHostInfoReturn;
    }

    //run mysql query and return data
    public static IEnumerable<string> RunMysqlQuery(List<string> lSQLInput, string sSrcIP, string sHostname)
    {
      //init local variables
      var lHostInfoReturn = new List<string>();
      var sqlConnect = new MySqlConnection(lSQLInput[0]);

      try
      {
        //open connection using pass SQL
        sqlConnect.Open();
        var sqlCmd = new MySqlCommand();

        //If IP is not empty then use IP based sql query.
        //If hostname is not empty then use host based sql query.
        //Replace inline variable with passed argument
        string sQuery = null;
        if (sSrcIP != null)
        {
          sQuery = lSQLInput[1].Replace(" + sIP + ", sSrcIP).ToString(CultureInfo.InvariantCulture);
          sqlCmd = new MySqlCommand(sQuery, sqlConnect);
        }
        else if (sHostname != null)
        {
          sQuery = lSQLInput[2].Replace(" + sHostname + ", sHostname);
          sqlCmd = new MySqlCommand(sQuery, sqlConnect);
        }

        //Initialize the reader and execute query
        MySqlDataReader sqlReader = sqlCmd.ExecuteReader();

        //If query returns values
        if (sqlReader.HasRows)
        {
          //then create object for total # of return columns
          var oHostInfoReturn = new object[sqlReader.FieldCount];
          while (sqlReader.Read())
          {
            sqlReader.GetValues(oHostInfoReturn);
            var q = oHostInfoReturn.Count();
            //read values into list object
            for (var i = 0; i < q; i++)
            {
              lHostInfoReturn.Add(oHostInfoReturn[i].ToString());
            }
            return lHostInfoReturn;
          }
        }
        //clean up and return list object
        sqlReader.Dispose();
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught running MYSQL query:" + e);
      }
      finally
      {
        sqlConnect.Close();
      }

      //If no values return empty
      lHostInfoReturn.Add("unknown");
      return lHostInfoReturn;
    }
  }
}