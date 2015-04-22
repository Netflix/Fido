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
using System.Data;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Windows.Forms;

//Much of the below code came from http://www.dreamincode.net/forums/topic/157830-using-sqlite-with-c%23/#/
using Fido_Main.Fido_Support.ErrorHandling;

namespace Fido_Main.Fido_Support.FidoDB
{
  class SqLiteDB
  {
    readonly String _dbConn;

    public SqLiteDB()
    {
      const string fidoDB = @"\data\fido.db";
      var sFidoDB = Application.StartupPath + fidoDB;

      if ((string.IsNullOrEmpty(sFidoDB)) | (!File.Exists(sFidoDB)))
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to find Fido local DB.");
        return;
      }

      _dbConn = @"Data Source=" + sFidoDB;
     
    }

    public SqLiteDB(String inFile)
    {
      _dbConn = String.Format("Data Source={0}", inFile);
    }

    public SqLiteDB(Dictionary<String, String> connectionOpts)
    {
      var str = connectionOpts.Aggregate(string.Empty, (current, row) => current + String.Format("{0}={1}; ", row.Key, row.Value));
      str = str.Trim().Substring(0, str.Length - 1);
      _dbConn = str;
    }

    public DataTable GetDataTable(string sql)
    {
      var dt = new DataTable();
      try
      {
        var cnn = new SQLiteConnection(_dbConn);
        cnn.Open();
        var mycommand = new SQLiteCommand(cnn) {CommandText = sql};
        var reader = mycommand.ExecuteReader();
        dt.Load(reader);
        reader.Close();
        cnn.Close();
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to get table." + e);
      }
      return dt;
    }

    private int ExecuteNonQuery(string sql)
    {
      var cnn = new SQLiteConnection(_dbConn);
      cnn.Open();
      var mycommand = new SQLiteCommand(cnn) {CommandText = sql};
      var rowsUpdated = mycommand.ExecuteNonQuery();
      cnn.Close();
      return rowsUpdated;
    }

    public string ExecuteScalar(string sql)
    {
      var cnn = new SQLiteConnection(_dbConn);
      cnn.Open();
      var mycommand = new SQLiteCommand(cnn) {CommandText = sql};
      var value = mycommand.ExecuteScalar();
      cnn.Close();
      return value != null ? value.ToString() : "";
    }

    public object ExecuteScalarArray(string sql)
    {
      var cnn = new SQLiteConnection(_dbConn);
      cnn.Open();
      var mycommand = new SQLiteCommand(cnn) { CommandText = sql };
      var value = mycommand.ExecuteScalar();
      cnn.Close();
      return value;// != null ? value.ToString() : "";
    }
    public bool Update(String tableName, Dictionary<String, String> data, String where)
    {
      var vals = "";
      var returnCode = false;
      try
      {
        if (data.Count >= 1)
        {
          foreach (KeyValuePair<string, string> pair in data)
          {
            if (pair.Value != null)
              vals = vals + String.Format(" {0} = '{1}',", pair.Key.ToString(CultureInfo.InvariantCulture), pair.Value.ToString(CultureInfo.InvariantCulture));
            else
            {
              vals = vals + String.Format(" {0} = '{1}',", pair.Key.ToString(CultureInfo.InvariantCulture), string.Empty);
            }
          }
        }
        vals = vals.Substring(0, vals.Length - 1);
        ExecuteNonQuery(String.Format("update {0} set {1} where {2};", tableName, vals, where));
        returnCode = true;
      }
      catch(Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught updating SQLite table:" + e);
        return false;
      }
      return returnCode;
    }

    //public bool Delete(String tableName, String where)
    //{
    //  var returnCode = true;
    //  try
    //  {
    //    ExecuteNonQuery(String.Format("delete from {0} where {1};", tableName, where));
    //  }
    //  catch (Exception e)
    //  {
    //    Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to date data." + e);
    //    returnCode = false;
    //  }
    //  return returnCode;
    //}

    public bool Insert(String tableName, Dictionary<String, String> data)
    {
      var columns = "";
      var values = "";
      var returnCode = true;
      foreach (KeyValuePair<String, String> val in data)
      {
        columns += String.Format(" {0},", val.Key.ToString(CultureInfo.InvariantCulture));
        values += String.Format(" '{0}',", val.Value);
      }
      columns = columns.Substring(0, columns.Length - 1);
      values = values.Substring(0, values.Length - 1);
      try
      {
        ExecuteNonQuery(String.Format("insert into {0}({1}) values({2});", tableName, columns, values));
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to get insert data." + e);
        returnCode = false;
      }
      return returnCode;
    }

    //public bool ClearDb()
    //{
    //  try
    //  {
    //    const string clearQuery = @"select NAME from SQLITE_MASTER where type='table' order by NAME;";
    //    var tables = GetDataTable(clearQuery);
    //    foreach (DataRow table in tables.Rows)
    //    {
    //      ClearTable(table["NAME"].ToString());
    //    }
    //    return true;
    //  }
    //  catch
    //  {
    //    return false;
    //  }
    //}

    //private bool ClearTable(String table)
    //{
    //  try
    //  {
    //    ExecuteNonQuery(String.Format("delete from {0};", table));
    //    return true;
    //  }
    //  catch
    //  {
    //    return false;
    //  }
    //}
  }
}
