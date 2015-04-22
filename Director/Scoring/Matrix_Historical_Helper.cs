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
using System.Globalization;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.FidoDB;
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Director.Scoring
{
  static class Matrix_Historical_Helper
  {
    private static DataTable GetPreviousAlerts(string query)
    {
      var fidoSQlite = new SqLiteDB();
      var fidoData = new DataTable();
      try
      {
        fidoData = fidoSQlite.GetDataTable(query);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to format datatable return." + e);
      }

      return fidoData;
    }

    internal static FidoReturnValues HistoricalEvent(FidoReturnValues lFidoReturnValues)
    {
      Console.WriteLine(@"Gathering historical information from FIDO DB.");
      const string historicalQuery = "SELECT * FROM configs_historical_events";
      var fidoTemp = GetPreviousAlerts(historicalQuery);
      if (fidoTemp.Rows.Count <= 0) return lFidoReturnValues;
      lFidoReturnValues.HistoricalEvent = FormatHistoricalEvents(fidoTemp);
      var urlCount = new DataTable();
      var hashCount = new DataTable();

      try
      {
        if (lFidoReturnValues.Url != null)
        {
          foreach (var url in lFidoReturnValues.Url)
          {
            urlCount = GetPreviousAlerts(lFidoReturnValues.HistoricalEvent.UrlQuery.Replace("%url%", url));
          }
        }

        var ipCount = GetPreviousAlerts(lFidoReturnValues.HistoricalEvent.IpQuery.Replace("%ip%", lFidoReturnValues.DstIP));

        if (lFidoReturnValues.Hash != null)
        {
          foreach (var hash in lFidoReturnValues.Hash)
          {
            hashCount = GetPreviousAlerts(lFidoReturnValues.HistoricalEvent.HashQuery.Replace("%hash%", hash));
          }
        }

        Console.WriteLine(@"Historical data:");
        lFidoReturnValues.HistoricalEvent.UrlCount = urlCount.Rows.Count;
        lFidoReturnValues.HistoricalEvent.IpCount = ipCount.Rows.Count;
        lFidoReturnValues.HistoricalEvent.HashCount = hashCount.Rows.Count;
        Console.WriteLine(@"URL Count = " + lFidoReturnValues.HistoricalEvent.UrlCount.ToString(CultureInfo.InvariantCulture));
        Console.WriteLine(@"IP Count = " + lFidoReturnValues.HistoricalEvent.IpCount.ToString(CultureInfo.InvariantCulture));
        Console.WriteLine(@"Hash Count = " + lFidoReturnValues.HistoricalEvent.HashCount.ToString(CultureInfo.InvariantCulture));
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to gather startup configs." + e);
      }
      return lFidoReturnValues;
    }

    internal static EventAlerts GetPreviousMachineAlerts(FidoReturnValues lFidoReturnValues, bool isMatrixScore)
    {
      var machineQuery = string.Empty;
      lFidoReturnValues.IsSendAlert = true;
      if (!string.IsNullOrEmpty(lFidoReturnValues.Hostname))
      {
        //todo: move this to the database
        machineQuery = "SELECT * FROM event_alerts WHERE hostname = '" + lFidoReturnValues.Hostname.ToLower() + "'  ORDER BY primkey DESC";
      }
      else if (!string.IsNullOrEmpty(lFidoReturnValues.SrcIP))
      {
        //todo: move this to the database
        machineQuery = "SELECT * FROM event_alerts WHERE ip_address = '" + lFidoReturnValues.SrcIP + "'  ORDER BY primkey DESC";
      }

      var fidoTemp = GetPreviousAlerts(machineQuery);
      if (fidoTemp.Rows.Count <= 0) return lFidoReturnValues.PreviousAlerts;
      lFidoReturnValues.PreviousAlerts = new EventAlerts {Alerts = fidoTemp};

      if (!isMatrixScore) return lFidoReturnValues.PreviousAlerts;

      //todo: move integer values for time offsets to database as configurable.
      try
      {
        return PreviousMachineAlerts(lFidoReturnValues, fidoTemp);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to gather startup configs." + e);
      }

      return lFidoReturnValues.PreviousAlerts;
    }

    private static EventAlerts PreviousMachineAlerts(FidoReturnValues lFidoReturnValues, DataTable fidoTemp)
    {
      lFidoReturnValues.PreviousAlerts = FormatEventAlert(fidoTemp);
      if ((lFidoReturnValues.PreviousAlerts.Hostname == lFidoReturnValues.Hostname.ToLower()) && lFidoReturnValues.Hostname.ToLower() != "unknown")
      {
        var previousAlertTimeDate = Convert.ToDateTime(lFidoReturnValues.PreviousAlerts.TimeStamp);
        var currentAlertTimeDate = Convert.ToDateTime(lFidoReturnValues.TimeOccurred);
        var diff = (currentAlertTimeDate - previousAlertTimeDate);
        //if the time is greater than this # determine how great and if there is an association
        //or if the alerts should be considered 'new'
        if (diff.TotalMinutes > 30)
        {
          //if time difference is greater than this # assume a new alert
          if (diff.TotalMinutes < 720 && diff.TotalMinutes > 240)
          {
            if (lFidoReturnValues.ThreatScore > 50)
            {
              lFidoReturnValues.ThreatScore = 75;
              lFidoReturnValues.IsPreviousAlert = false;
              lFidoReturnValues.IsSendAlert = true;
              Console.WriteLine(@"New Threat Score for event = " + lFidoReturnValues.ThreatScore.ToString(CultureInfo.InvariantCulture));
              Console.WriteLine(@"New Total Score for event = " + lFidoReturnValues.TotalScore.ToString(CultureInfo.InvariantCulture));
            }
            else
            {
              lFidoReturnValues.ThreatScore += 15;
              lFidoReturnValues.IsPreviousAlert = false;
              lFidoReturnValues.IsSendAlert = true;
              Console.WriteLine(@"New Threat Score for event = " + lFidoReturnValues.ThreatScore.ToString(CultureInfo.InvariantCulture));
              Console.WriteLine(@"New Total Score for event = " + lFidoReturnValues.TotalScore.ToString(CultureInfo.InvariantCulture));
            }
            Console.WriteLine(@"Machine previous alerted and it has been longer than 4 hours!");
          }
          else if (diff.TotalMinutes > 240)
          {
            if (lFidoReturnValues.ThreatScore > 50)
            {
              lFidoReturnValues.ThreatScore = 100;
              lFidoReturnValues.IsPreviousAlert = false;
              lFidoReturnValues.IsSendAlert = true;
              Console.WriteLine(@"New Threat Score for event = " + lFidoReturnValues.ThreatScore.ToString(CultureInfo.InvariantCulture));
              Console.WriteLine(@"New Total Score for event = " + lFidoReturnValues.TotalScore.ToString(CultureInfo.InvariantCulture));
            }
            else
            {
              lFidoReturnValues.ThreatScore += 25;
              lFidoReturnValues.IsPreviousAlert = false;
              lFidoReturnValues.IsSendAlert = true;
              Console.WriteLine(@"New Threat Score for event = " + lFidoReturnValues.ThreatScore.ToString(CultureInfo.InvariantCulture));
              Console.WriteLine(@"New Total Score for event = " + lFidoReturnValues.TotalScore.ToString(CultureInfo.InvariantCulture));
            }
            Console.WriteLine(@"Machine previous alerted and it has been longer than 4 hours!");
          }

          //else an associated alert with the machine making multiple callbacks
          else
          {
            Console.WriteLine(@"Machine previous alerted but assuming this is part of same event!");
            lFidoReturnValues.IsPreviousAlert = false;
            lFidoReturnValues.IsSendAlert = true;
          }
        }
          //if less then determine if additional alerts are higher or lower severity than previous alerts
        else if (diff.TotalMinutes <= 30 & lFidoReturnValues.TotalScore > lFidoReturnValues.PreviousAlerts.PreviousScore)
        {
          Console.WriteLine(@"Multiple alerts detected and this event is scored higher than previous event!");
          lFidoReturnValues.IsPreviousAlert = true;
          lFidoReturnValues.IsSendAlert = true;
        }
        else if (diff.TotalMinutes <= 30 & lFidoReturnValues.PreviousAlerts.PreviousScore >= lFidoReturnValues.TotalScore)
        {
          Console.WriteLine(@"Multiple alerts detected and this event is scored lower than previous event!");
          lFidoReturnValues.IsPreviousAlert = true;
          lFidoReturnValues.IsSendAlert = false;
        }
      }
      return lFidoReturnValues.PreviousAlerts;
    }

    //todo: below is highlighted out until we start parsing previous alerts again
    //private static FidoReturnValues GetPreviousUserAlerts(FidoReturnValues lFidoReturnValues)
    //{
    //}

    //private static FidoReturnValues GetPreviousMachineAlerts(FidoReturnValues lFidoReturnValues)
    //{
    //}

    private static EventAlerts FormatEventAlert(DataTable dbReturn)
    {
      try
      {
        var reformat = new EventAlerts
        {
          PrimKey = Convert.ToInt32(dbReturn.Rows[0].ItemArray[0]),
          Timer = Convert.ToInt32(dbReturn.Rows[0].ItemArray[1]),
          IP = Convert.ToString(dbReturn.Rows[0].ItemArray[2]),
          Hostname = Convert.ToString(dbReturn.Rows[0].ItemArray[3]),
          TimeStamp = Convert.ToString(dbReturn.Rows[0].ItemArray[4]),
          PreviousScore = Convert.ToInt32(dbReturn.Rows[0].ItemArray[5]),
          AlertID = Convert.ToString(dbReturn.Rows[0].ItemArray[6])
        };

        EventAlerts lEventAlerts = reformat;
        return lEventAlerts;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to format event alerts return." + e);
      }
      return null;
    }

    private static HistoricalEvents FormatHistoricalEvents(DataTable dbReturn)
    {
      try
      {
        var reformat = new HistoricalEvents
        {
          UrlQuery = Convert.ToString(dbReturn.Rows[0].ItemArray[0]),
          IpQuery = Convert.ToString(dbReturn.Rows[0].ItemArray[1]),
          HashQuery = Convert.ToString(dbReturn.Rows[0].ItemArray[2]),
          UrlScore = Convert.ToInt32(dbReturn.Rows[0].ItemArray[3]),
          IpScore = Convert.ToInt32(dbReturn.Rows[0].ItemArray[4]),
          HashScore = Convert.ToInt32(dbReturn.Rows[0].ItemArray[5]),
          UrlWeight = Convert.ToInt32(dbReturn.Rows[0].ItemArray[6]),
          IpWeight = Convert.ToInt32(dbReturn.Rows[0].ItemArray[7]),
          HashWeight = Convert.ToInt32(dbReturn.Rows[0].ItemArray[8]),
          UrlIncrement = Convert.ToInt32(dbReturn.Rows[0].ItemArray[9]),
          IpIncrement = Convert.ToInt32(dbReturn.Rows[0].ItemArray[10]),
          HashIncrement = Convert.ToInt32(dbReturn.Rows[0].ItemArray[11]),
          UrlMultiplier = Convert.ToInt32(dbReturn.Rows[0].ItemArray[12]),
          IpMultiplier = Convert.ToInt32(dbReturn.Rows[0].ItemArray[13]),
          HashMultiplier = Convert.ToInt32(dbReturn.Rows[0].ItemArray[14])
        };

        return reformat;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to format historical event alerts return." + e);
      }
      return null;
    }

  }
}
