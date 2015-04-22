
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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Notification.Email;
using Fido_Main.Notification.Notification_Helper;

namespace Fido_Main.Notification
{
  static class Notification
  {
    //module to compose notifications
    public static void Notify (FidoReturnValues lFidoReturnValues)
    {
      try
      {
        var sFidoEmail = Object_Fido_Configs.GetAsString("fido.email.fidoemail", null);
        var sPrimaryEmail = Object_Fido_Configs.GetAsString("fido.email.primaryemail", null);
        var sSecondaryEmail = Object_Fido_Configs.GetAsString("fido.email.secondaryemail", null);
        var sNonAlertEmail = Object_Fido_Configs.GetAsString("fido.email.nonalertemail", null);
        var lAttachment = new List<string>
      {
        Application.StartupPath + "\\media\\gauge\\total" + lFidoReturnValues.TotalScore.ToString(CultureInfo.InvariantCulture) + ".png",
        Application.StartupPath + "\\media\\gauge\\red" + lFidoReturnValues.UserScore.ToString(CultureInfo.InvariantCulture) + ".png",
        Application.StartupPath + "\\media\\gauge\\red" + lFidoReturnValues.MachineScore.ToString(CultureInfo.InvariantCulture) + ".png",
        Application.StartupPath + "\\media\\gauge\\red" + lFidoReturnValues.ThreatScore.ToString(CultureInfo.InvariantCulture) + ".png"
      };


        string sSubject;
        if (lFidoReturnValues.IsPreviousAlert)
        {
          sSubject = @"Previously Alerted! Fido Alert: " + lFidoReturnValues.MalwareType + ". ";
        }
        else
        {
          sSubject = @"Fido Alert: " + lFidoReturnValues.MalwareType + ". ";
        }

        if (lFidoReturnValues.IsHostKnown)
        {
          sSubject += "Hostname = " + lFidoReturnValues.Hostname;
        }
        else
        {
          sSubject += "Hostname = Unknown (" + lFidoReturnValues.SrcIP + ")";
        }

        lFidoReturnValues = SummaryEmail(lFidoReturnValues);
        lFidoReturnValues.Recommendation = ReturnRecommendation(lFidoReturnValues);
        lFidoReturnValues.SummaryEmail = ReplacingValues(lFidoReturnValues.SummaryEmail, lFidoReturnValues);
        lFidoReturnValues.SummaryEmail = ReplacingBadGuyValues(lFidoReturnValues.SummaryEmail, lFidoReturnValues);

        if (!lFidoReturnValues.IsTargetOS)
        {
          sSubject = "Fido InfoSec only Alert : Target OS does not match.";
        }
        else if (!lFidoReturnValues.IsSendAlert)
        {
          sSubject = "Fido InfoSec only alert. " + lFidoReturnValues.MalwareType + ". Hostname = " + lFidoReturnValues.Hostname + " (" + lFidoReturnValues.SrcIP + ")";
        }

        lFidoReturnValues.IsTest = Object_Fido_Configs.GetAsBool("fido.application.teststartup", true);
        if (lFidoReturnValues.IsTest) sSubject = @"TEST: " + sSubject;

        if (lFidoReturnValues.IsSendAlert)
        {
          Email_Send.Send(sPrimaryEmail, sSecondaryEmail, sFidoEmail, sSubject, lFidoReturnValues.SummaryEmail, lAttachment, null);
        }
        else
        {
          Email_Send.Send(sNonAlertEmail, sNonAlertEmail, sFidoEmail, sSubject, lFidoReturnValues.SummaryEmail, lAttachment, null);
        }
      }
      catch (Exception e)
      {
        Console.WriteLine(@"Error creating FIDO email. " + e);
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Director sending network detector info to threat feeds:" + e); 
      }

    }

    private static string ReplacingBadGuyValues(string sHtmlBody, FidoReturnValues lFidoReturnValues)
    {
      var replacements = new Dictionary<string, string>();
      var detectors = Object_Fido_Configs.GetAsString("fido.application.detectors", null).Split(',');
      var lBadMD5Hashes = new List<string>();
      var lBadURLs = new List<string>();
      var lGoodMD5Hashes = new List<string>();
      var lGoodURLs = new List<string>();

      replacements.Add("%threatip%", lFidoReturnValues.DstIP ?? string.Empty);
      replacements.Add("%dnsname%", lFidoReturnValues.DNSName ?? string.Empty);
      replacements.Add("%timeoccurred%", lFidoReturnValues.TimeOccurred + " (UTC)" ?? DateTime.Now.ToString(CultureInfo.InvariantCulture));
      replacements.Add("%malwaretype%", lFidoReturnValues.MalwareType ?? "unknown");
      replacements.Add("%detector%", lFidoReturnValues.CurrentDetector ?? string.Empty);
      replacements.Add("%prevmach%", lFidoReturnValues.IsMachSeenBefore ? lFidoReturnValues.IsMachSeenBefore.ToString() + " " + lFidoReturnValues.PreviousAlerts.TimeStamp : "No");
      replacements.Add("%prevuser%", lFidoReturnValues.IsUserSeenBefore ? lFidoReturnValues.IsUserSeenBefore.ToString() + " " + lFidoReturnValues.PreviousAlerts.TimeStamp : "No");
      replacements.Add("%prevurl%", lFidoReturnValues.IsUrlSeenBefore ? lFidoReturnValues.IsUrlSeenBefore.ToString() : "No");
      replacements.Add("%prevhash%", lFidoReturnValues.IsHashSeenBefore ? lFidoReturnValues.IsHashSeenBefore.ToString() : "No");
      replacements.Add("%previp%", lFidoReturnValues.IsIPSeenBefore ? lFidoReturnValues.IsIPSeenBefore.ToString() : "No");

      if (lFidoReturnValues.CurrentDetector == "antivirus")
      {
        replacements = Notfication_Helper.AntivirusReplacements(lFidoReturnValues);
      }

      if (lFidoReturnValues.CurrentDetector == "bit9")
      {
        if (!string.IsNullOrEmpty(lFidoReturnValues.Bit9.FileName))
        {
          replacements.Add("%bit9_filename%", lFidoReturnValues.Bit9.FileName);
        }
      }

      if (lFidoReturnValues.CurrentDetector == "carbonblackv1")
      {
        if (!string.IsNullOrEmpty(lFidoReturnValues.CB.Alert.ProcessPath))
        {
          replacements.Add("%threatfile%", lFidoReturnValues.CB.Alert.ProcessPath);
        }
        if (!string.IsNullOrEmpty(lFidoReturnValues.CB.Alert.ProcessPath))
        {
          replacements.Add("%hostcount%", lFidoReturnValues.CB.Alert.HostCount + @" other host(s) have this file.");
        }
        if (!string.IsNullOrEmpty(lFidoReturnValues.CB.Alert.ProcessPath))
        {
          replacements.Add("%netconns%", lFidoReturnValues.CB.Alert.NetConn + @" network connections initiated by this file.");
        }
      }

      if (lFidoReturnValues.Detectors != null) 
      {
        var sListOfDetectors = lFidoReturnValues.Detectors.Aggregate(string.Empty, (current, sDetector) => current + (sDetector + ", "));
        replacements.Add("%detectors%", sListOfDetectors); 
      }
      else
      {
        replacements.Add("%detectors%", "No"); 
      }

      replacements = Notfication_Helper.StartReplacements(lFidoReturnValues, detectors, lBadMD5Hashes, lGoodMD5Hashes, lBadURLs, lGoodURLs, replacements);

      return replacements.Aggregate(sHtmlBody, (current, replacement) => current.Replace(replacement.Key, replacement.Value));
    }

    private static string ReplacingValues(string sHtmlBody, FidoReturnValues lFidoReturnValues)
    {
      var replacements = new Dictionary<string, string>
      {
        {"%recommendation%", lFidoReturnValues.Recommendation[0]},
        {"%recommendationdetail%", lFidoReturnValues.Recommendation[1]}
      };

      //todo: is there really no better way to do this? Me thinks someone had too much caffeine on the day this was written.
      if (lFidoReturnValues.Actions != null)
      {
        var q = 1;
        var counter = "a";

        for (var p = 0; p < lFidoReturnValues.Actions.Count; p++)
        {
          if (counter == "a")
          {
            replacements.Add("%action" + (q).ToString(CultureInfo.InvariantCulture) + "a%", lFidoReturnValues.Actions[p] ?? string.Empty);
            counter = "b";
            p++;
          }
          if (counter == "b")
          {
            replacements.Add("%action" + (q).ToString(CultureInfo.InvariantCulture) + "b%", lFidoReturnValues.Actions[p] ?? string.Empty);
            counter = "a";
            q++;
          }          
        }
        
        for (var r = q; r < 7; r++)
        {
          if (counter == "a")
          {
            replacements.Add("%action" + (q).ToString(CultureInfo.InvariantCulture) + "a%", string.Empty);
            counter = "b";
          }
          if (counter == "b")
          {
            replacements.Add("%action" + (q).ToString(CultureInfo.InvariantCulture) + "b%", string.Empty);
            counter = "a";
            q++;
          } 
        }
      }
      
      //todo: this /100 should be a variable stored in the fido db
      replacements.Add("%userscore%", lFidoReturnValues.UserScore.ToString(CultureInfo.InvariantCulture) + "/100");

      if (lFidoReturnValues.UserInfo != null)
      {
        replacements.Add("%username%", lFidoReturnValues.UserInfo.Username);
        replacements.Add("%useremail%", lFidoReturnValues.UserInfo.UserEmail);
        replacements.Add("%usertitle%", lFidoReturnValues.UserInfo.Title);
        replacements.Add("%userdepartment%", lFidoReturnValues.UserInfo.Department);
        replacements.Add("%usertype%", lFidoReturnValues.UserInfo.EmployeeType);
        replacements.Add("%userphone%", lFidoReturnValues.UserInfo.MobileNumber);
        replacements.Add("%userlocation%", lFidoReturnValues.UserInfo.CubeLocation);
        replacements.Add("%usercitystate%", lFidoReturnValues.UserInfo.City + "/" + lFidoReturnValues.UserInfo.State);
        replacements.Add("%managername%", lFidoReturnValues.UserInfo.ManagerName);
        replacements.Add("%managertitle%", lFidoReturnValues.UserInfo.ManagerTitle);
        replacements.Add("%manageremail%", lFidoReturnValues.UserInfo.ManagerMail);
        replacements.Add("%managerphone%", lFidoReturnValues.UserInfo.ManagerMobile);
      }
      else
      {
        replacements.Add("%username%", lFidoReturnValues.Username);
        replacements.Add("%useremail%", "....................");
        replacements.Add("%usertitle%", "....................");
        replacements.Add("%userdepartment%", "....................");
        replacements.Add("%usertype%", "....................");
        replacements.Add("%userphone%", "....................");
        replacements.Add("%userlocation%", "....................");
        replacements.Add("%usercitystate%", "....................");
        replacements.Add("%managername%", "....................");
        replacements.Add("%managertitle%", "....................");
        replacements.Add("%manageremail%", "....................");
        replacements.Add("%managerphone%", "....................");
      }

      replacements.Add("%machinescore%", lFidoReturnValues.MachineScore.ToString(CultureInfo.InvariantCulture) + "/100");

      if (lFidoReturnValues.Landesk != null)
      {
        replacements.Add("%machinename%", lFidoReturnValues.Hostname);
        replacements.Add("%srcip%", lFidoReturnValues.SrcIP);
        replacements.Add("%machineos%", lFidoReturnValues.MachineType);
        replacements.Add("%machinedomain%", lFidoReturnValues.Landesk.Domain);
        replacements.Add("%criticalpatches%", "Critical: " + lFidoReturnValues.Landesk.Patches[1].ToString(CultureInfo.InvariantCulture));
        replacements.Add("%highpatches%", "High:" + lFidoReturnValues.Landesk.Patches[2].ToString(CultureInfo.InvariantCulture));
        replacements.Add("%lowpatches%", "Low: " + lFidoReturnValues.Landesk.Patches[3].ToString(CultureInfo.InvariantCulture));
        replacements.Add("%avinstalled%", lFidoReturnValues.Landesk.Product);
        replacements.Add("%avrunning%", lFidoReturnValues.Landesk.AgentRunning);
        replacements.Add("%avdefversion%", lFidoReturnValues.Landesk.DefInstallDate);
        replacements.Add("%bit9installed%", lFidoReturnValues.Landesk.Bit9Version);
        replacements.Add("%bit9running%", lFidoReturnValues.Landesk.Bit9Running);
        replacements.Add("%clientlastupdate%", lFidoReturnValues.Landesk.LastUpdate);
      }
      else if (lFidoReturnValues.Jamf != null)
      {
        replacements.Add("%machinename%", lFidoReturnValues.Hostname);
        replacements.Add("%srcip%", lFidoReturnValues.SrcIP);
        replacements.Add("%machineos%", lFidoReturnValues.MachineType);
        replacements.Add("%machinedomain%", string.Empty); 
        replacements.Add("%criticalpatches%", "....................");
        replacements.Add("%highpatches%", "....................");
        replacements.Add("%lowpatches%", "....................");
        replacements.Add("%avinstalled%", lFidoReturnValues.Jamf.Product);
        replacements.Add("%avrunning%", lFidoReturnValues.Jamf.AgentRunning);
        replacements.Add("%avdefversion%", "....................");
        replacements.Add("%bit9installed%", string.Empty);
        replacements.Add("%bit9running%", string.Empty);
        replacements.Add("%clientlastupdate%", lFidoReturnValues.Jamf.LastUpdate);
      }
      else
      {
        replacements.Add("%machinename%", lFidoReturnValues.Hostname);
        replacements.Add("%srcip%", lFidoReturnValues.SrcIP);
        replacements.Add("%machineos%", "....................");
        replacements.Add("%machinedomain%", "....................");
        replacements.Add("%criticalpatches%", "....................");
        replacements.Add("%highpatches%", "....................");
        replacements.Add("%lowpatches%", "....................");
        replacements.Add("%avinstalled%", "....................");
        replacements.Add("%avrunning%", "....................");
        replacements.Add("%avdefversion%", "....................");
        replacements.Add("%bit9installed%", string.Empty);
        replacements.Add("%bit9running%", string.Empty);
        replacements.Add("%clientlastupdate%", string.Empty);
      }

      return replacements.Aggregate(sHtmlBody, (current, replacement) => current.Replace(replacement.Key, replacement.Value));
    }

    private static FidoReturnValues SummaryEmail(FidoReturnValues lFidoReturnValues)
    {
      //load summary template email
      switch (lFidoReturnValues.CurrentDetector)
      {
        case "antivirus":
          lFidoReturnValues.SummaryEmail = File.ReadAllText(Application.StartupPath + "\\media\\email_templates\\email_template_summary_av.htm");
          break;
        case "bit9":
          lFidoReturnValues.SummaryEmail = File.ReadAllText(Application.StartupPath + "\\media\\email_templates\\email_template_summary_bit9.htm");
          break;
        case "carbonblackv1":
          lFidoReturnValues.SummaryEmail = File.ReadAllText(Application.StartupPath + "\\media\\email_templates\\email_template_summary_carbonblack.htm");
          break;
        default:
          lFidoReturnValues.SummaryEmail = File.ReadAllText(Application.StartupPath + "\\media\\email_templates\\email_template_summary.htm");
          break;
      }
      return lFidoReturnValues;
    }

    private static List<string> ReturnRecommendation(FidoReturnValues lFidoReturnValues)
    {
      var recommendation = new List<string>();

      if (lFidoReturnValues.IsPCI)
      {
        if (lFidoReturnValues.IsPreviousAlert)
        {
          recommendation.Add("Previously Alerted/Re-image");
          recommendation.Add("Machine has alerted multiple times and user was found to be in a PCI zone where SOP for the host is to be re-imaged.");
        }
        else
        {
          //Do we always need to reimage for PCI?
          recommendation.Add("Re-image");
          recommendation.Add("Machine and user were found to be in a PCI zone where SOP for the host is to be re-imaged.");
        }
      }
      else if ((lFidoReturnValues.Hostname == null) || (lFidoReturnValues.Hostname == "unknown"))
      {
        if (lFidoReturnValues.TotalScore <= 20)
        {
          lFidoReturnValues.IsSendAlert = false;
          recommendation.Add("Machine could not be verified");
          recommendation.Add("Severity is low, but unable to automatically remediate because machine is unknown.");
        }
        else if ((lFidoReturnValues.TotalScore > 20) && (lFidoReturnValues.TotalScore <= 30) && (lFidoReturnValues.IsReboot == false))
        {
          recommendation.Add("Machine could not be verified");
          recommendation.Add("Severity is medium, but machine could not be verified. Please find and scan this machine offline.");
        }
        else if ((lFidoReturnValues.TotalScore > 30) && (lFidoReturnValues.TotalScore <= 80))
        {
          recommendation.Add("Machine could not be verified");
          recommendation.Add("Severity is medium/high, but machine could not be verified. Please find and scan this machine offline.");
        }
        else
        {
          recommendation.Add("Machine could not be verified");
          recommendation.Add("Severity is critical and machine should be found and removed from network!!!");
        }
      }
      else if (lFidoReturnValues.CurrentDetector == "antivirus")
      {
        var sNewThreatName = lFidoReturnValues.Antivirus.ThreatName.Split('/');
        if (sNewThreatName != null)
        {
          switch (lFidoReturnValues.Antivirus.ActionTaken.ToLower())
          {
            case "none":
              switch (lFidoReturnValues.Antivirus.Status.ToLower())
              {
                case "cleanable":
                  recommendation.Add("Action required");
                  recommendation.Add("Antivirus was unable to remove the threat, but this malware is cleanable.");
                  break;
                case "cleanup failed":
                  recommendation.Add("Action required");
                  recommendation.Add("Antivirus attempted to cleanup malware, but failed. Make sure system is offline and attempt cleanup again.");
                  break;
                case "restart required":
                  recommendation.Add("Action required");
                  recommendation.Add("Antivirus attempted to cleanup malware, but requires a reboot to complete remediation.");
                  break;
                case "not cleanable":
                  recommendation.Add("Re-image");
                  recommendation.Add("Antivirus is not capable of removing this malware and the system will need to be rebuilt.");
                  break;
              }
              break;
            case "partially removed":
              switch (lFidoReturnValues.Antivirus.Status.ToLower())
              {
                case "cleanable":
                  recommendation.Add("Action required");
                  recommendation.Add("Antivirus was unable to remove the threat, but this malware is cleanable.");
                  break;
                case "cleanup failed":
                  recommendation.Add("Action required");
                  recommendation.Add("Antivirus attempted to cleanup malware, but failed. Make sure system is offline and attempt cleanup again.");
                  break;
                case "restart required":
                  recommendation.Add("Action required");
                  recommendation.Add("Antivirus attempted to cleanup malware, but requires a reboot to complete remediation.");
                  break;
                case "not cleanable":
                  recommendation.Add("Re-image");
                  recommendation.Add("Antivirus is not capable of removing this malware and the system will need to be rebuilt.");
                  break;
              }
              break;
          }
        }
      }
      else
      {
        //todo: all the below integer and string values should be put into the database to be configurable and retrieved at runtime.
        if (!lFidoReturnValues.IsTargetOS)
        {
          recommendation.Add("No Action Required");
          recommendation.Add("This email is a notification only. The malicious file and the target OS do not match.");
        }
        else if (lFidoReturnValues.TotalScore <= 10)
        {
          lFidoReturnValues.IsSendAlert = false;
          recommendation.Add("No Action Required");
          recommendation.Add("This email is a notification, or FIDO was able to remediate on its own.");
        }
        else if ((lFidoReturnValues.TotalScore > 80) && (lFidoReturnValues.TotalScore <= 89) &&
                 lFidoReturnValues.IsPatch)
        {
          if (lFidoReturnValues.IsPreviousAlert)
          {
            recommendation.Add("Previously Alerted/Scan, Patch and Release");
            recommendation.Add("Machine previously alerted and severity is high. Machine should be scanned and patched, but if it continues to alert it should be re-imaged.");
          }
          else
          {
            recommendation.Add("Scan, Patch and Release");
            recommendation.Add("Severity is critical and machine should be scanned and patched.");
          }
        }
        else if ((lFidoReturnValues.TotalScore > 10) && (lFidoReturnValues.TotalScore <= 80) && lFidoReturnValues.IsReboot)
        {
          recommendation.Add("System Reboot Needed");
          recommendation.Add("FIDO was able to remediate on its own, but a system reboot is needed. Please contact the user to do this ASAP.");
        }
        else if ((lFidoReturnValues.TotalScore > 10) && (lFidoReturnValues.TotalScore <= 30) &&
                 (lFidoReturnValues.IsReboot == false))
        {
          if (lFidoReturnValues.IsPatch)
          {
            recommendation.Add("Scan, Patch and Release");
            recommendation.Add("Severity is medium and machine should be taken offline then patched and scanned.");
          }
          else
          {
            recommendation.Add("Scan and Release");
            recommendation.Add("Severity is medium and machine should be taken offline and scanned.");
          }
        }
        else if ((lFidoReturnValues.TotalScore > 30) && (lFidoReturnValues.TotalScore <= 80))
        {
          if (lFidoReturnValues.IsPreviousAlert)
          {
            if (lFidoReturnValues.IsPatch)
            {
              recommendation.Add("Previously Alerted/Scan, Patch and Release");
              recommendation.Add(
                "Machine previously alerted and severity is high. Machine should be taken offline and scanned and patched. If it continues to alert it should be re-imaged.");
            }
            else
            {
              recommendation.Add("Previously Alerted/Scan and Release");
              recommendation.Add(
                "Machine previously alerted and severity is high. Machine should be taken offline and scanned, but if it continues to alert it should be re-imaged.");
            }
          }
          else
          {
            if (lFidoReturnValues.IsPatch)
            {
              recommendation.Add("Scan, Patch and Release");
              recommendation.Add("Severity is critical and machine should be scanned and patched.");
            }

            else
            {
              recommendation.Add("Scan and Release");
              recommendation.Add("Severity is high and machine should be taken offline and scanned.");
            }
          }
        }
        else
        {
          if (lFidoReturnValues.IsPreviousAlert)
          {
            recommendation.Add("Previously Alerted/Re-image");
            recommendation.Add("Machine previously alerted and severity gathered from all information is critical... the systems needs to be rebuilt.");
          }
          else
          {
            recommendation.Add("Re-image");
            recommendation.Add("Severity gathered from all information is critical and the systems needs to be rebuilt.");
          }
        }
      }
      return recommendation;
    }

  }
}
