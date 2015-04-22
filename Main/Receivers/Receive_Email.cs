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
using System.Net.Mail;
using Fido_Main.Fido_Support.Crypto;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Main.Detectors;
using S22.Imap;

namespace Fido_Main.Main.Receivers
{
  static class Receive_Email
  {

   //ReadEmail is the handler for email based detectors. It is designed
   //to retrieve email from a configured email service and parse the alerts
   public static void ReadEmail(string sVendor, string sFolderName, string sFolderNameTest, string sDetectorEmail, bool isParamTest)
    {
      switch (sVendor)
      {
        //Outlook based email plugin which requires the Outlook client to be installed.
        case "outlook":
        #region Microsoft Outlook Plugin
          //try
          //{
          //  //Setup connection information to mailstore
          //  //If logon information is null then mailstore must be open already
          //  //var oApp = new Microsoft.Office.Interop.Outlook.Application();
          //  //var sFolder = new Microsoft.Office.Interop.Outlook.Folder(sFolderName);
          //  //var oNameSpace = oApp.GetNamespace("MAPI");
          //  //oNameSpace.Logon(null, null, true, true);
          //  //var oInboxFolder = oNameSpace.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderInbox);
          //  //Outlook.Folder oFolder = oInboxFolder.Folder[sFolderName];

          //  //logging
          //  //Logging_Fido.Main.RunLogging("Running FIDO on file " + sFolderName);

          //  ////attach to folder and for each item in the folder then loop. During loop assign subject, body and detect malware type
          //  //foreach (var item in sFolder.Items)
          //  //{
          //  //  var oMailItem = item as Microsoft.Office.Interop.Outlook._MailItem;
          //  //  if (oMailItem != null)
          //  //  {
          //  //    var sMessageBody = oMailItem.Body;
          //  //  }
          //  //  if (oMailItem != null)
          //  //  {
          //  //    var sSubject = oMailItem.Subject;
          //  //  }
          //    //List<string> sERet = scan_email(sSubject, sMessageBody, sFolderName);
          //  //  if (sERet.First() == "Test Email")
          //  //  {
          //  //    oMailItem.Delete();
          //  //  }
          //  //  else
          //  //  {
          //  //    fido.Form1.Run_FIDO(sMessageBody, sERet, "fubar", false, false, true, sVendor);//MalwareType
          //  //    oMailItem.Delete();
          //  //  }
          //  }
            #endregion

          //}
          //catch (Exception e)
          //{
          //  Fido_Modules.Fido.Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Outlook emailreceive area:" + e);
          //}
          break;

        case "exchange":
        #region Microsoft Exchange Plugin
          //still need to build out direct Exchange access
          #endregion
          break;
        
        //IMAP based email plugin which has been verified to work with Gmail
        case "imap":
        #region IMAP Plugin
          try
          {
            //get encrypted password and decrypt
            //then login
            var sfidoemail = Object_Fido_Configs.GetAsString("fido.email.fidoemail", null);
            var sfidopwd = Object_Fido_Configs.GetAsString("fido.email.fidopwd", null);
            var sfidoacek = Object_Fido_Configs.GetAsString("fido.email.fidoacek", null);
            var sImapServer = Object_Fido_Configs.GetAsString("fido.email.imapserver", null);
            var iImapPort = Object_Fido_Configs.GetAsInt("fido.email.imapport", 0);
            sfidoacek = Aes_Crypto.DecryptStringAES(sfidoacek, "1");
            sfidopwd = Aes_Crypto.DecryptStringAES(sfidopwd, sfidoacek);
            IImapClient gLogin = new ImapClient(sImapServer, iImapPort, sfidoemail, sfidopwd, AuthMethod.Login, true);

            var sSeperator = new[] { "," };
            gLogin.DefaultMailbox = isParamTest ? sFolderNameTest : sFolderName;
            var listUids = new List<uint>();

            //seperate out list of email addresses handed to emailreceive
            //then run query based on each email from the specified folder
            //and finally convert to array
            string[] aryInboxSearch = sDetectorEmail.Split(sSeperator, StringSplitOptions.RemoveEmptyEntries);
            foreach (var search in aryInboxSearch)
            {
              listUids.AddRange(gLogin.Search(SearchCondition.From(search)).ToList());
            }
            var uids = listUids.ToArray();
            uids = uids.Take(50).ToArray();
            var msg = gLogin.GetMessages(uids);
            var mailMessages = msg as MailMessage[] ?? msg.ToArray();
            for (var i = 0; i < mailMessages.Count(); i++)
            {
              var sMessageBody = mailMessages[i].Body;
              var sSubject = mailMessages[i].Subject;
              var sERet = ScanEmail(sSubject, sMessageBody, sFolderName, isParamTest);
              if (sERet == "Test Email")
              {
                Console.WriteLine(@"Test email found, putting in processed folder.");
                gLogin.MoveMessage(uids[i], "Processed");
              }
              else
              {
                Console.WriteLine(@"Finished processing email alert, puttig in processed folder.");
                gLogin.MoveMessage(uids[i], "Processed");
              }
            }
            #endregion
          }
          catch (Exception e)
          {
            Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in IMAP emailreceive area:" + e);
          }
          Console.WriteLine(@"Finished processing email alerts.");
          break;
      }
    }

    //After receiving the email alert the subject, body and folder the email came from are passed
    //to this function to be parsed.
    private static string ScanEmail(string sSubject, string sBody, string sFolderName, bool isParamTest)
    {
      //todo: this seems hokey and needs to be redone. I think I was drinking whiskey when I wrote it.
      try
      {
        switch (sFolderName)
        {
          case "FireEye":
            Detect_FireeyeMPS.FireEyeEmailReceive(sBody, sSubject);
            return "test";

          case "FireEye-MAS":
            Detect_FireEyeMas.ParseFireEyeMas(sBody);
            return "test";

          case "Bit9":
            return "test";

          case "ClearPass":
            return "test";

          case "PaloAlto":
            return "test";

          case "Sophos":
            return "test";

          case "SourceFire":
            //sourcefire.Main
            return "test";
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught during scan email:" + e);
      }
      //todo: return 'test'? why? remove this or finish return value handling.
      return "test";
    }
  }
}
