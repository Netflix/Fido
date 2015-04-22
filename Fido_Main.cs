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
using System.IO;
using System.Globalization;
using System.Threading;
using System.Windows.Forms;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Main.Receivers;
//using Fido_Main.Logger;

namespace Fido_Main
{
  public partial class FidoMain : Form
  {
    public FidoMain()
    {
      InitializeComponent();
    }
    
    //The load will grab configurations for what FIDO is monitoring,
    //then go to each configured external system to parse any alerts.
    //Finally, FIDO is configured to pause per iteration on a 
    //configurable timed basis.
    private void Fido_Load(object sender, EventArgs aug)
    {
      //Disabled the current time during current iteration.
      timer1.Enabled = false;
      Hide();

      //Check to see if Fido configurations exists and if not
      //fail with prompt that configurations are not found.
      Console.Clear();
      var sAppStartupPath = Application.StartupPath + @"\data\fido.db";
      if (!File.Exists(sAppStartupPath))
      {
        Console.WriteLine(@"Failed to load FIDO DB.");
        Application.Exit();
      }
      else {Console.WriteLine(@"Loaded FIDO DB successfully.");}

      //Load fido configs from database
      Object_Fido_Configs.LoadConfigFromDb("config");

      //Setup syslog
      var server1 = Object_Fido_Configs.GetAsString("fido.logger.syslog.server", "localhost");
      var port1 = Object_Fido_Configs.GetAsInt("fido.logger.syslog.port", 514);
      var facility1 = Object_Fido_Configs.GetAsString("fido.logger.syslog.facility", "local1");
      var sender1 = Object_Fido_Configs.GetAsString("fido.logger.syslog.sender", "Fido");
      var layout1 = Object_Fido_Configs.GetAsString("fido.logger.syslog.layout", "$(message)");
      //SysLogger.Setup(server1, port1, facility1, sender1, layout1);

      //Beginning of primary area which starts parsing of alerts.
      var isParamTest = Object_Fido_Configs.GetAsBool("fido.application.teststartup", true);
      var sDetectors = Object_Fido_Configs.GetAsString("fido.application.detectors", string.Empty).Split(',');

      try
      {
        Console.WriteLine(isParamTest ? @"Running test configs." : @"Running production configs.");

        foreach (var detect in sDetectors)
        {
          var parseConfigs = Object_Fido_Configs.ParseDetectorConfigs(detect);
          //Get the detector, ie, email, log, web service, etc.
          var sDetectorType = parseConfigs.DetectorType;
          switch (sDetectorType)
          {
            case "api":
              Console.WriteLine(@"Loading webservice receiver.");
              Recieve_API.DirectToEngine(sDetectorType, detect);
              break;

            case "log":
              Console.WriteLine(@"Loaded log receiver.");
              var sDefaultServer = parseConfigs.Server;
              var sDefaultFile = parseConfigs.File;
              var sVendor = parseConfigs.Vendor;
              Receive_Logging.DirectToEngine(detect, sVendor, sDefaultServer, sDefaultFile, isParamTest);
              break;

            case "sql":
              Console.WriteLine(@"Loaded sql receiver.");
              Receive_SQL.DirectToEngine(sDetectorType, detect);
              break;

            case "email":
              Console.WriteLine(@"Loaded email receiver.");
              var sEmailVendor = Object_Fido_Configs.GetAsString("fido.email.vendor", "imap");
              var sDetectorsEmail = parseConfigs.EmailFrom;
              var sDetectorsFolder = parseConfigs.Folder;
              Receive_Email.ReadEmail(sEmailVendor, sDetectorsFolder, null, sDetectorsEmail, isParamTest);
              break;
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in fidomain area:" + e);
      }

      //Sleep for X # of seconds per iteration specified in Fido configuration 
      Application.DoEvents();
      var iSleep = Object_Fido_Configs.GetAsInt("fido.application.sleepiteration", 5);
      Console.WriteLine(@"Fido processing complete... sleeping for " + (iSleep / 1000).ToString(CultureInfo.InvariantCulture) + @" seconds.");
      Thread.Sleep(iSleep);
      timer1.Enabled = true;

    }

    //Configurable timer to run Fido
    private void Timer1Tick(object sender, EventArgs e)
    {
      try
      {
        Application.DoEvents();
        Fido_Load(null, null);
        
        //todo: make the below integer value configurable
        Thread.Sleep(2000);
      }
      catch (Exception ex)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in fidomain area:" + ex);
      }

    }

    //todo: do something with this timer or remove it.
    private void timer2_Tick(object sender, EventArgs e)
    {
      Application.DoEvents();
    }
  }
}